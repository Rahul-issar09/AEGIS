"""AEGIS Agent 1 — HTTP client.

Centralized HTTP layer wrapping httpx. All outgoing requests are routed
through the scope controller — no security module may create its own
unrestricted HTTP client.
"""

from __future__ import annotations

import hashlib
import logging
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from agent1.http.models import HttpMethod, HttpRequest, HttpResponse, RequestResponse
from agent1.scope.validator import ScopeController

logger = logging.getLogger("aegis.http")


# Headers/cookies that contain sensitive values to redact in logs
_SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "proxy-authorization",
}


def _redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """Return a copy of headers with sensitive values redacted.

    Used for logging only — the actual HttpRequest/HttpResponse
    models keep original values until evidence redaction.
    """
    redacted = {}
    for key, value in headers.items():
        if key.lower() in _SENSITIVE_HEADERS:
            redacted[key] = "[REDACTED]"
        else:
            redacted[key] = value
    return redacted


class HttpClient:
    """Scope-controlled HTTP client backed by httpx.

    Features:
    - Connection pooling
    - Timeout handling
    - Redirect control (validated through scope controller)
    - Request/response capture for evidence
    - TLS configuration
    - Proxy support
    - All requests validated through scope controller

    Usage:
        client = HttpClient(scope_controller)
        rr = client.request("GET", "https://example.test/api/users")
        print(rr.response.status_code)
    """

    def __init__(
        self,
        scope_controller: ScopeController,
        proxy: str | None = None,
        verify_ssl: bool = True,
        default_headers: dict[str, str] | None = None,
    ) -> None:
        self._scope = scope_controller
        policy = scope_controller.policy

        # Build httpx client with scope-derived settings
        self._client = httpx.Client(
            timeout=httpx.Timeout(
                connect=policy.timeout_seconds,
                read=policy.timeout_seconds,
                write=policy.timeout_seconds,
                pool=policy.timeout_seconds,
            ),
            follow_redirects=False,  # We handle redirects manually for scope validation
            max_redirects=0,
            verify=verify_ssl,
            proxy=proxy,
            headers=default_headers or {},
        )

        self._max_redirects = policy.max_redirects

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
        body: str | None = None,
        json_body: Any | None = None,
        auth_context: str | None = None,
    ) -> RequestResponse:
        """Send an HTTP request after scope validation.

        All requests are captured as HttpRequest/HttpResponse pairs
        for evidence collection.

        Args:
            method: HTTP method.
            url: Full request URL.
            headers: Additional request headers.
            cookies: Request cookies.
            params: Query string parameters.
            body: Raw request body.
            json_body: JSON request body (mutually exclusive with body).
            auth_context: Authentication context identifier.

        Returns:
            RequestResponse pair for evidence.

        Raises:
            ScopeViolation: If the request is out of scope.
            RateLimitExceeded: If rate limit exceeded.
            MaxRequestsExceeded: If max requests reached.
            httpx.HTTPError: On transport-level errors.
        """
        # Validate through scope controller
        self._scope.validate(method, url)

        # Build internal request model
        req = HttpRequest(
            method=HttpMethod(method.upper()),
            url=url,
            headers=headers or {},
            cookies=cookies or {},
            query_params=params or {},
            body=body,
            auth_context=auth_context,
            timestamp=datetime.now(timezone.utc),
        )

        logger.info(
            "request.sending",
            extra={
                "method": method,
                "url": url,
                "auth_context": auth_context or "anonymous",
                "headers": _redact_headers(req.headers),
            },
        )

        # Send via httpx
        start_time = time.monotonic()

        request_headers = dict(headers or {})
        if cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
            cookie_key = next((k for k in request_headers if k.lower() == "cookie"), None)
            if cookie_key:
                request_headers[cookie_key] = f"{request_headers[cookie_key]}; {cookie_str}"
            else:
                request_headers["Cookie"] = cookie_str

        try:
            httpx_response = self._client.request(
                method=method.upper(),
                url=url,
                headers=request_headers,
                params=params,
                content=body,
                json=json_body,
            )
        except httpx.TimeoutException as e:
            logger.warning(
                "request.timeout",
                extra={"method": method, "url": url, "error": str(e)},
            )
            raise
        except httpx.HTTPError as e:
            logger.error(
                "request.error",
                extra={"method": method, "url": url, "error": str(e)},
            )
            raise

        elapsed_ms = (time.monotonic() - start_time) * 1000
        response_body = httpx_response.text

        # Follow redirects manually with scope validation
        redirect_count = 0
        current_response = httpx_response

        while (
            current_response.is_redirect
            and redirect_count < self._max_redirects
        ):
            redirect_url = str(current_response.next_request.url) if current_response.next_request else None
            if not redirect_url:
                break

            # Validate redirect through scope controller
            try:
                self._scope.validate_redirect(redirect_url)
            except Exception:
                logger.warning(
                    "redirect.blocked",
                    extra={
                        "original_url": url,
                        "redirect_url": redirect_url,
                    },
                )
                break

            # Validate and count the redirect as a new request
            self._scope.validate(method, redirect_url)

            current_response = self._client.request(
                method=method.upper(),
                url=redirect_url,
                headers=headers,
                cookies=cookies,
            )
            redirect_count += 1

        if current_response is not httpx_response:
            response_body = current_response.text
            elapsed_ms = (time.monotonic() - start_time) * 1000

        # Build internal response model
        resp = HttpResponse(
            status_code=current_response.status_code,
            headers=dict(current_response.headers),
            body=response_body,
            body_hash=HttpResponse.compute_body_hash(response_body),
            response_time_ms=round(elapsed_ms, 2),
            size=len(response_body.encode("utf-8", errors="replace")),
            timestamp=datetime.now(timezone.utc),
        )

        logger.info(
            "response.received",
            extra={
                "method": method,
                "url": url,
                "status_code": resp.status_code,
                "response_time_ms": resp.response_time_ms,
                "size_bytes": resp.size,
            },
        )

        return RequestResponse(request=req, response=resp)

    def get(self, url: str, **kwargs) -> RequestResponse:
        """Convenience method for GET requests."""
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> RequestResponse:
        """Convenience method for POST requests."""
        return self.request("POST", url, **kwargs)

    def head(self, url: str, **kwargs) -> RequestResponse:
        """Convenience method for HEAD requests."""
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs) -> RequestResponse:
        """Convenience method for OPTIONS requests."""
        return self.request("OPTIONS", url, **kwargs)

    def close(self) -> None:
        """Close the underlying HTTP client and release resources."""
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
