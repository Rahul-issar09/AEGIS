"""AEGIS Agent 1 — Scope controller and validator.

Every outgoing HTTP request MUST pass through scope_controller.validate()
before being sent. This is the primary safety gate — no security module
may bypass it or create its own unrestricted HTTP client.
"""

from __future__ import annotations

import ipaddress
import logging
import time
from urllib.parse import urlparse

from agent1.http.models import DESTRUCTIVE_METHODS, HttpMethod
from agent1.scope.policy import ScopePolicy

logger = logging.getLogger("aegis.scope")


class ScopeViolation(Exception):
    """Raised when a request violates the scan scope policy."""

    pass


class RateLimitExceeded(Exception):
    """Raised when the request rate limit has been reached."""

    pass


class MaxRequestsExceeded(Exception):
    """Raised when the maximum number of requests has been reached."""

    pass


# Private/internal network ranges that must be blocked unless explicitly allowed
_INTERNAL_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local
    ipaddress.ip_network("::1/128"),  # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),  # IPv6 unique local
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
]


class ScopeController:
    """Validates every outgoing request against the scan scope policy.

    Enforces: hostname, scheme, port, path, rate limits, request count,
    destructive method blocking, and internal network restrictions.
    """

    def __init__(self, policy: ScopePolicy) -> None:
        self._policy = policy
        self._request_count = 0
        self._request_timestamps: list[float] = []

    @property
    def policy(self) -> ScopePolicy:
        """The active scope policy."""
        return self._policy

    @property
    def request_count(self) -> int:
        """Number of requests sent so far in this scan."""
        return self._request_count

    def validate_target(self, url: str) -> None:
        """Validate that a target URL is within scope before starting a scan.

        Args:
            url: The target URL to validate.

        Raises:
            ScopeViolation: If the target is out of scope.
        """
        parsed = urlparse(url)
        self._validate_scheme(parsed.scheme)
        self._validate_host(parsed.hostname)
        self._validate_port(parsed.port, parsed.scheme)
        logger.info(
            "target.validated",
            extra={"url": url},
        )

    def validate(self, method: str, url: str) -> None:
        """Validate a request before sending it.

        This method MUST be called for every outgoing HTTP request.

        Args:
            method: HTTP method (GET, POST, etc.).
            url: Full request URL.

        Raises:
            ScopeViolation: If the request violates scope policy.
            RateLimitExceeded: If rate limit would be exceeded.
            MaxRequestsExceeded: If max requests reached.
        """
        parsed = urlparse(url)

        self._validate_scheme(parsed.scheme)
        self._validate_host(parsed.hostname)
        self._validate_port(parsed.port, parsed.scheme)
        self._validate_path(parsed.path)
        self._validate_method(method)
        self._validate_internal_network(parsed.hostname)
        self._validate_request_count()
        self._enforce_rate_limit()

        self._request_count += 1
        self._request_timestamps.append(time.monotonic())

        logger.debug(
            "request.validated",
            extra={"method": method, "url": url, "count": self._request_count},
        )

    def validate_redirect(self, redirect_url: str) -> None:
        """Validate that a redirect target is within scope.

        Args:
            redirect_url: The URL being redirected to.

        Raises:
            ScopeViolation: If the redirect target is out of scope.
        """
        parsed = urlparse(redirect_url)
        self._validate_scheme(parsed.scheme)
        self._validate_host(parsed.hostname)
        self._validate_port(parsed.port, parsed.scheme)

        logger.debug(
            "redirect.validated",
            extra={"url": redirect_url},
        )

    # ── Private validation methods ──────────────────────────────────

    def _validate_scheme(self, scheme: str | None) -> None:
        if not scheme:
            raise ScopeViolation("URL has no scheme")
        if scheme.lower() not in self._policy.allowed_schemes:
            raise ScopeViolation(
                f"Scheme '{scheme}' not in allowed schemes: "
                f"{sorted(self._policy.allowed_schemes)}"
            )

    def _validate_host(self, hostname: str | None) -> None:
        if not hostname:
            raise ScopeViolation("URL has no hostname")
        if hostname.lower() not in {h.lower() for h in self._policy.allowed_hosts}:
            raise ScopeViolation(
                f"Host '{hostname}' not in allowed hosts: "
                f"{sorted(self._policy.allowed_hosts)}"
            )

    def _validate_port(self, port: int | None, scheme: str | None) -> None:
        # Resolve default port from scheme if not explicitly specified
        if port is None:
            default_ports = {"http": 80, "https": 443}
            port = default_ports.get(scheme or "", 0)

        if port not in self._policy.allowed_ports:
            raise ScopeViolation(
                f"Port {port} not in allowed ports: "
                f"{sorted(self._policy.allowed_ports)}"
            )

    def _validate_path(self, path: str | None) -> None:
        if not path:
            return

        # Check excluded paths
        for excluded in self._policy.excluded_paths:
            if path == excluded or path.startswith(excluded + "/"):
                raise ScopeViolation(f"Path '{path}' is excluded by scope policy")

        # Check allowed paths (if specified, only these prefixes are allowed)
        if self._policy.allowed_paths:
            allowed = any(
                path == ap or path.startswith(ap.rstrip("/") + "/")
                for ap in self._policy.allowed_paths
            )
            if not allowed:
                raise ScopeViolation(
                    f"Path '{path}' not in allowed paths: "
                    f"{list(self._policy.allowed_paths)}"
                )

    def _validate_method(self, method: str) -> None:
        if self._policy.safe_mode and not self._policy.destructive_tests:
            try:
                http_method = HttpMethod(method.upper())
            except ValueError:
                raise ScopeViolation(f"Unknown HTTP method: {method}")

            if http_method in DESTRUCTIVE_METHODS:
                raise ScopeViolation(
                    f"Destructive method '{method}' blocked in safe mode. "
                    f"Set destructive_tests=true to allow."
                )

    def _validate_internal_network(self, hostname: str | None) -> None:
        """Block requests to internal/private network addresses unless allowed."""
        if not hostname or self._policy.allow_internal_network:
            return

        # Try to resolve hostname as an IP address
        try:
            addr = ipaddress.ip_address(hostname)
        except ValueError:
            # It's a domain name, not an IP — allow it
            # (DNS resolution to internal IPs is a separate concern)
            return

        for network in _INTERNAL_NETWORKS:
            if addr in network:
                raise ScopeViolation(
                    f"Host '{hostname}' resolves to internal network "
                    f"{network}. Set allow_internal_network=true to allow."
                )

    def _validate_request_count(self) -> None:
        if self._request_count >= self._policy.max_requests:
            raise MaxRequestsExceeded(
                f"Maximum request count reached: {self._policy.max_requests}"
            )

    def _enforce_rate_limit(self) -> None:
        """Enforce requests-per-second limit using a sliding window."""
        now = time.monotonic()
        window_start = now - 1.0  # 1-second window

        # Remove timestamps outside the window
        self._request_timestamps = [
            ts for ts in self._request_timestamps if ts >= window_start
        ]

        if len(self._request_timestamps) >= self._policy.requests_per_second:
            # Calculate how long to wait
            oldest_in_window = self._request_timestamps[0]
            wait_time = 1.0 - (now - oldest_in_window)
            if wait_time > 0:
                logger.debug(
                    "rate_limit.throttling",
                    extra={"wait_seconds": round(wait_time, 3)},
                )
                time.sleep(wait_time)
