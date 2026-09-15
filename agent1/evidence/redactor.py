"""AEGIS Agent 1 — Sensitive data redaction engine.

Per PRD Section 31, all sensitive information (credentials, tokens, session IDs,
API keys, JWTs, passwords) must be strictly redacted before evidence is stored
in reports. Plaintext credentials must never appear in final reports.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

# Header keys that must have their entire value or token redacted
_SENSITIVE_HEADER_KEYS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-access-token",
    "proxy-authorization",
    "x-csrf-token",
    "x-xsrf-token",
    "session-id",
    "x-session-id",
    "apikey",
    "api-key",
}

# Query parameter names that typically hold secrets
_SENSITIVE_QUERY_PARAMS = {
    "token",
    "access_token",
    "auth_token",
    "refresh_token",
    "api_key",
    "apikey",
    "key",
    "secret",
    "password",
    "passwd",
    "session",
    "sessionid",
    "session_id",
    "sig",
    "signature",
}

# Regex for detecting sensitive JSON or form fields
_BODY_PATTERNS = [
    # JSON field values: "password": "...", "secret": "..."
    (
        re.compile(
            r'("?(?:password|passwd|secret|token|access_token|refresh_token|api_key|apikey|api-key|client_secret)"?\s*[:=]\s*)"[^"]*"',
            re.IGNORECASE,
        ),
        r'\1"[REDACTED]"',
    ),
    # Form-urlencoded values: password=secret&token=abc
    (
        re.compile(
            r'((?:^|[&;])(?:password|passwd|secret|token|access_token|api_key|apikey)=)[^&;]*',
            re.IGNORECASE,
        ),
        r'\1[REDACTED]',
    ),
    # Authorization header style: Bearer <token>
    (
        re.compile(r'(Bearer\s+)[A-Za-z0-9_\-\.=]+', re.IGNORECASE),
        r'\1[REDACTED]',
    ),
    # JWT tokens: eyJ...
    (
        re.compile(r'\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b'),
        r'[REDACTED_JWT]',
    ),
    # Private keys
    (
        re.compile(
            r'-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----'
        ),
        r'[REDACTED_PRIVATE_KEY]',
    ),
    # AWS Access Key IDs
    (
        re.compile(r'\b(AKIA[0-9A-Z]{16})\b'),
        r'[REDACTED_AWS_KEY]',
    ),
]


class Redactor:
    """Centralized engine for sanitizing evidence, headers, URLs, and bodies."""

    @classmethod
    def redact_headers(cls, headers: dict[str, str]) -> dict[str, str]:
        """Redact sensitive HTTP headers."""
        redacted: dict[str, str] = {}
        for key, value in headers.items():
            k_lower = key.lower()
            if k_lower == "set-cookie":
                redacted[key] = cls.redact_set_cookie(value)
            elif k_lower == "cookie":
                redacted[key] = cls.redact_cookie_header(value)
            elif k_lower in _SENSITIVE_HEADER_KEYS:
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = value
        return redacted

    @classmethod
    def redact_cookie_header(cls, cookie_header: str) -> str:
        """Redact cookie values in a Cookie header string (e.g. session=abc; user=1)."""
        parts = cookie_header.split(";")
        redacted_parts = []
        for part in parts:
            if "=" in part:
                name, _ = part.split("=", 1)
                redacted_parts.append(f"{name.strip()}=[REDACTED]")
            else:
                redacted_parts.append(part.strip())
        return "; ".join(redacted_parts)

    @classmethod
    def redact_set_cookie(cls, set_cookie: str) -> str:
        """Redact the cookie value in a Set-Cookie header while preserving attributes.

        PRD Section 29: Check Secure, HttpOnly, SameSite but do not expose value.
        Example: session=abc123; Secure; HttpOnly; SameSite=Lax
        Result: session=[REDACTED]; Secure; HttpOnly; SameSite=Lax
        """
        parts = [p.strip() for p in set_cookie.split(";")]
        if not parts:
            return "[REDACTED]"

        first_part = parts[0]
        if "=" in first_part:
            name, _ = first_part.split("=", 1)
            parts[0] = f"{name}=[REDACTED]"
        else:
            parts[0] = "[REDACTED]"

        return "; ".join(parts)

    @classmethod
    def redact_url(cls, url: str) -> str:
        """Redact sensitive query parameter values in a URL."""
        if not url or "?" not in url:
            return url

        try:
            parsed = urlparse(url)
            if not parsed.query:
                return url

            query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
            redacted_pairs = []
            for k, v in query_pairs:
                k_lower = k.lower()
                if k_lower in _SENSITIVE_QUERY_PARAMS:
                    # Avoid over-redacting common filter/sort parameters named 'key' with short values
                    if k_lower == "key" and len(v) <= 8:
                        redacted_pairs.append((k, v))
                    else:
                        redacted_pairs.append((k, "[REDACTED]"))
                else:
                    redacted_pairs.append((k, v))

            new_query = urlencode(redacted_pairs)
            return urlunparse(parsed._replace(query=new_query))
        except Exception:
            return url

    @classmethod
    def redact_body(cls, body: str | None) -> str | None:
        """Redact credentials and sensitive patterns from request/response bodies."""
        if body is None or not body:
            return body

        result = body
        for pattern, replacement in _BODY_PATTERNS:
            result = pattern.sub(replacement, result)
        return result

    @classmethod
    def redact_value(cls, val: Any) -> Any:
        """Recursively redact arbitrary structured data (e.g. metadata or observations)."""
        if isinstance(val, str):
            # Check for URL or body pattern
            return cls.redact_body(cls.redact_url(val))
        elif isinstance(val, dict):
            redacted_dict = {}
            for k, v in val.items():
                if isinstance(k, str):
                    k_lower = k.lower()
                    if k_lower in _SENSITIVE_HEADER_KEYS:
                        redacted_dict[k] = "[REDACTED]"
                    elif k_lower in _SENSITIVE_QUERY_PARAMS:
                        if k_lower == "key" and isinstance(v, str) and len(v) <= 8:
                            redacted_dict[k] = v
                        else:
                            redacted_dict[k] = "[REDACTED]"
                    else:
                        redacted_dict[k] = cls.redact_value(v)
                else:
                    redacted_dict[k] = cls.redact_value(v)
            return redacted_dict
        elif isinstance(val, list):
            return [cls.redact_value(item) for item in val]
        return val
