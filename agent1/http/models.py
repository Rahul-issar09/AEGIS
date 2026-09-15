"""AEGIS Agent 1 — HTTP request and response models.

Internal representations for every HTTP interaction. These models are
used by the HTTP client, evidence collector, and security tests.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class HttpMethod(str, Enum):
    """Supported HTTP methods."""

    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    TRACE = "TRACE"


# Methods considered destructive — blocked in safe mode
DESTRUCTIVE_METHODS = {HttpMethod.PUT, HttpMethod.DELETE, HttpMethod.PATCH}

# Methods considered dangerous — flagged in misconfiguration checks
DANGEROUS_METHODS = {HttpMethod.TRACE}


class HttpRequest(BaseModel):
    """Internal representation of an outgoing HTTP request."""

    method: HttpMethod = Field(..., description="HTTP method")
    url: str = Field(..., description="Full request URL")
    headers: dict[str, str] = Field(
        default_factory=dict, description="Request headers"
    )
    cookies: dict[str, str] = Field(
        default_factory=dict, description="Request cookies"
    )
    query_params: dict[str, str] = Field(
        default_factory=dict, description="Query string parameters"
    )
    body: str | None = Field(default=None, description="Request body")
    auth_context: str | None = Field(
        default=None,
        description="Authentication context identifier (e.g. USER_A)",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When the request was sent",
    )


class HttpResponse(BaseModel):
    """Internal representation of an HTTP response."""

    status_code: int = Field(..., description="HTTP status code")
    headers: dict[str, str] = Field(
        default_factory=dict, description="Response headers"
    )
    body: str = Field(default="", description="Response body text")
    body_hash: str = Field(
        default="",
        description="SHA-256 hash of the response body",
    )
    response_time_ms: float = Field(
        default=0.0,
        description="Response time in milliseconds",
    )
    size: int = Field(default=0, description="Response body size in bytes")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When the response was received",
    )

    @staticmethod
    def compute_body_hash(body: str) -> str:
        """Compute SHA-256 hash of the response body."""
        return hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()


class RequestResponse(BaseModel):
    """A paired HTTP request and its response, used in evidence."""

    request: HttpRequest
    response: HttpResponse
