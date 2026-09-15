"""AEGIS Agent 1 — Discovery models.

Implements the normalized Endpoint model per PRD Section 12 and
discovery output structures per PRD Section 16.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, Field


class ParameterLocation(str, Enum):
    """Where an endpoint parameter is supplied."""

    PATH = "path"
    QUERY = "query"
    HEADER = "header"
    BODY = "body"
    FORM = "form"


class EndpointParameter(BaseModel):
    """Structured parameter metadata for an endpoint (PRD Section 16)."""

    name: str = Field(..., description="Parameter name")
    location: ParameterLocation = Field(
        default=ParameterLocation.QUERY,
        description="Parameter location (path, query, header, body, form)",
    )
    type: str = Field(
        default="string",
        description="Data type (string, integer, identifier, boolean, etc.)",
    )
    required: bool = Field(default=False, description="Whether parameter is mandatory")
    default: Any = Field(default=None, description="Default value if specified")
    description: str = Field(default="", description="Parameter description")


class Endpoint(BaseModel):
    """Normalized endpoint representation per PRD Section 12.

    Fields:
        id: Unique endpoint ID (e.g. ep_001)
        method: HTTP method (e.g. GET, POST)
        scheme: Scheme (http, https)
        host: Hostname
        port: Port number
        path: Normalized URL path (e.g. /api/users/{id})
        raw_path: Concrete URL path observed during discovery
        parameters: Structured parameter list
        query_parameters: List of query parameter names
        headers: Required or default headers
        source: Discovery origin (crawler, openapi, probe)
        authentication_required: Authentication requirement flag
        discovered_at: Discovery timestamp
    """

    id: str = Field(..., description="Unique endpoint identifier, e.g. ep_001")
    method: str = Field(..., description="HTTP method in uppercase, e.g. GET, POST")
    scheme: str = Field(default="http", description="URL scheme (http/https)")
    host: str = Field(default="", description="Target hostname")
    port: int = Field(default=80, description="Target port")
    path: str = Field(..., description="Normalized path, e.g. /api/users/{id}")
    raw_path: str | None = Field(
        default=None,
        description="Original observed concrete path before normalization",
    )
    parameters: list[EndpointParameter] = Field(
        default_factory=list,
        description="Structured parameter definitions",
    )
    query_parameters: list[str] = Field(
        default_factory=list,
        description="Names of query parameters",
    )
    headers: dict[str, str] = Field(
        default_factory=dict,
        description="Associated headers",
    )
    source: str = Field(
        default="crawler",
        description="Discovery source: crawler, openapi, probe",
    )
    authentication_required: bool | None = Field(
        default=None,
        description="Whether authentication is required (True/False/None for unknown)",
    )
    discovered_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when endpoint was discovered",
    )

    @property
    def endpoint_id(self) -> str:
        """Alias for id matching PRD Section 16 output."""
        return self.id

    @property
    def url(self) -> str:
        """Reconstructed full URL."""
        scheme = self.scheme or "http"
        port_part = ""
        if (scheme == "http" and self.port != 80) or (
            scheme == "https" and self.port != 443
        ):
            port_part = f":{self.port}"
        path = self.path if self.path.startswith("/") else f"/{self.path}"
        return f"{scheme}://{self.host}{port_part}{path}"

    @property
    def signature(self) -> str:
        """Unique signature for deduplication: METHOD:HOST:PORT:PATH."""
        return f"{self.method.upper()}:{self.host.lower()}:{self.port}:{self.path}"

    @classmethod
    def from_url(
        cls,
        url: str,
        method: str = "GET",
        endpoint_id: str = "ep_000",
        source: str = "crawler",
        **kwargs: Any,
    ) -> Endpoint:
        """Helper to construct an Endpoint directly from a full URL."""
        parsed = urlparse(url)
        port = parsed.port
        if port is None:
            port = 443 if parsed.scheme == "https" else 80

        path = parsed.path or "/"
        return cls(
            id=endpoint_id,
            method=method.upper(),
            scheme=parsed.scheme or "http",
            host=parsed.hostname or "",
            port=port,
            path=path,
            raw_path=path,
            source=source,
            **kwargs,
        )


class DiscoveryResult(BaseModel):
    """Aggregate result from endpoint discovery per PRD Section 16."""

    target: str = Field(..., description="Target base URL")
    endpoints: list[Endpoint] = Field(
        default_factory=list,
        description="Discovered normalized endpoints",
    )
    total_discovered: int = Field(
        default=0,
        description="Total number of unique endpoints discovered",
    )
    sources: dict[str, int] = Field(
        default_factory=dict,
        description="Endpoint counts grouped by discovery source",
    )
    duration_seconds: float = Field(
        default=0.0,
        description="Time taken for discovery phase in seconds",
    )
