"""AEGIS Agent 1 — Discovery abstraction interface.

Defines the pluggable DiscoverySource contract per PRD Section 8.
Enables swapping or combining discovery engines (crawlers, OpenAPI parsers,
browser capture) without affecting security testing engines.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agent1.discovery.models import Endpoint
    from agent1.http.client import HttpClient


class DiscoverySource(ABC):
    """Abstract base class for all endpoint discovery mechanisms."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the discovery source (e.g. 'crawler', 'openapi')."""
        ...

    @abstractmethod
    def discover(
        self,
        target_url: str,
        http_client: HttpClient,
    ) -> list[Endpoint]:
        """Discover endpoints from the given target URL.

        All HTTP requests MUST go through the provided http_client,
        which enforces scope and safety policies.

        Args:
            target_url: The root target URL to inspect.
            http_client: Scope-enforcing HTTP client.

        Returns:
            List of discovered Endpoint objects.
        """
        ...
