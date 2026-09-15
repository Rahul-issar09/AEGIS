"""AEGIS Agent 1 — Discovery Engine.

Orchestrates multiple discovery sources (crawler, OpenAPI, etc.), applies
endpoint normalization and deduplication, and returns standardized discovery
results per PRD Section 15, 16, and 46.
"""

from __future__ import annotations

import logging
import time
from typing import Sequence

from agent1.discovery.base import DiscoverySource
from agent1.discovery.crawler import HtmlCrawler
from agent1.discovery.models import DiscoveryResult, Endpoint
from agent1.discovery.normalizer import EndpointNormalizer
from agent1.discovery.openapi import OpenApiParser
from agent1.http.client import HttpClient

logger = logging.getLogger("aegis.discovery.engine")


class DiscoveryEngine:
    """Coordinates endpoint discovery across multiple pluggable sources.

    Per PRD Section 8, discovery mechanisms are swappable and extensible.
    By default, activates both OpenAPI discovery and HTML crawling.
    """

    def __init__(
        self,
        sources: Sequence[DiscoverySource] | None = None,
        max_crawler_depth: int = 2,
        max_crawler_pages: int = 40,
    ) -> None:
        if sources is not None:
            self.sources = list(sources)
        else:
            # Default pipeline: OpenAPI probe first (rich schemas), then HTML crawler
            self.sources = [
                OpenApiParser(),
                HtmlCrawler(
                    max_depth=max_crawler_depth,
                    max_pages=max_crawler_pages,
                ),
            ]

    def discover(
        self,
        target_url: str,
        http_client: HttpClient,
    ) -> DiscoveryResult:
        """Run all configured discovery sources, normalize, deduplicate, and return results.

        Acceptance criterion (PRD Section 16 & 53 Phase 2):
            Target -> discovered endpoints -> JSON list

        Args:
            target_url: Target URL to discover.
            http_client: Centralized HTTP client enforcing scope and rate limits.

        Returns:
            DiscoveryResult containing normalized, deduplicated endpoints and statistics.
        """
        start_time = time.perf_counter()
        raw_endpoints: list[Endpoint] = []

        logger.info(
            "discovery.started",
            extra={"target": target_url, "source_count": len(self.sources)},
        )

        for source in self.sources:
            try:
                logger.info(
                    "discovery.source_started",
                    extra={"source": source.name, "target": target_url},
                )
                source_endpoints = source.discover(target_url, http_client)
                logger.info(
                    "discovery.source_finished",
                    extra={
                        "source": source.name,
                        "endpoints_found": len(source_endpoints),
                    },
                )
                raw_endpoints.extend(source_endpoints)
            except Exception as e:
                logger.warning(
                    "discovery.source_error",
                    extra={"source": source.name, "error": str(e)},
                )

        # Normalize and deduplicate across all sources
        deduped = EndpointNormalizer.deduplicate(raw_endpoints)

        # Aggregate counts by source
        source_counts: dict[str, int] = {}
        for ep in deduped:
            source_counts[ep.source] = source_counts.get(ep.source, 0) + 1

        duration = time.perf_counter() - start_time

        logger.info(
            "discovery.completed",
            extra={
                "target": target_url,
                "raw_count": len(raw_endpoints),
                "total_discovered": len(deduped),
                "duration_seconds": round(duration, 3),
            },
        )

        return DiscoveryResult(
            target=target_url,
            endpoints=deduped,
            total_discovered=len(deduped),
            sources=source_counts,
            duration_seconds=round(duration, 3),
        )
