"""AEGIS Agent 1 — Discovery package.

Provides endpoint discovery through HTML crawling, OpenAPI/Swagger parsing,
parameter normalization, and endpoint deduplication.
"""

from agent1.discovery.base import DiscoverySource
from agent1.discovery.crawler import HtmlCrawler
from agent1.discovery.engine import DiscoveryEngine
from agent1.discovery.models import (
    DiscoveryResult,
    Endpoint,
    EndpointParameter,
    ParameterLocation,
)
from agent1.discovery.normalizer import EndpointNormalizer
from agent1.discovery.openapi import OpenApiParser

__all__ = [
    "DiscoveryEngine",
    "DiscoveryResult",
    "DiscoverySource",
    "Endpoint",
    "EndpointNormalizer",
    "EndpointParameter",
    "HtmlCrawler",
    "OpenApiParser",
    "ParameterLocation",
]
