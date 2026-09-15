"""AEGIS Agent 1 — Unit tests for Discovery Engine (Phase 2).

Tests:
- Endpoint & EndpointParameter models (PRD Section 12 & 16)
- EndpointNormalizer: path parameter extraction, regex normalization, deduplication (PRD Section 46)
- OpenApiParser: OpenAPI 3.0, Swagger 2.0, YAML specs, probe error resilience (PRD Section 15)
- HtmlCrawler: links, forms, scripts, depth limits, scope safety (PRD Section 15)
- DiscoveryEngine: coordination, stats, pluggable sources (PRD Section 8)
- Orchestrator integration: discovery execution and evidence capture
"""

import json
from unittest.mock import MagicMock

import pytest
import respx
import httpx

from agent1.config import ScanConfig, TargetConfig
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
from agent1.evidence.models import EvidenceType
from agent1.http.client import HttpClient
from agent1.orchestrator import ScanStatus, run_scan
from agent1.scope.policy import ScopePolicy
from agent1.scope.validator import ScopeController


# ===================================================================
# 1. Endpoint & Parameter Models
# ===================================================================

class TestEndpointModels:
    """Tests for Endpoint and EndpointParameter data models."""

    def test_create_endpoint_minimal(self):
        ep = Endpoint(
            id="ep_001",
            method="GET",
            scheme="https",
            host="example.test",
            port=443,
            path="/api/users",
        )
        assert ep.id == "ep_001"
        assert ep.endpoint_id == "ep_001"
        assert ep.method == "GET"
        assert ep.path == "/api/users"
        assert ep.url == "https://example.test/api/users"

    def test_endpoint_from_url_helper(self):
        ep = Endpoint.from_url(
            "https://api.example.test:8443/v1/items?filter=active",
            method="post",
            endpoint_id="ep_100",
            source="crawler",
        )
        assert ep.id == "ep_100"
        assert ep.method == "POST"
        assert ep.scheme == "https"
        assert ep.host == "api.example.test"
        assert ep.port == 8443
        assert ep.path == "/v1/items"
        assert ep.source == "crawler"

    def test_endpoint_signature_generation(self):
        ep1 = Endpoint(
            id="ep_001",
            method="GET",
            scheme="http",
            host="example.test",
            port=80,
            path="/users",
        )
        ep2 = Endpoint(
            id="ep_002",
            method="POST",
            scheme="http",
            host="example.test",
            port=80,
            path="/users",
        )
        assert ep1.signature != ep2.signature
        assert ep1.signature == "GET:example.test:80:/users"
        assert ep2.signature == "POST:example.test:80:/users"

    def test_endpoint_serialization_prd_format(self):
        param = EndpointParameter(
            name="id",
            location=ParameterLocation.PATH,
            type="identifier",
            required=True,
            description="User identifier",
        )
        ep = Endpoint(
            id="ep_001",
            method="GET",
            path="/api/users/{id}",
            parameters=[param],
            authentication_required=True,
            source="openapi",
        )
        dumped = ep.model_dump(mode="json")
        assert dumped["id"] == "ep_001"
        assert dumped["method"] == "GET"
        assert dumped["path"] == "/api/users/{id}"
        assert dumped["parameters"][0]["name"] == "id"
        assert dumped["parameters"][0]["location"] == "path"
        assert dumped["parameters"][0]["type"] == "identifier"
        assert dumped["authentication_required"] is True

    def test_parameter_locations(self):
        for loc in (
            ParameterLocation.PATH,
            ParameterLocation.QUERY,
            ParameterLocation.HEADER,
            ParameterLocation.BODY,
            ParameterLocation.FORM,
        ):
            p = EndpointParameter(name="test", location=loc)
            assert p.location == loc


# ===================================================================
# 2. Endpoint Normalizer & Deduplication
# ===================================================================

class TestEndpointNormalizer:
    """Tests for path parameter detection and endpoint deduplication."""

    def test_normalize_integer_segment(self):
        norm_path, params = EndpointNormalizer.normalize_path("/api/users/12345")
        assert norm_path == "/api/users/{id}"
        assert len(params) == 1
        assert params[0].name == "id"
        assert params[0].location == ParameterLocation.PATH
        assert params[0].type == "integer"

    def test_normalize_uuid_segment(self):
        norm_path, params = EndpointNormalizer.normalize_path(
            "/api/orders/550e8400-e29b-41d4-a716-446655440000"
        )
        assert norm_path == "/api/orders/{id}"
        assert len(params) == 1
        assert params[0].type == "identifier"

    def test_normalize_hash_segment(self):
        norm_path, params = EndpointNormalizer.normalize_path(
            "/api/files/5f4dcc3b5aa765d61d8327deb882cf99"
        )
        assert norm_path == "/api/files/{id}"
        assert len(params) == 1

    def test_normalize_prefixed_id(self):
        norm_path, params = EndpointNormalizer.normalize_path("/api/accounts/usr_98a76b")
        assert norm_path == "/api/accounts/{id}"
        assert len(params) == 1

    def test_normalize_express_colon_parameter(self):
        norm_path, params = EndpointNormalizer.normalize_path("/api/users/:userId/books/:bookId")
        assert norm_path == "/api/users/{userId}/books/{bookId}"
        assert len(params) == 2
        assert params[0].name == "userId"
        assert params[1].name == "bookId"

    def test_normalize_preserves_brackets(self):
        norm_path, params = EndpointNormalizer.normalize_path("/api/v1/items/{itemId}")
        assert norm_path == "/api/v1/items/{itemId}"
        assert len(params) == 1
        assert params[0].name == "itemId"

    def test_normalize_preserves_static_segments(self):
        norm_path, params = EndpointNormalizer.normalize_path("/api/v1/users/profile")
        assert norm_path == "/api/v1/users/profile"
        assert len(params) == 0

    def test_normalize_multiple_dynamic_segments(self):
        norm_path, params = EndpointNormalizer.normalize_path("/api/users/42/documents/99")
        assert norm_path == "/api/users/{id}/documents/{id_2}"
        assert len(params) == 2
        assert params[0].name == "id"
        assert params[1].name == "id_2"

    def test_deduplicate_merges_crawler_and_openapi(self):
        ep_crawl = Endpoint(
            id="crawl_1",
            method="GET",
            host="example.test",
            port=80,
            path="/api/users/10",
            source="crawler",
        )
        ep_openapi = Endpoint(
            id="oapi_1",
            method="GET",
            host="example.test",
            port=80,
            path="/api/users/{id}",
            parameters=[
                EndpointParameter(
                    name="id",
                    location=ParameterLocation.PATH,
                    type="integer",
                    description="User unique ID",
                )
            ],
            authentication_required=True,
            source="openapi",
        )

        deduped = EndpointNormalizer.deduplicate([ep_crawl, ep_openapi])
        assert len(deduped) == 1
        result = deduped[0]
        assert result.id == "ep_001"
        assert result.path == "/api/users/{id}"
        assert result.source == "crawler,openapi"
        assert result.authentication_required is True
        assert len(result.parameters) >= 1
        assert result.parameters[0].description == "User unique ID"

    def test_deduplicate_assigns_sequential_ids(self):
        endpoints = [
            Endpoint(id="t3", method="GET", host="ex.test", path="/b"),
            Endpoint(id="t1", method="GET", host="ex.test", path="/a"),
            Endpoint(id="t2", method="POST", host="ex.test", path="/a"),
        ]
        deduped = EndpointNormalizer.deduplicate(endpoints)
        assert len(deduped) == 3
        assert deduped[0].id == "ep_001"
        assert deduped[1].id == "ep_002"
        assert deduped[2].id == "ep_003"


# ===================================================================
# 3. OpenAPI Parser
# ===================================================================

class TestOpenApiParser:
    """Tests for OpenAPI / Swagger spec probing and parsing."""

    SAMPLE_OPENAPI_3 = {
        "openapi": "3.0.0",
        "info": {"title": "Test API", "version": "1.0"},
        "servers": [{"url": "/api/v1"}],
        "security": [{"bearerAuth": []}],
        "paths": {
            "/users/{id}": {
                "get": {
                    "summary": "Get user",
                    "parameters": [
                        {
                            "name": "id",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "integer"},
                            "description": "User ID",
                        }
                    ],
                },
                "put": {
                    "summary": "Update user",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "name": {"type": "string"},
                                        "email": {"type": "string"},
                                    },
                                    "required": ["email"],
                                }
                            }
                        }
                    },
                },
            },
            "/public/health": {
                "get": {
                    "summary": "Health check",
                    "security": [],  # Public override
                }
            },
        },
    }

    SAMPLE_SWAGGER_2 = {
        "swagger": "2.0",
        "basePath": "/v2",
        "paths": {
            "/items": {
                "get": {
                    "parameters": [
                        {
                            "name": "limit",
                            "in": "query",
                            "type": "integer",
                            "required": False,
                        }
                    ]
                }
            }
        },
    }

    def test_parse_openapi_3_spec(self):
        parser = OpenApiParser()
        endpoints = parser.parse_spec(self.SAMPLE_OPENAPI_3, "https://api.test")

        assert len(endpoints) == 3
        paths = {f"{e.method} {e.path}": e for e in endpoints}

        assert "GET /api/v1/users/{id}" in paths
        get_user = paths["GET /api/v1/users/{id}"]
        assert get_user.authentication_required is True
        assert len(get_user.parameters) == 1
        assert get_user.parameters[0].name == "id"
        assert get_user.parameters[0].location == ParameterLocation.PATH

        assert "PUT /api/v1/users/{id}" in paths
        put_user = paths["PUT /api/v1/users/{id}"]
        body_params = {p.name: p for p in put_user.parameters if p.location == ParameterLocation.BODY}
        assert "email" in body_params
        assert body_params["email"].required is True

        assert "GET /api/v1/public/health" in paths
        health = paths["GET /api/v1/public/health"]
        assert health.authentication_required is False  # Explicitly overridden with []

    def test_parse_swagger_2_spec(self):
        parser = OpenApiParser()
        endpoints = parser.parse_spec(self.SAMPLE_SWAGGER_2, "http://api.test")

        assert len(endpoints) == 1
        ep = endpoints[0]
        assert ep.method == "GET"
        assert ep.path == "/v2/items"
        assert "limit" in ep.query_parameters

    @respx.mock
    def test_probe_discovers_openapi_json(self):
        respx.get("https://example.test/openapi.json").respond(
            status_code=200,
            json=self.SAMPLE_OPENAPI_3,
        )

        policy = ScopePolicy.from_config(
            ScanConfig(target=TargetConfig(url="https://example.test"))
        )
        controller = ScopeController(policy)
        client = HttpClient(controller)

        parser = OpenApiParser()
        discovered = parser.discover("https://example.test", client)
        client.close()

        assert len(discovered) == 3

    @respx.mock
    def test_probe_handles_missing_spec_gracefully(self):
        for path in OpenApiParser().probe_paths:
            respx.get(f"https://example.test{path}").respond(status_code=404)

        policy = ScopePolicy.from_config(
            ScanConfig(target=TargetConfig(url="https://example.test"))
        )
        controller = ScopeController(policy)
        client = HttpClient(controller)

        parser = OpenApiParser()
        discovered = parser.discover("https://example.test", client)
        client.close()

        assert discovered == []


# ===================================================================
# 4. HTML Crawler
# ===================================================================

class TestHtmlCrawler:
    """Tests for HTML link and form crawler."""

    HTML_PAGE_1 = """
    <!DOCTYPE html>
    <html>
    <head><title>Test App</title></head>
    <body>
        <a href="/about">About Us</a>
        <a href="/users/100">User Profile</a>
        <a href="https://external.test/out-of-scope">External</a>

        <form action="/login" method="POST">
            <input type="text" name="username" />
            <input type="password" name="password" />
            <input type="submit" value="Login" />
        </form>

        <form action="/search" method="GET">
            <input type="text" name="q" />
            <select name="category"><option>All</option></select>
        </form>

        <script>
            fetch('/api/v1/notifications');
        </script>
    </body>
    </html>
    """

    HTML_ABOUT_PAGE = """
    <html><body><a href="/contact">Contact</a></body></html>
    """

    @respx.mock
    def test_crawl_extracts_links_forms_scripts(self):
        respx.get("http://example.test/").respond(
            status_code=200,
            html=self.HTML_PAGE_1,
        )
        respx.get("http://example.test/about").respond(
            status_code=200,
            html=self.HTML_ABOUT_PAGE,
        )
        respx.get("http://example.test/users/100").respond(
            status_code=200,
            text="User details",
        )
        respx.get("http://example.test/contact").respond(
            status_code=200,
            text="Contact page",
        )
        respx.get("http://example.test/api/v1/notifications").respond(
            status_code=200,
            json={"items": []},
        )

        policy = ScopePolicy.from_config(
            ScanConfig(target=TargetConfig(url="http://example.test"))
        )
        controller = ScopeController(policy)
        client = HttpClient(controller)

        crawler = HtmlCrawler(max_depth=2, max_pages=10)
        endpoints = crawler.discover("http://example.test", client)
        client.close()

        paths = {f"{e.method} {e.path}" for e in endpoints}

        assert "GET /" in paths
        assert "GET /about" in paths
        assert "GET /users/100" in paths
        assert "POST /login" in paths
        assert "GET /search" in paths
        assert "GET /api/v1/notifications" in paths
        # Depth 2 should find contact from about
        assert "GET /contact" in paths

    @respx.mock
    def test_crawler_form_parameters(self):
        respx.get("http://example.test/").respond(
            status_code=200,
            html=self.HTML_PAGE_1,
        )

        policy = ScopePolicy.from_config(
            ScanConfig(target=TargetConfig(url="http://example.test"))
        )
        controller = ScopeController(policy)
        client = HttpClient(controller)

        crawler = HtmlCrawler(max_depth=1, max_pages=2)
        endpoints = crawler.discover("http://example.test", client)
        client.close()

        login_ep = next(e for e in endpoints if e.path == "/login" and e.method == "POST")
        param_names = [p.name for p in login_ep.parameters]
        assert "username" in param_names
        assert "password" in param_names

    @respx.mock
    def test_crawler_avoids_infinite_loops(self):
        # A links to B, B links to A
        respx.get("http://example.test/a").respond(
            status_code=200,
            html='<a href="/b">Go to B</a>',
        )
        respx.get("http://example.test/b").respond(
            status_code=200,
            html='<a href="/a">Go to A</a>',
        )

        policy = ScopePolicy.from_config(
            ScanConfig(target=TargetConfig(url="http://example.test"))
        )
        controller = ScopeController(policy)
        client = HttpClient(controller)

        crawler = HtmlCrawler(max_depth=5, max_pages=10)
        endpoints = crawler.discover("http://example.test/a", client)
        client.close()

        paths = {e.path for e in endpoints}
        assert "/a" in paths
        assert "/b" in paths


# ===================================================================
# 5. Discovery Engine
# ===================================================================

class TestDiscoveryEngine:
    """Tests for the DiscoveryEngine orchestrating all discovery sources."""

    class DummySource(DiscoverySource):
        def __init__(self, name: str, endpoints: list[Endpoint]):
            self._name = name
            self._endpoints = endpoints

        @property
        def name(self) -> str:
            return self._name

        def discover(self, target_url: str, http_client: HttpClient) -> list[Endpoint]:
            return self._endpoints

    def test_engine_combines_sources_and_normalizes(self):
        src1 = self.DummySource(
            "openapi",
            [
                Endpoint(
                    id="o1",
                    method="GET",
                    host="app.test",
                    path="/api/users/{id}",
                    source="openapi",
                    authentication_required=True,
                )
            ],
        )
        src2 = self.DummySource(
            "crawler",
            [
                Endpoint(
                    id="c1",
                    method="GET",
                    host="app.test",
                    path="/api/users/42",
                    source="crawler",
                ),
                Endpoint(
                    id="c2",
                    method="POST",
                    host="app.test",
                    path="/api/users",
                    source="crawler",
                ),
            ],
        )

        engine = DiscoveryEngine(sources=[src1, src2])

        # Mock client since dummy sources don't make network calls
        mock_client = MagicMock(spec=HttpClient)

        result = engine.discover("http://app.test", mock_client)

        assert isinstance(result, DiscoveryResult)
        assert result.total_discovered == 2
        assert len(result.endpoints) == 2
        assert result.duration_seconds >= 0.0

        # Endpoint 1 should be normalized & deduplicated
        ep_users_id = next(e for e in result.endpoints if e.path == "/api/users/{id}")
        assert ep_users_id.source == "crawler,openapi"
        assert ep_users_id.authentication_required is True

        # Endpoint 2 is the POST /api/users
        ep_post_users = next(e for e in result.endpoints if e.method == "POST")
        assert ep_post_users.path == "/api/users"


# ===================================================================
# 6. Orchestrator Integration with Discovery
# ===================================================================

class TestOrchestratorDiscoveryIntegration:
    """Tests discovery execution during a full run_scan()."""

    @respx.mock
    def test_run_scan_executes_discovery_and_records_evidence(self):
        respx.get("http://example.test/").respond(
            status_code=200,
            html='<a href="/dashboard">Dashboard</a><a href="/users/5">User</a>',
        )
        respx.get("http://example.test/dashboard").respond(
            status_code=200,
            text="Dashboard",
        )
        respx.get("http://example.test/users/5").respond(
            status_code=200,
            text="User details",
        )
        # OpenAPI probes return 404
        for p in OpenApiParser().probe_paths:
            respx.get(f"http://example.test{p}").respond(status_code=404)

        config = ScanConfig(target=TargetConfig(url="http://example.test"))
        result = run_scan(config)

        assert result.session.status == ScanStatus.COMPLETED
        assert result.discovery is not None
        assert result.discovery.total_discovered > 0
        assert result.session.statistics["endpoints_discovered"] == result.discovery.total_discovered

        # Check that discovery evidence was recorded
        discovery_ev = [
            e for e in result.evidence if e.get("type") == EvidenceType.DISCOVERY.value
        ]
        assert len(discovery_ev) == 1
        assert "Discovered" in discovery_ev[0]["observation"]

        # Ensure discovered endpoints are normalized
        paths = [ep.path for ep in result.discovery.endpoints]
        assert "/users/{id}" in paths or "/users/5" in paths
