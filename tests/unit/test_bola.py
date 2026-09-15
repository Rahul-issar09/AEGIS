"""Unit tests for AEGIS Agent 1 — BOLA Testing Engine (Phase 4).

Tests:
- Candidate endpoint detection (/users/{id})
- Identity requirement (USER_A and USER_B)
- Confirmed BOLA vulnerability detection
- Protected access control (no vulnerability)
- False positive prevention (public endpoints, generic 200 errors, empty bodies)
- Evidence generation and linkage
- Orchestrator end-to-end vertical slice integration
"""

import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import respx
import httpx

from agent1.auth.context import AuthContext, load_auth_contexts
from agent1.config import ScanConfig, TargetConfig
from agent1.discovery.models import Endpoint, EndpointParameter, ParameterLocation
from agent1.evidence.collector import EvidenceCollector
from agent1.evidence.models import Confidence, EvidenceType
from agent1.findings.models import FindingStatus, Severity, VulnerabilityType
from agent1.http.client import HttpClient
from agent1.orchestrator import ScanSession, ScanStatus, run_scan
from agent1.scope.policy import ScopePolicy
from agent1.scope.validator import ScopeController
from agent1.tests.base import TestContext
from agent1.tests.bola import BOLATest, _is_generic_error_body


def _make_test_context(
    endpoints: list[Endpoint],
    auth_contexts: dict[str, AuthContext],
    target_url: str = "https://example.test",
) -> tuple[TestContext, HttpClient]:
    """Helper to construct a TestContext with HttpClient."""
    policy = ScopePolicy.from_config(
        ScanConfig(target=TargetConfig(url=target_url))
    )
    controller = ScopeController(policy)
    client = HttpClient(controller)
    collector = EvidenceCollector("scan_test_001")
    session = ScanSession(scan_id="scan_test_001", target=target_url)

    ctx = TestContext(
        scan_session=session,
        target=target_url,
        endpoints=endpoints,
        http_client=client,
        auth_contexts=auth_contexts,
        scope_controller=controller,
        evidence_collector=collector,
        configuration=ScanConfig(target=TargetConfig(url=target_url)),
    )
    return ctx, client


class TestBolaFalsePositiveHelpers:
    """Tests for generic error detection helper."""

    def test_generic_error_json_patterns(self):
        assert _is_generic_error_body('{"error": "not found"}') is True
        assert _is_generic_error_body('{"message": "access denied"}') is True
        assert _is_generic_error_body('{"detail": "forbidden"}') is True
        assert _is_generic_error_body('{}') is True
        assert _is_generic_error_body('[]') is True
        assert _is_generic_error_body('') is True

    def test_valid_resource_body(self):
        body = '{"id": "101", "name": "Alice Smith", "email": "alice@example.test", "balance": 5000}'
        assert _is_generic_error_body(body) is False


class TestBolaEngine:
    """Tests for BOLATest plugin."""

    def test_bola_skipped_if_missing_auth_contexts(self):
        ep = Endpoint(
            id="ep_001",
            method="GET",
            path="/api/users/{id}",
            source="crawler",
        )
        # Only User A, missing User B
        auth = {
            "USER_A": AuthContext(id="USER_A", name="Alice", token="tok_a")
        }
        ctx, client = _make_test_context([ep], auth)
        try:
            results = BOLATest().run(ctx)
            assert results == []
        finally:
            client.close()

    @respx.mock
    def test_confirmed_bola_detection(self):
        target = "https://example.test"
        object_id = "101"
        resource_url = f"{target}/api/users/{object_id}"

        def mock_route(request):
            auth = request.headers.get("Authorization", "")
            if "token_a" in auth:
                return httpx.Response(200, json={"id": 101, "name": "Alice", "ssn": "000-11-2222", "role": "user"})
            elif "token_b" in auth:
                return httpx.Response(200, json={"id": 101, "name": "Alice", "ssn": "000-11-2222", "role": "user"})
            return httpx.Response(401, json={"error": "Unauthorized"})

        respx.get(resource_url).mock(side_effect=mock_route)

        ep = Endpoint(
            id="ep_001",
            method="GET",
            path="/api/users/{id}",
            raw_path="/api/users/101",
            source="openapi",
        )

        auth = {
            "USER_A": AuthContext(id="USER_A", name="Alice", token="token_a", owned_objects=["101"]),
            "USER_B": AuthContext(id="USER_B", name="Bob", token="token_b"),
            "ANONYMOUS": AuthContext(id="ANONYMOUS", name="Anon", role="anonymous"),
        }

        ctx, client = _make_test_context([ep], auth, target_url=target)
        try:
            results = BOLATest().run(ctx)
            assert len(results) == 1
            result = results[0]

            assert result.status == FindingStatus.CONFIRMED
            assert result.severity == Severity.HIGH
            assert result.confidence == Confidence.CONFIRMED
            assert result.finding is not None
            assert "BOLA" in result.finding.title
            assert result.finding.severity == Severity.HIGH
            assert len(result.finding.evidence) == 3

            # Check that evidence was stored in collector
            evidence_records = [ctx.evidence_collector.get(eid) for eid in result.finding.evidence]
            assert all(ev is not None for ev in evidence_records)
            ev_types = {ev.type for ev in evidence_records}
            assert EvidenceType.REQUEST in ev_types
            assert EvidenceType.DIFF in ev_types
        finally:
            client.close()

    @respx.mock
    def test_protected_endpoint_no_bola_finding(self):
        target = "https://example.test"
        object_id = "101"
        resource_url = f"{target}/api/users/{object_id}"

        def mock_protected(request):
            auth = request.headers.get("Authorization", "")
            if "token_a" in auth:
                return httpx.Response(200, json={"id": 101, "name": "Alice"})
            elif "token_b" in auth:
                return httpx.Response(403, json={"error": "Access denied"})
            return httpx.Response(401, json={"error": "Unauthorized"})

        respx.get(resource_url).mock(side_effect=mock_protected)

        ep = Endpoint(
            id="ep_001",
            method="GET",
            path="/api/users/{id}",
            source="crawler",
        )

        auth = {
            "USER_A": AuthContext(id="USER_A", name="Alice", token="token_a", owned_objects=["101"]),
            "USER_B": AuthContext(id="USER_B", name="Bob", token="token_b"),
            "ANONYMOUS": AuthContext(id="ANONYMOUS", name="Anon", role="anonymous"),
        }

        ctx, client = _make_test_context([ep], auth, target_url=target)
        try:
            results = BOLATest().run(ctx)
            assert len(results) == 1
            result = results[0]
            assert result.status == FindingStatus.FALSE_POSITIVE
            assert result.finding is None
        finally:
            client.close()

    @respx.mock
    def test_public_endpoint_false_positive_filtered(self):
        target = "https://example.test"
        object_id = "101"
        resource_url = f"{target}/api/items/{object_id}"

        public_data = {"id": 101, "title": "Public Article", "body": "Hello world"}
        respx.get(resource_url).respond(status_code=200, json=public_data)

        ep = Endpoint(
            id="ep_001",
            method="GET",
            path="/api/items/{id}",
            source="crawler",
        )

        auth = {
            "USER_A": AuthContext(id="USER_A", name="Alice", token="token_a", owned_objects=["101"]),
            "USER_B": AuthContext(id="USER_B", name="Bob", token="token_b"),
            "ANONYMOUS": AuthContext(id="ANONYMOUS", name="Anon", role="anonymous"),
        }

        ctx, client = _make_test_context([ep], auth, target_url=target)
        try:
            results = BOLATest().run(ctx)
            # Public endpoint should be skipped — no findings
            confirmed = [r for r in results if r.status == FindingStatus.CONFIRMED]
            assert len(confirmed) == 0
        finally:
            client.close()


class TestOrchestratorBolaIntegration:
    """End-to-end integration: ScanSession executes BOLA and generates findings."""

    @respx.mock
    def test_vertical_slice_discovery_to_confirmed_finding(self):
        target = "http://example.test"

        # Initial probe
        respx.get(f"{target}/").respond(
            status_code=200,
            html='<a href="/api/users/100">Profile</a>',
        )

        # OpenAPI probes return 404
        from agent1.discovery.openapi import DEFAULT_OPENAPI_PATHS
        for p in DEFAULT_OPENAPI_PATHS:
            respx.get(f"{target}{p}").respond(status_code=404)

        # Multi-auth behavior on /api/users/100
        def mock_users_api(request):
            auth = request.headers.get("Authorization", "")
            if "token_alice" in auth:
                return httpx.Response(200, json={"id": 100, "username": "alice", "private_records": [1, 2, 3]})
            elif "token_bob" in auth:
                return httpx.Response(200, json={"id": 100, "username": "alice", "private_records": [1, 2, 3]})
            # Anonymous (crawler or unauth check)
            return httpx.Response(401, json={"error": "Unauthorized"})

        respx.get(f"{target}/api/users/100").mock(side_effect=mock_users_api)

        # Create temporary auth config file
        auth_yaml = """
contexts:
  USER_A:
    name: "Alice"
    token: "token_alice"
    owned_objects: ["100"]
  USER_B:
    name: "Bob"
    token: "token_bob"
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(auth_yaml)
            auth_file = f.name

        try:
            config = ScanConfig(target=TargetConfig(url=target))
            result = run_scan(config, auth_config=auth_file)

            assert result.session.status == ScanStatus.COMPLETED
            assert result.session.statistics["findings_count"] >= 1
            assert len(result.findings) >= 1

            finding = result.findings[0]
            assert finding["vulnerability_type"] == "BOLA"
            assert finding["severity"] == "HIGH"
            assert finding["status"] == "CONFIRMED"
            assert len(finding["evidence"]) >= 2
        finally:
            Path(auth_file).unlink(missing_ok=True)
