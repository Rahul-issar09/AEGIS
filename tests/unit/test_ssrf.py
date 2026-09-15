"""Unit tests for AEGIS SSRF Testing Engine and Canary Callback System.

Covers PRD Sections 3.3, 10, 21, and 22:
- Canary token generation and thread-safe recorder
- Embedded lightweight HTTP canary callback server
- Candidate SSRF parameter discovery
- Verified callback correlation -> CONFIRMED SSRF finding
- Absence of callback -> safe suppression (no false positive)
- Safety invariants (no cloud metadata, no broad internal scanning)
"""

import threading
import urllib.request
from unittest.mock import MagicMock, patch

import pytest

from agent1.config import LimitsConfig, SafetyConfig, ScanConfig, ScopeConfig, SSRFConfig, TargetConfig, TestsConfig
from agent1.discovery.models import Endpoint, EndpointParameter, ParameterLocation
from agent1.evidence.collector import EvidenceCollector
from agent1.findings.models import FindingStatus, Severity, VulnerabilityType
from agent1.http.client import HttpClient
from agent1.http.models import HttpRequest, HttpResponse, RequestResponse
from agent1.orchestrator import ScanSession, run_scan
from agent1.scope.policy import ScopePolicy
from agent1.scope.validator import ScopeController
from agent1.tests.base import TestContext
from agent1.tests.canary import (
    CanaryHit,
    CanaryRecorder,
    EmbeddedCanaryServer,
    generate_canary_token,
)
from agent1.tests.ssrf import SSRFTest, _SSRF_PARAM_NAMES


# =============================================================================
# 1. Canary System Tests
# =============================================================================

class TestCanarySystem:
    """Tests for token generation, recording, and embedded canary server."""

    def test_generate_canary_token_format(self):
        token = generate_canary_token("scan_20260914_abc123")
        assert token.startswith("scan_20260914_abc123_")
        assert len(token) > len("scan_20260914_abc123_")

    def test_canary_recorder_records_and_retrieves_hit(self):
        recorder = CanaryRecorder()
        token = "test_token_123"

        assert not recorder.has_hit(token)
        assert recorder.get_hits(token) == []

        hit = recorder.record_hit(
            token=token,
            client_ip="192.168.1.50",
            method="GET",
            path=f"/canary/{token}",
            headers={"User-Agent": "TargetBot/1.0"},
        )

        assert recorder.has_hit(token)
        hits = recorder.get_hits(token)
        assert len(hits) == 1
        assert hits[0].client_ip == "192.168.1.50"
        assert hits[0].headers["User-Agent"] == "TargetBot/1.0"

    def test_canary_recorder_thread_safety(self):
        recorder = CanaryRecorder()
        token = "concurrent_token"

        def record_worker(worker_id: int):
            for i in range(20):
                recorder.record_hit(
                    token=f"{token}_{worker_id}",
                    client_ip=f"10.0.0.{worker_id}",
                )

        threads = [threading.Thread(target=record_worker, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        for i in range(5):
            assert len(recorder.get_hits(f"{token}_{i}")) == 20

    def test_embedded_canary_server_receives_callback(self):
        recorder = CanaryRecorder()
        server = EmbeddedCanaryServer(recorder=recorder, host="127.0.0.1")
        server.start()

        try:
            test_token = "live_test_token_999"
            canary_url = server.build_canary_url(test_token)
            assert f"/canary/{test_token}" in canary_url

            # Simulate target server making an HTTP GET request to our canary URL
            req = urllib.request.Request(
                canary_url,
                headers={"User-Agent": "VulnerableServer-Webhook"},
            )
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                assert resp.status == 200

            # Verify callback hit was captured
            assert recorder.has_hit(test_token)
            hits = recorder.get_hits(test_token)
            assert len(hits) == 1
            assert hits[0].token == test_token
            assert "vulnerableserver-webhook" in str(hits[0].headers).lower()

        finally:
            server.stop()

    def test_canary_url_uses_externally_reachable_address(self):
        """F-05 Regression: Embedded canary server default must use externally reachable address."""
        server = EmbeddedCanaryServer(CanaryRecorder())
        url = server.build_canary_url("test_token")
        assert "127.0.0.1" not in url
        assert "0.0.0.0" not in url
        assert "/canary/test_token" in url


# =============================================================================
# 2. SSRF Parameter Discovery Tests
# =============================================================================

class TestSSRFParameterDiscovery:
    """Tests for discovering candidate endpoints and URL parameters."""

    def test_find_candidates_from_query_parameters(self):
        ep = Endpoint(
            id="ep_001",
            method="GET",
            path="/api/fetch",
            query_parameters=["url", "format"],
        )
        test = SSRFTest()
        candidates = test._find_candidates([ep])

        assert len(candidates) == 1
        endpoint, param_name, location = candidates[0]
        assert endpoint.id == "ep_001"
        assert param_name == "url"
        assert location == "query"

    def test_find_candidates_from_parameters_list(self):
        ep = Endpoint(
            id="ep_002",
            method="POST",
            path="/api/webhooks",
            parameters=[
                EndpointParameter(name="callback", location=ParameterLocation.BODY, type="string"),
                EndpointParameter(name="secret", location=ParameterLocation.BODY, type="string"),
            ],
        )
        test = SSRFTest()
        candidates = test._find_candidates([ep])

        assert len(candidates) == 1
        endpoint, param_name, location = candidates[0]
        assert param_name == "callback"
        assert location == "body"

    def test_find_candidates_from_fetch_path_indicator(self):
        # Endpoint with path /proxy and no declared parameters should fallback to 'url'
        ep = Endpoint(
            id="ep_003",
            method="GET",
            path="/api/v1/proxy",
        )
        test = SSRFTest()
        candidates = test._find_candidates([ep])

        assert len(candidates) == 1
        assert candidates[0][1] == "url"

    def test_non_ssrf_endpoints_ignored(self):
        ep = Endpoint(
            id="ep_004",
            method="GET",
            path="/api/users",
            query_parameters=["page", "limit", "sort"],
        )
        test = SSRFTest()
        candidates = test._find_candidates([ep])
        assert len(candidates) == 0


# =============================================================================
# 3. SSRF Execution & Callback Correlation Tests
# =============================================================================

class TestSSRFExecution:
    """Tests for SSRF testing execution, callback correlation, and findings."""

    @pytest.fixture
    def test_context(self):
        policy = ScopePolicy(
            allowed_hosts=frozenset(["target.test"]),
            allowed_ports=frozenset([80, 443]),
        )
        ctrl = ScopeController(policy)
        client = HttpClient(ctrl)

        scan_session = ScanSession(
            scan_id="scan_test_ssrf_001",
            target="https://target.test",
        )
        collector = EvidenceCollector("scan_test_ssrf_001")

        config = ScanConfig(
            target=TargetConfig(url="https://target.test"),
            scope=ScopeConfig(allowed_hosts=["target.test"]),
            tests=TestsConfig(ssrf=True),
            ssrf=SSRFConfig(allow_internal_targets=False),
        )

        return TestContext(
            scan_session=scan_session,
            target="https://target.test",
            endpoints=[],
            http_client=client,
            auth_contexts={},
            scope_controller=ctrl,
            evidence_collector=collector,
            configuration=config,
        )

    def test_ssrf_confirmed_when_canary_receives_callback(self, test_context):
        recorder = CanaryRecorder()
        test = SSRFTest(canary_recorder=recorder, callback_wait_seconds=0.01)

        ep = Endpoint(
            id="ep_ssrf",
            method="GET",
            path="/api/v1/preview",
            query_parameters=["target"],
        )
        test_context.endpoints = [ep]

        # Mock http_client to simulate target receiving canary URL and making callback
        def mock_get(url, **kwargs):
            # Simulate target triggering a callback to the canary URL
            from urllib.parse import parse_qs, urlparse
            query = parse_qs(urlparse(url).query)
            if "target" in query:
                injected_canary = query["target"][0]
                token = injected_canary.split("/canary/")[-1]
                recorder.record_hit(
                    token=token,
                    client_ip="198.51.100.25",  # Target server IP
                    method="GET",
                    path=f"/canary/{token}",
                    headers={"User-Agent": "VulnerableServer-Fetcher/1.0"},
                )

            req = HttpRequest(method="GET", url=url)
            resp = HttpResponse(status_code=200, headers={}, body='{"status":"preview generated"}')
            return RequestResponse(request=req, response=resp)

        test_context.http_client.get = MagicMock(side_effect=mock_get)

        results = test.run(test_context)

        assert len(results) == 1
        res = results[0]
        assert res.status == FindingStatus.CONFIRMED
        assert res.vulnerability_type == VulnerabilityType.SSRF
        assert res.finding is not None
        assert res.finding.severity == Severity.HIGH
        assert any("918" in ref for ref in res.finding.references)
        assert len(res.evidence_ids) >= 2  # Request/response + callback evidence
        assert len(res.finding.evidence) >= 2

    def test_ssrf_no_callback_produces_no_finding(self, test_context):
        recorder = CanaryRecorder()
        test = SSRFTest(canary_recorder=recorder, callback_wait_seconds=0.01)

        ep = Endpoint(
            id="ep_secure",
            method="GET",
            path="/api/v1/load",
            query_parameters=["url"],
        )
        test_context.endpoints = [ep]

        # Target rejects the request or does not call canary
        def mock_get(url, **kwargs):
            req = HttpRequest(method="GET", url=url)
            resp = HttpResponse(status_code=400, headers={}, body='{"error":"Invalid domain"}')
            return RequestResponse(request=req, response=resp)

        test_context.http_client.get = MagicMock(side_effect=mock_get)

        results = test.run(test_context)
        assert len(results) == 0

    def test_ssrf_detected_with_delayed_callback(self, test_context):
        """F-08 Regression: Async callback arriving during polling wait is captured."""
        recorder = CanaryRecorder()
        test = SSRFTest(canary_recorder=recorder, callback_wait_seconds=1.0)

        ep = Endpoint(
            id="ep_async_ssrf",
            method="GET",
            path="/api/v1/webhook",
            query_parameters=["url"],
        )
        test_context.endpoints = [ep]

        def mock_get(url, **kwargs):
            from urllib.parse import parse_qs, urlparse
            query = parse_qs(urlparse(url).query)
            token = query["url"][0].split("/canary/")[-1]

            def delayed_callback():
                import time
                time.sleep(0.05)
                recorder.record_hit(
                    token=token,
                    client_ip="198.51.100.25",
                    method="GET",
                    path=f"/canary/{token}",
                )

            t = threading.Thread(target=delayed_callback)
            t.daemon = True
            t.start()

            req = HttpRequest(method="GET", url=url)
            resp = HttpResponse(status_code=202, headers={}, body='{"status":"queued"}')
            return RequestResponse(request=req, response=resp)

        test_context.http_client.get = MagicMock(side_effect=mock_get)
        results = test.run(test_context)

        confirmed = [r for r in results if r.status == FindingStatus.CONFIRMED]
        assert len(confirmed) == 1
        assert confirmed[0].finding is not None


# =============================================================================
# 4. SSRF Safety Policy Tests
# =============================================================================

class TestSSRFSafety:
    """Tests enforcing PRD Section 22 safety bounds."""

    def test_ssrf_config_defaults(self):
        config = SSRFConfig()
        assert config.allow_internal_targets is False
        assert config.canary_domain == ""

    def test_ssrf_canary_token_unique_per_run(self):
        tokens = {generate_canary_token("scan_1") for _ in range(100)}
        assert len(tokens) == 100
