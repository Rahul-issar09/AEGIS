"""Unit tests for AEGIS Agent 1 — Evidence system (Phase 3).

Tests:
- Evidence collection across all EvidenceType categories (REQUEST, DIFF, AUTH_CONTEXT, CALLBACK, CONFIGURATION)
- Querying by ID, scan, test, type, and confidence level
- Response diff calculation and similarity metrics
- Confidence evaluation and generic error safeguards (PRD Section 47)
- Sensitive data redaction: headers, Set-Cookie attributes, URL query params, body tokens, and metadata (PRD Section 31)
"""

import pytest

from agent1.evidence.collector import (
    EvidenceCollector,
    _redact_body,
    _redact_headers,
)
from agent1.evidence.confidence import ConfidenceCalculator
from agent1.evidence.diff import ResponseDiff, compute_response_diff
from agent1.evidence.models import Confidence, Evidence, EvidenceType
from agent1.evidence.redactor import Redactor
from agent1.http.models import HttpMethod, HttpRequest, HttpResponse, RequestResponse


def _make_request_response(**kwargs) -> RequestResponse:
    """Helper to create a test RequestResponse pair."""
    req_kwargs = {
        "method": HttpMethod.GET,
        "url": "https://example.test/api/users?token=secret-token-123&page=1",
        "headers": {"Authorization": "Bearer secret-token-123"},
        "cookies": {"session": "abc123"},
    }
    req_kwargs.update(kwargs.get("request", {}))

    resp_kwargs = {
        "status_code": 200,
        "headers": {"Set-Cookie": "session=xyz789; HttpOnly; Secure; SameSite=Lax"},
        "body": '{"user": "test", "token": "secret_abc"}',
    }
    resp_kwargs.update(kwargs.get("response", {}))

    return RequestResponse(
        request=HttpRequest(**req_kwargs),
        response=HttpResponse(**resp_kwargs),
    )


# ===================================================================
# 1. Evidence Collection
# ===================================================================

class TestEvidenceCollector:
    """Tests for EvidenceCollector creation, retrieval, and counting."""

    def test_collect_request_response(self):
        collector = EvidenceCollector("scan_001")
        rr = _make_request_response()

        evidence = collector.collect_request_response(
            rr,
            test_id="bola_test",
            observation="User A accessed endpoint",
            confidence=Confidence.HIGH,
        )

        assert evidence.evidence_id.startswith("evidence_")
        assert evidence.scan_id == "scan_001"
        assert evidence.test_id == "bola_test"
        assert evidence.type == EvidenceType.REQUEST
        assert evidence.confidence == Confidence.HIGH
        assert collector.count == 1

    def test_unique_evidence_ids(self):
        collector = EvidenceCollector("scan_001")
        rr = _make_request_response()

        e1 = collector.collect_request_response(rr)
        e2 = collector.collect_request_response(rr)

        assert e1.evidence_id != e2.evidence_id
        assert collector.count == 2

    def test_get_by_id(self):
        collector = EvidenceCollector("scan_001")
        rr = _make_request_response()
        evidence = collector.collect_request_response(rr)

        retrieved = collector.get(evidence.evidence_id)
        assert retrieved is not None
        assert retrieved.evidence_id == evidence.evidence_id

    def test_get_missing_returns_none(self):
        collector = EvidenceCollector("scan_001")
        assert collector.get("nonexistent") is None

    def test_get_all(self):
        collector = EvidenceCollector("scan_001")
        rr = _make_request_response()

        collector.collect_request_response(rr)
        collector.collect_request_response(rr)

        all_evidence = collector.get_all()
        assert len(all_evidence) == 2

    def test_get_by_scan(self):
        collector = EvidenceCollector("scan_001")
        rr = _make_request_response()
        collector.collect_request_response(rr)

        assert len(collector.get_by_scan("scan_001")) == 1
        assert len(collector.get_by_scan("scan_other")) == 0

    def test_get_by_test(self):
        collector = EvidenceCollector("scan_001")
        rr = _make_request_response()

        collector.collect_request_response(rr, test_id="bola")
        collector.collect_request_response(rr, test_id="ssrf")
        collector.collect_request_response(rr, test_id="bola")

        bola_evidence = collector.get_by_test("bola")
        assert len(bola_evidence) == 2

    def test_get_by_type(self):
        collector = EvidenceCollector("scan_001")
        rr = _make_request_response()
        collector.collect_request_response(rr)
        collector.collect_auth_context("User A")

        assert len(collector.get_by_type(EvidenceType.REQUEST)) == 1
        assert len(collector.get_by_type(EvidenceType.AUTH_CONTEXT)) == 1
        assert len(collector.get_by_type(EvidenceType.DIFF)) == 0

    def test_get_by_confidence(self):
        collector = EvidenceCollector("scan_001")
        collector.collect_observation(type=EvidenceType.REQUEST, confidence=Confidence.LOW)
        collector.collect_observation(type=EvidenceType.REQUEST, confidence=Confidence.MEDIUM)
        collector.collect_observation(type=EvidenceType.REQUEST, confidence=Confidence.HIGH)
        collector.collect_observation(type=EvidenceType.REQUEST, confidence=Confidence.CONFIRMED)

        assert len(collector.get_by_confidence(Confidence.LOW)) == 4
        assert len(collector.get_by_confidence(Confidence.MEDIUM)) == 3
        assert len(collector.get_by_confidence(Confidence.HIGH)) == 2
        assert len(collector.get_by_confidence(Confidence.CONFIRMED)) == 1

    def test_collect_diff(self):
        collector = EvidenceCollector("scan_001")
        rr1 = _make_request_response(
            response={"status_code": 200, "body": '{"user": "A", "role": "admin"}'}
        )
        rr2 = _make_request_response(
            response={"status_code": 403, "body": '{"error": "Forbidden"}'}
        )

        evidence = collector.collect_diff(
            baseline=rr1,
            tested=rr2,
            test_id="bola_001",
            observation="Status code changed from 200 to 403",
        )

        assert evidence.type == EvidenceType.DIFF
        assert evidence.diff is not None
        assert evidence.diff.status_code_1 == 200
        assert evidence.diff.status_code_2 == 403
        assert evidence.diff.status_code_match is False
        assert evidence.diff.has_significant_difference is True
        assert evidence.metadata["baseline_status"] == 200
        assert evidence.metadata["tested_status"] == 403

    def test_collect_auth_context(self):
        collector = EvidenceCollector("scan_001")
        evidence = collector.collect_auth_context(
            context_name="USER_B",
            test_id="auth_switch",
        )
        assert evidence.type == EvidenceType.AUTH_CONTEXT
        assert evidence.metadata["auth_context"] == "USER_B"

    def test_collect_callback(self):
        collector = EvidenceCollector("scan_001")
        evidence = collector.collect_callback(
            canary_id="canary_xyz",
            callback_source="192.0.2.1",
            test_id="ssrf_test",
        )
        assert evidence.type == EvidenceType.CALLBACK
        assert evidence.confidence == Confidence.CONFIRMED
        assert evidence.metadata["canary_id"] == "canary_xyz"

    def test_collect_configuration(self):
        collector = EvidenceCollector("scan_001")
        evidence = collector.collect_configuration(
            key="Access-Control-Allow-Origin",
            value="*",
            test_id="cors_test",
        )
        assert evidence.type == EvidenceType.CONFIGURATION
        assert evidence.metadata["config_key"] == "Access-Control-Allow-Origin"
        assert evidence.metadata["config_value"] == "*"

    def test_collect_observation(self):
        collector = EvidenceCollector("scan_001")

        evidence = collector.collect_observation(
            type=EvidenceType.CONFIGURATION,
            observation="CORS wildcard detected",
            test_id="misconfig",
            confidence=Confidence.CONFIRMED,
        )

        assert evidence.type == EvidenceType.CONFIGURATION
        assert evidence.observation == "CORS wildcard detected"
        assert evidence.request is None
        assert evidence.response is None

    def test_collector_stats(self):
        collector = EvidenceCollector("scan_001")
        rr = _make_request_response()
        collector.collect_request_response(rr, confidence=Confidence.HIGH)
        collector.collect_auth_context("Admin", confidence=Confidence.CONFIRMED)

        stats = collector.stats()
        assert stats["total_evidence"] == 2
        assert stats["by_type"][EvidenceType.REQUEST.value] == 1
        assert stats["by_type"][EvidenceType.AUTH_CONTEXT.value] == 1
        assert stats["by_confidence"][Confidence.HIGH.value] == 1
        assert stats["by_confidence"][Confidence.CONFIRMED.value] == 1


# ===================================================================
# 2. Response Differential Analysis
# ===================================================================

class TestResponseDiff:
    """Tests for ResponseDiff and compute_response_diff."""

    def test_identical_responses_diff(self):
        resp1 = HttpResponse(
            status_code=200,
            headers={"Content-Type": "application/json"},
            body='{"status": "ok"}',
        )
        resp2 = HttpResponse(
            status_code=200,
            headers={"Content-Type": "application/json"},
            body='{"status": "ok"}',
        )

        diff = compute_response_diff(resp1, resp2)
        assert diff.status_code_match is True
        assert diff.body_hash_match is True
        assert diff.body_similarity == 1.0
        assert diff.content_length_delta == 0
        assert diff.has_significant_difference is False
        assert len(diff.headers_diff.added) == 0
        assert len(diff.headers_diff.removed) == 0
        assert len(diff.headers_diff.modified) == 0

    def test_different_status_code_diff(self):
        resp1 = HttpResponse(status_code=200, headers={}, body="OK")
        resp2 = HttpResponse(status_code=403, headers={}, body="Forbidden")

        diff = compute_response_diff(resp1, resp2)
        assert diff.status_code_match is False
        assert diff.has_significant_difference is True

    def test_header_diff_added_removed_modified(self):
        resp1 = HttpResponse(
            status_code=200,
            headers={"Server": "nginx", "X-Custom": "val1"},
            body="",
        )
        resp2 = HttpResponse(
            status_code=200,
            headers={"Server": "apache", "X-New": "added"},
            body="",
        )

        diff = compute_response_diff(resp1, resp2)
        assert "x-new" in diff.headers_diff.added
        assert "x-custom" in diff.headers_diff.removed
        assert "server" in diff.headers_diff.modified
        assert diff.headers_diff.modified["server"] == ("nginx", "apache")


# ===================================================================
# 3. Confidence Calculation
# ===================================================================

class TestConfidenceCalculator:
    """Tests for deterministic confidence evaluation (PRD Section 47)."""

    def test_generic_error_safeguard(self):
        # Critical PRD safeguard: generic errors must never exceed LOW
        conf = ConfidenceCalculator.evaluate(
            indicators=["500_status_code", "stack_trace_keyword"],
            is_generic_error=True,
            direct_violation=False,
        )
        assert conf == Confidence.LOW

    def test_direct_violation_reproducible(self):
        conf = ConfidenceCalculator.evaluate(
            direct_violation=True,
            is_reproducible=True,
        )
        assert conf == Confidence.CONFIRMED

    def test_direct_violation_non_reproducible(self):
        conf = ConfidenceCalculator.evaluate(
            direct_violation=True,
            is_reproducible=False,
        )
        assert conf == Confidence.HIGH

    def test_multiple_indicators_reproducible(self):
        conf = ConfidenceCalculator.evaluate(
            indicators=["auth_bypass_status", "content_leak"],
            is_reproducible=True,
            direct_violation=False,
        )
        assert conf == Confidence.HIGH

    def test_single_indicator_reproducible(self):
        conf = ConfidenceCalculator.evaluate(
            indicators=["cors_wildcard"],
            is_reproducible=True,
            direct_violation=False,
        )
        assert conf == Confidence.MEDIUM

    def test_multiple_indicators_non_reproducible(self):
        conf = ConfidenceCalculator.evaluate(
            indicators=["anomaly_1", "anomaly_2"],
            is_reproducible=False,
            direct_violation=False,
        )
        assert conf == Confidence.MEDIUM

    def test_no_indicators(self):
        conf = ConfidenceCalculator.evaluate(
            indicators=[],
            is_reproducible=True,
            direct_violation=False,
        )
        assert conf == Confidence.LOW


# ===================================================================
# 4. Sensitive Data Redaction
# ===================================================================

class TestRedactor:
    """Tests for Redactor (PRD Section 31)."""

    def test_authorization_redacted(self):
        headers = {"Authorization": "Bearer token123"}
        redacted = Redactor.redact_headers(headers)
        assert redacted["Authorization"] == "[REDACTED]"

    def test_cookie_values_redacted(self):
        cookie = "session=secret_sess_123; user_id=456"
        redacted = Redactor.redact_cookie_header(cookie)
        assert "secret_sess_123" not in redacted
        assert "456" not in redacted
        assert "session=[REDACTED]" in redacted
        assert "user_id=[REDACTED]" in redacted

    def test_set_cookie_preserves_attributes(self):
        set_cookie = "session=raw_secret_value; Secure; HttpOnly; SameSite=Lax"
        redacted = Redactor.redact_set_cookie(set_cookie)
        assert "raw_secret_value" not in redacted
        assert "session=[REDACTED]" in redacted
        assert "Secure" in redacted
        assert "HttpOnly" in redacted
        assert "SameSite=Lax" in redacted

    def test_api_keys_and_tokens_headers_redacted(self):
        headers = {
            "X-API-Key": "sk-123456",
            "X-Auth-Token": "tok-789",
            "X-CSRF-Token": "csrf-abc",
            "Proxy-Authorization": "Basic dXNlcjpwYXNz",
        }
        redacted = Redactor.redact_headers(headers)
        for val in redacted.values():
            assert val == "[REDACTED]"

    def test_url_query_parameters_redacted(self):
        url = "https://example.test/api/data?token=secret123&key=apiKey999&filter=active"
        redacted = Redactor.redact_url(url)
        assert "secret123" not in redacted
        assert "apiKey999" not in redacted
        assert "token=%5BREDACTED%5D" in redacted or "token=[REDACTED]" in redacted
        assert "key=%5BREDACTED%5D" in redacted or "key=[REDACTED]" in redacted
        assert "filter=active" in redacted

    def test_body_password_and_secret_redacted(self):
        body = '{"username": "admin", "password": "secret123", "client_secret": "xyz"}'
        redacted = Redactor.redact_body(body)
        assert "secret123" not in redacted
        assert "xyz" not in redacted
        assert "[REDACTED]" in redacted

    def test_body_bearer_token_redacted(self):
        body = "Authorization: Bearer mySecretBearerToken123"
        redacted = Redactor.redact_body(body)
        assert "mySecretBearerToken123" not in redacted
        assert "Bearer [REDACTED]" in redacted

    def test_body_jwt_redacted(self):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisSignature"
        body = f'{{"auth": "{jwt}"}}'
        redacted = Redactor.redact_body(body)
        assert jwt not in redacted
        assert "[REDACTED_JWT]" in redacted

    def test_body_aws_key_redacted(self):
        body = "Found key: AKIAIOSFODNN7EXAMPLE in response"
        redacted = Redactor.redact_body(body)
        assert "AKIAIOSFODNN7EXAMPLE" not in redacted
        assert "[REDACTED_AWS_KEY]" in redacted

    def test_body_private_key_redacted(self):
        body = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----"
        redacted = Redactor.redact_body(body)
        assert "MIIEowIBAAKCAQEA0" not in redacted
        assert "[REDACTED_PRIVATE_KEY]" in redacted

    def test_recursive_metadata_redaction(self):
        meta = {
            "auth": {"token": "secret_abc", "role": "admin"},
            "headers": ["Authorization: Bearer xyz123"],
            "session_id": "sid_9999",
        }
        redacted = Redactor.redact_value(meta)
        assert "secret_abc" not in str(redacted)
        assert "xyz123" not in str(redacted)
        assert redacted["session_id"] == "[REDACTED]"
        assert redacted["auth"]["role"] == "admin"


# ===================================================================
# 5. Full Evidence Redaction via Collector
# ===================================================================

class TestEvidenceRedaction:
    """Tests for complete evidence redaction via collector."""

    def test_redacted_evidence_has_no_secrets(self):
        collector = EvidenceCollector("scan_001")
        rr = _make_request_response()

        evidence = collector.collect_request_response(
            rr,
            observation="Observed bearer token: Bearer secret-token-123",
            metadata={"api_key": "raw_api_key_123"},
        )
        redacted = collector.get_redacted(evidence.evidence_id)

        assert redacted is not None
        assert "secret-token-123" not in redacted.request.url
        assert redacted.request.headers["Authorization"] == "[REDACTED]"
        assert redacted.request.cookies["session"] == "[REDACTED]"
        assert "xyz789" not in redacted.response.headers["Set-Cookie"]
        assert "Secure" in redacted.response.headers["Set-Cookie"]
        assert "secret_abc" not in redacted.response.body
        assert "secret-token-123" not in redacted.observation
        assert redacted.metadata["api_key"] == "[REDACTED]"

    def test_get_all_redacted(self):
        collector = EvidenceCollector("scan_001")
        rr = _make_request_response()

        collector.collect_request_response(rr)
        collector.collect_request_response(rr)

        all_redacted = collector.get_all_redacted()
        assert len(all_redacted) == 2
        for evidence in all_redacted:
            assert evidence.request.headers["Authorization"] == "[REDACTED]"
            assert "secret-token-123" not in evidence.request.url
