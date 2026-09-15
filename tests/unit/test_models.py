"""Unit tests for AEGIS Agent 1 — Finding and evidence models."""

import pytest

from agent1.evidence.models import Confidence, Evidence, EvidenceType
from agent1.findings.models import (
    EndpointInfo,
    Finding,
    FindingStatus,
    Severity,
    VulnerabilityType,
)


class TestFindingModel:
    """Tests for Finding model creation and serialization."""

    def test_create_finding(self):
        finding = Finding(
            finding_id="finding_001",
            scan_id="scan_001",
            title="Broken Object Level Authorization",
            vulnerability_type=VulnerabilityType.BOLA,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            status=FindingStatus.CONFIRMED,
            endpoint=EndpointInfo(method="GET", path="/api/users/{id}"),
            description="User B accessed User A's object.",
            impact="Unauthorized data access.",
            evidence=["evidence_001", "evidence_002"],
            remediation="Enforce server-side authorization.",
        )

        assert finding.finding_id == "finding_001"
        assert finding.severity == Severity.HIGH
        assert finding.status == FindingStatus.CONFIRMED
        assert len(finding.evidence) == 2

    def test_default_status_is_potential(self):
        finding = Finding(
            finding_id="f1",
            scan_id="s1",
            title="Test",
            vulnerability_type=VulnerabilityType.SQLI,
            severity=Severity.MEDIUM,
            confidence=Confidence.LOW,
        )
        assert finding.status == FindingStatus.POTENTIAL

    def test_finding_serialization(self):
        finding = Finding(
            finding_id="f1",
            scan_id="s1",
            title="Test Finding",
            vulnerability_type=VulnerabilityType.XSS,
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            status=FindingStatus.POTENTIAL,
            endpoint=EndpointInfo(method="GET", path="/search"),
        )

        data = finding.model_dump(mode="json")
        assert data["finding_id"] == "f1"
        assert data["vulnerability_type"] == "XSS"
        assert data["severity"] == "MEDIUM"
        assert data["endpoint"]["method"] == "GET"


class TestSeverityEnum:
    """Tests for severity level ordering."""

    def test_all_severity_levels(self):
        levels = [s.value for s in Severity]
        assert levels == ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


class TestConfidenceEnum:
    """Tests for confidence level ordering."""

    def test_all_confidence_levels(self):
        levels = [c.value for c in Confidence]
        assert levels == ["LOW", "MEDIUM", "HIGH", "CONFIRMED"]


class TestFindingStatus:
    """Tests for finding status values."""

    def test_all_statuses(self):
        statuses = [s.value for s in FindingStatus]
        assert "POTENTIAL" in statuses
        assert "CONFIRMED" in statuses
        assert "FALSE_POSITIVE" in statuses


class TestEvidenceModel:
    """Tests for Evidence model."""

    def test_create_evidence(self):
        evidence = Evidence(
            evidence_id="e1",
            scan_id="s1",
            type=EvidenceType.REQUEST,
            observation="User A accessed endpoint",
            confidence=Confidence.HIGH,
        )
        assert evidence.evidence_id == "e1"
        assert evidence.type == EvidenceType.REQUEST
        assert evidence.request is None  # No request attached

    def test_evidence_types(self):
        types = [t.value for t in EvidenceType]
        expected = [
            "REQUEST", "RESPONSE", "DIFF", "AUTH_CONTEXT",
            "DISCOVERY", "CALLBACK", "CONFIGURATION",
        ]
        assert types == expected
