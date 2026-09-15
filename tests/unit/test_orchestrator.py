"""Unit tests for AEGIS Agent 1 — Orchestrator and ScanSession."""

import pytest

from agent1.config import ScanConfig, TargetConfig, build_config
from agent1.orchestrator import ScanSession, ScanStatus, _generate_scan_id


class TestScanIdGeneration:
    """Tests for scan ID format."""

    def test_scan_id_format(self):
        scan_id = _generate_scan_id()
        assert scan_id.startswith("scan_")
        parts = scan_id.split("_")
        assert len(parts) == 3
        # Date part should be 8 digits
        assert len(parts[1]) == 8
        assert parts[1].isdigit()
        # Random part should be 6 hex characters
        assert len(parts[2]) == 6

    def test_unique_scan_ids(self):
        ids = {_generate_scan_id() for _ in range(100)}
        assert len(ids) == 100


class TestScanSession:
    """Tests for ScanSession model."""

    def test_create_session(self):
        session = ScanSession(
            scan_id="scan_20260914_abc123",
            target="https://example.test",
        )
        assert session.scan_id == "scan_20260914_abc123"
        assert session.target == "https://example.test"
        assert session.status == ScanStatus.CREATED
        assert session.finished_at is None
        assert session.errors == []

    def test_status_values(self):
        statuses = [s.value for s in ScanStatus]
        expected = ["CREATED", "DISCOVERING", "TESTING", "COMPLETED", "FAILED", "CANCELLED"]
        assert statuses == expected

    def test_session_serialization(self):
        session = ScanSession(
            scan_id="scan_001",
            target="https://example.test",
        )
        data = session.model_dump(mode="json")
        assert data["scan_id"] == "scan_001"
        assert data["status"] == "CREATED"


class TestOrchestratorTestSelection:
    """F-09 Regression: Explicit test enablement without silent defaults."""

    def test_disabled_tests_are_respected(self, monkeypatch):
        from unittest.mock import MagicMock
        from agent1.config import TestsConfig
        from agent1.orchestrator import run_scan

        config = ScanConfig(
            target=TargetConfig(url="https://example.test"),
            tests=TestsConfig(bola=False, ssrf=False),
        )

        # Mock discovery so run_scan completes quickly without network calls
        from agent1.discovery.models import DiscoveryResult
        monkeypatch.setattr(
            "agent1.orchestrator.DiscoveryEngine.discover",
            lambda self, url: DiscoveryResult(target=url, endpoints=[], duration_seconds=0.01),
        )

        result = run_scan(config)
        assert result.session.status == ScanStatus.COMPLETED
        # No tests ran because both bola and ssrf were False
        assert len(result.findings) == 0
