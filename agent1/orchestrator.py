"""AEGIS Agent 1 — Scan orchestrator.

Coordinates the complete scan lifecycle: session management, scope
validation, discovery, security testing, evidence collection, and
report generation. This is the primary entry point for running a scan.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from agent1.auth.context import load_auth_contexts
from agent1.config import ScanConfig
from agent1.discovery.engine import DiscoveryEngine
from agent1.discovery.models import DiscoveryResult
from agent1.evidence.collector import EvidenceCollector
from agent1.evidence.models import Confidence, EvidenceType
from agent1.findings.models import Finding
from agent1.http.client import HttpClient
from agent1.scope.policy import ScopePolicy
from agent1.scope.validator import ScopeController, ScopeViolation
from agent1.tests.base import SecurityTest, TestContext, TestResult
from agent1.tests.bola import BOLATest
from agent1.tests.ssrf import SSRFTest

logger = logging.getLogger("aegis.orchestrator")


class ScanStatus(str, Enum):
    """Scan session lifecycle statuses."""

    CREATED = "CREATED"
    DISCOVERING = "DISCOVERING"
    TESTING = "TESTING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ScanSession(BaseModel):
    """Represents a single scan execution.

    Every scan gets a unique scan_id. All requests, evidence,
    and findings reference this session.
    """

    scan_id: str = Field(..., description="Unique scan identifier")
    target: str = Field(..., description="Target URL")
    started_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    finished_at: datetime | None = Field(default=None)
    status: ScanStatus = Field(default=ScanStatus.CREATED)
    configuration: ScanConfig | None = Field(default=None)
    errors: list[dict[str, Any]] = Field(default_factory=list)
    statistics: dict[str, Any] = Field(default_factory=dict)


def _generate_scan_id() -> str:
    """Generate a unique scan ID in the format scan_YYYYMMDD_xxxxxx."""
    date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
    short_id = uuid.uuid4().hex[:6]
    return f"scan_{date_str}_{short_id}"


class ScanResult(BaseModel):
    """Result of a completed scan."""

    session: ScanSession
    discovery: DiscoveryResult | None = Field(default=None)
    evidence: list[Any] = Field(default_factory=list)
    findings: list[Any] = Field(default_factory=list)


def run_scan(
    config: ScanConfig,
    auth_config: str | None = None,
) -> ScanResult:
    """Execute a complete security scan against the configured target.

    This is the main orchestration function. It:
    1. Creates a scan session
    2. Validates the target against scope policy
    3. Sends an initial probe request
    4. Collects evidence
    5. Returns results

    In later phases, discovery and security tests will be added
    between steps 3 and 4.

    Args:
        config: Fully resolved scan configuration.

    Returns:
        ScanResult with session, evidence, and findings.
    """
    scan_id = _generate_scan_id()
    session = ScanSession(
        scan_id=scan_id,
        target=config.target.url,
        configuration=config,
    )

    logger.info(
        "scan.started",
        extra={"scan_id": scan_id, "target": config.target.url},
    )

    # Build scope policy and controller
    policy = ScopePolicy.from_config(config)
    scope_controller = ScopeController(policy)

    # Validate target URL
    try:
        scope_controller.validate_target(config.target.url)
        logger.info(
            "scope.validated",
            extra={"scan_id": scan_id},
        )
    except ScopeViolation as e:
        session.status = ScanStatus.FAILED
        session.finished_at = datetime.now(timezone.utc)
        session.errors.append({
            "component": "scope",
            "error": str(e),
        })
        logger.error(
            "scope.validation_failed",
            extra={"scan_id": scan_id, "error": str(e)},
        )
        return ScanResult(session=session)

    # Initialize evidence collector
    evidence_collector = EvidenceCollector(scan_id)

    # Initialize HTTP client
    http_client = HttpClient(scope_controller)

    try:
        # Phase 1: Initial probe — verify target is reachable
        session.status = ScanStatus.DISCOVERING

        try:
            probe = http_client.get(config.target.url)
            evidence_collector.collect_request_response(
                probe,
                test_id="initial_probe",
                observation=(
                    f"Target responded with status {probe.response.status_code}"
                ),
            )
            logger.info(
                "probe.completed",
                extra={
                    "scan_id": scan_id,
                    "status_code": probe.response.status_code,
                },
            )
        except Exception as e:
            session.errors.append({
                "component": "probe",
                "error_type": type(e).__name__,
                "message": str(e),
            })
            logger.error(
                "probe.failed",
                extra={"scan_id": scan_id, "error": str(e)},
            )
            # Continue — probe failure is not fatal

        # Phase 2: Endpoint Discovery
        discovery_result: DiscoveryResult | None = None
        try:
            discovery_engine = DiscoveryEngine()
            discovery_result = discovery_engine.discover(config.target.url, http_client)

            evidence_collector.collect_observation(
                type=EvidenceType.DISCOVERY,
                observation=(
                    f"Discovered {discovery_result.total_discovered} unique endpoint(s) "
                    f"across sources: {discovery_result.sources}"
                ),
                test_id="discovery",
                confidence=Confidence.CONFIRMED,
            )
            logger.info(
                "discovery.completed",
                extra={
                    "scan_id": scan_id,
                    "total_endpoints": discovery_result.total_discovered,
                    "sources": discovery_result.sources,
                },
            )
        except Exception as e:
            session.errors.append({
                "component": "discovery",
                "error_type": type(e).__name__,
                "message": str(e),
            })
            logger.error(
                "discovery.failed",
                extra={"scan_id": scan_id, "error": str(e)},
            )

        # Phase 4+: Security testing
        session.status = ScanStatus.TESTING
        findings: list[Finding] = []

        auth_contexts = load_auth_contexts(auth_config)

        test_context = TestContext(
            scan_session=session,
            target=config.target.url,
            endpoints=discovery_result.endpoints if discovery_result else [],
            http_client=http_client,
            auth_contexts=auth_contexts,
            scope_controller=scope_controller,
            evidence_collector=evidence_collector,
            configuration=config,
        )

        active_tests: list[SecurityTest] = []
        if getattr(config.tests, "bola", True):
            active_tests.append(BOLATest())
        if getattr(config.tests, "ssrf", True):
            active_tests.append(SSRFTest())

        for test in active_tests:
            try:
                test_results = test.run(test_context)
                for tr in test_results:
                    if tr.finding:
                        findings.append(tr.finding)
                logger.info(
                    f"test.{test.name}.completed",
                    extra={"scan_id": scan_id, "results_count": len(test_results)},
                )
            except Exception as e:
                session.errors.append({
                    "component": f"test_{test.name}",
                    "error_type": type(e).__name__,
                    "message": str(e),
                })
                logger.error(
                    f"test.{test.name}.failed",
                    extra={"scan_id": scan_id, "error": str(e)},
                )

        # Mark scan as completed
        session.status = ScanStatus.COMPLETED
        session.finished_at = datetime.now(timezone.utc)
        session.statistics = {
            "total_requests": scope_controller.request_count,
            "endpoints_discovered": discovery_result.total_discovered if discovery_result else 0,
            "evidence_count": evidence_collector.count,
            "findings_count": len(findings),
        }

        logger.info(
            "scan.completed",
            extra={
                "scan_id": scan_id,
                "total_requests": scope_controller.request_count,
                "endpoints_discovered": session.statistics["endpoints_discovered"],
                "evidence_count": evidence_collector.count,
                "findings_count": len(findings),
            },
        )

    except Exception as e:
        session.status = ScanStatus.FAILED
        session.finished_at = datetime.now(timezone.utc)
        session.errors.append({
            "component": "orchestrator",
            "error_type": type(e).__name__,
            "message": str(e),
        })
        logger.error(
            "scan.failed",
            extra={"scan_id": scan_id, "error": str(e)},
        )

    finally:
        http_client.close()

    return ScanResult(
        session=session,
        discovery=discovery_result,
        evidence=[e.model_dump(mode="json") for e in evidence_collector.get_all_redacted()],
        findings=[f.model_dump(mode="json") for f in findings],
    )
