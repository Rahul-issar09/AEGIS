"""AEGIS Agent 1 — Security Test Plugin Architecture.

Defines the SecurityTest abstract base class, TestContext, and TestResult
models per PRD Sections 35 & 36. Allows security tests to be added
modularly without modifying the orchestrator.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field

from agent1.evidence.models import Confidence
from agent1.findings.models import EndpointInfo, Finding, FindingStatus, Severity, VulnerabilityType

if TYPE_CHECKING:
    from agent1.auth.context import AuthContext
    from agent1.config import ScanConfig
    from agent1.discovery.models import Endpoint
    from agent1.evidence.collector import EvidenceCollector
    from agent1.http.client import HttpClient
    from agent1.orchestrator import ScanSession
    from agent1.scope.validator import ScopeController


class TestResult(BaseModel):
    """Result produced by executing a security test against an endpoint."""

    __test__ = False

    test_id: str = Field(..., description="Unique test execution ID")
    test_name: str = Field(..., description="Name of the security test plugin")
    vulnerability_type: VulnerabilityType = Field(..., description="Vulnerability category")
    status: FindingStatus = Field(default=FindingStatus.POTENTIAL, description="Confirmation status")
    severity: Severity = Field(default=Severity.MEDIUM, description="Calculated severity")
    confidence: Confidence = Field(default=Confidence.LOW, description="Evidence confidence")
    endpoint: EndpointInfo | None = Field(default=None, description="Affected endpoint")
    evidence_ids: list[str] = Field(default_factory=list, description="Associated evidence IDs")
    finding: Finding | None = Field(default=None, description="Generated Finding object if confirmed")
    details: dict[str, Any] = Field(default_factory=dict, description="Test-specific metadata")


class TestContext(BaseModel):
    """Context provided to every security test during execution (PRD Section 36)."""

    __test__ = False
    model_config = ConfigDict(arbitrary_types_allowed=True)

    scan_session: Any = Field(..., description="Current scan session")
    target: str = Field(..., description="Base target URL")
    endpoints: list[Any] = Field(default_factory=list, description="Discovered endpoints")
    http_client: Any = Field(..., description="Scope-enforcing HTTP client")
    auth_contexts: dict[str, Any] = Field(default_factory=dict, description="Configured identities")
    scope_controller: Any = Field(..., description="Active scope controller")
    evidence_collector: Any = Field(..., description="Central evidence collector")
    configuration: Any = Field(..., description="Full scan configuration")


class SecurityTest(ABC):
    """Abstract base class for all AEGIS security test plugins (PRD Section 35)."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Test identifier (e.g. 'bola', 'ssrf', 'sqli')."""
        ...

    @property
    @abstractmethod
    def vulnerability_type(self) -> VulnerabilityType:
        """Category of vulnerability this test targets."""
        ...

    @abstractmethod
    def run(self, context: TestContext) -> list[TestResult]:
        """Execute the security test against endpoints in context.

        Args:
            context: TestContext containing targets, endpoints, client, and auth contexts.

        Returns:
            List of TestResult objects.
        """
        ...
