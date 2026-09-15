"""AEGIS Agent 1 — Finding models.

Standardized schema for every security finding produced by Agent 1.
Findings must always reference evidence — no evidence means no
confirmed vulnerability.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from agent1.evidence.models import Confidence


class Severity(str, Enum):
    """Finding severity levels."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingStatus(str, Enum):
    """Finding confirmation status."""

    POTENTIAL = "POTENTIAL"
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class VulnerabilityType(str, Enum):
    """Supported vulnerability categories for MVP."""

    AUTHENTICATION = "AUTHENTICATION"
    BOLA = "BOLA"
    SSRF = "SSRF"
    SQLI = "SQLI"
    NOSQLI = "NOSQLI"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    XSS = "XSS"
    SECURITY_MISCONFIGURATION = "SECURITY_MISCONFIGURATION"
    CORS = "CORS"
    COOKIE_SECURITY = "COOKIE_SECURITY"
    SECURITY_HEADERS = "SECURITY_HEADERS"
    INFORMATION_DISCLOSURE = "INFORMATION_DISCLOSURE"


class EndpointInfo(BaseModel):
    """Minimal endpoint reference within a finding."""

    method: str = Field(..., description="HTTP method")
    path: str = Field(..., description="URL path (may include path params)")


class Finding(BaseModel):
    """A standardized security finding.

    Every confirmed finding must contain evidence references.
    No evidence → no confirmed vulnerability.
    """

    finding_id: str = Field(..., description="Unique finding identifier")
    scan_id: str = Field(..., description="Parent scan session ID")
    title: str = Field(..., description="Human-readable title")
    vulnerability_type: VulnerabilityType = Field(
        ..., description="Vulnerability category"
    )
    severity: Severity = Field(..., description="Finding severity")
    confidence: Confidence = Field(..., description="Confidence level")
    status: FindingStatus = Field(
        default=FindingStatus.POTENTIAL,
        description="Confirmation status",
    )
    endpoint: EndpointInfo | None = Field(
        default=None, description="Affected endpoint"
    )
    description: str = Field(
        default="", description="Detailed description of the vulnerability"
    )
    impact: str = Field(
        default="", description="Potential security impact"
    )
    evidence: list[str] = Field(
        default_factory=list,
        description="Evidence IDs supporting this finding",
    )
    remediation: str = Field(
        default="", description="Suggested remediation steps"
    )
    references: list[str] = Field(
        default_factory=list,
        description="Reference URLs or identifiers",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When this finding was created",
    )
