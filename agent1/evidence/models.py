"""AEGIS Agent 1 — Evidence models.

The evidence system is the foundation of Agent 1. Every finding must
point to evidence that demonstrates the vulnerability.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from agent1.evidence.diff import ResponseDiff
from agent1.http.models import HttpRequest, HttpResponse


class EvidenceType(str, Enum):
    """Types of evidence that can be collected."""

    REQUEST = "REQUEST"
    RESPONSE = "RESPONSE"
    DIFF = "DIFF"
    AUTH_CONTEXT = "AUTH_CONTEXT"
    DISCOVERY = "DISCOVERY"
    CALLBACK = "CALLBACK"
    CONFIGURATION = "CONFIGURATION"


class Confidence(str, Enum):
    """Confidence level of evidence or findings.

    LOW      — weak indicator
    MEDIUM   — multiple indicators
    HIGH     — reproducible deterministic behavior
    CONFIRMED — direct security property violation demonstrated
    """

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CONFIRMED = "CONFIRMED"


class Evidence(BaseModel):
    """A piece of evidence supporting a security finding.

    Evidence captures what was observed during a test, including
    the request/response pair and any derived observations.
    Sensitive data must be redacted before storage.
    """

    evidence_id: str = Field(..., description="Unique evidence identifier")
    scan_id: str = Field(..., description="Parent scan session ID")
    test_id: str = Field(
        default="", description="Security test that produced this evidence"
    )
    type: EvidenceType = Field(..., description="Evidence category")
    request: HttpRequest | None = Field(
        default=None, description="The HTTP request (if applicable)"
    )
    response: HttpResponse | None = Field(
        default=None, description="The HTTP response (if applicable)"
    )
    diff: ResponseDiff | None = Field(
        default=None, description="Differential between responses (for DIFF evidence)"
    )
    observation: str = Field(
        default="",
        description="Human-readable description of what was observed",
    )
    confidence: Confidence = Field(
        default=Confidence.LOW,
        description="Confidence level of this evidence",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When this evidence was collected",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional structured metadata",
    )
