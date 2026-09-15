"""AEGIS Agent 1 — Evidence package.

Provides evidence collection, response diffing, confidence evaluation,
and credential redaction per PRD Sections 30-31, 47.
"""

from agent1.evidence.collector import EvidenceCollector
from agent1.evidence.confidence import ConfidenceCalculator
from agent1.evidence.diff import HeaderDiff, ResponseDiff, compute_response_diff
from agent1.evidence.models import Confidence, Evidence, EvidenceType
from agent1.evidence.redactor import Redactor

__all__ = [
    "Confidence",
    "ConfidenceCalculator",
    "Evidence",
    "EvidenceCollector",
    "EvidenceType",
    "HeaderDiff",
    "Redactor",
    "ResponseDiff",
    "compute_response_diff",
]
