"""AEGIS Agent 1 — Evidence collector.

Captures, stores, queries, and redacts evidence objects. Handles sensitive
data redaction before evidence is included in reports per PRD Section 30-31, 47.
"""

from __future__ import annotations

import logging
import re
import uuid
from datetime import datetime, timezone
from typing import Any

from agent1.evidence.confidence import ConfidenceCalculator
from agent1.evidence.diff import ResponseDiff, compute_response_diff
from agent1.evidence.models import Confidence, Evidence, EvidenceType
from agent1.evidence.redactor import Redactor, _SENSITIVE_HEADER_KEYS, _BODY_PATTERNS
from agent1.http.models import HttpRequest, HttpResponse, RequestResponse

logger = logging.getLogger("aegis.evidence")


# Exposed for backward compatibility with existing tests
def _redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """Redact sensitive header values."""
    return Redactor.redact_headers(headers)


def _redact_body(body: str) -> str:
    """Redact sensitive values from a body string."""
    return Redactor.redact_body(body) or ""


def _generate_evidence_id() -> str:
    """Generate a unique evidence identifier."""
    short_id = uuid.uuid4().hex[:8]
    return f"evidence_{short_id}"


_CONFIDENCE_ORDER = {
    Confidence.LOW: 1,
    Confidence.MEDIUM: 2,
    Confidence.HIGH: 3,
    Confidence.CONFIRMED: 4,
}


class EvidenceCollector:
    """Collects, manages, and redacts evidence during a security scan.

    Per PRD Section 30: Evidence is the foundation of Agent 1.
    Every finding must point to evidence.
    """

    def __init__(self, scan_id: str) -> None:
        self._scan_id = scan_id
        self._evidence: dict[str, Evidence] = {}

    @property
    def scan_id(self) -> str:
        return self._scan_id

    @property
    def count(self) -> int:
        return len(self._evidence)

    def collect_request_response(
        self,
        request_response: RequestResponse,
        test_id: str = "",
        observation: str = "",
        confidence: Confidence = Confidence.LOW,
        metadata: dict | None = None,
    ) -> Evidence:
        """Collect evidence from an HTTP request/response pair."""
        evidence = Evidence(
            evidence_id=_generate_evidence_id(),
            scan_id=self._scan_id,
            test_id=test_id,
            type=EvidenceType.REQUEST,
            request=request_response.request,
            response=request_response.response,
            observation=observation,
            confidence=confidence,
            metadata=metadata or {},
        )

        self._evidence[evidence.evidence_id] = evidence
        logger.info(
            "evidence.collected",
            extra={
                "evidence_id": evidence.evidence_id,
                "scan_id": self._scan_id,
                "test_id": test_id,
                "type": evidence.type.value,
            },
        )
        return evidence

    def collect_diff(
        self,
        baseline: RequestResponse,
        tested: RequestResponse,
        diff: ResponseDiff | None = None,
        test_id: str = "",
        observation: str = "",
        confidence: Confidence = Confidence.HIGH,
        metadata: dict | None = None,
    ) -> Evidence:
        """Collect response differential evidence (PRD Section 30)."""
        calculated_diff = diff or compute_response_diff(
            baseline.response, tested.response
        )

        meta = dict(metadata or {})
        meta["baseline_status"] = baseline.response.status_code
        meta["tested_status"] = tested.response.status_code
        meta["baseline_url"] = baseline.request.url
        meta["tested_url"] = tested.request.url

        evidence = Evidence(
            evidence_id=_generate_evidence_id(),
            scan_id=self._scan_id,
            test_id=test_id,
            type=EvidenceType.DIFF,
            request=tested.request,
            response=tested.response,
            diff=calculated_diff,
            observation=observation,
            confidence=confidence,
            metadata=meta,
        )

        self._evidence[evidence.evidence_id] = evidence
        logger.info(
            "evidence.diff_collected",
            extra={
                "evidence_id": evidence.evidence_id,
                "scan_id": self._scan_id,
                "test_id": test_id,
            },
        )
        return evidence

    def collect_auth_context(
        self,
        context_name: str,
        test_id: str = "",
        observation: str = "",
        confidence: Confidence = Confidence.HIGH,
        metadata: dict | None = None,
    ) -> Evidence:
        """Collect authentication context switch / setup evidence."""
        meta = dict(metadata or {})
        meta["auth_context"] = context_name

        evidence = Evidence(
            evidence_id=_generate_evidence_id(),
            scan_id=self._scan_id,
            test_id=test_id,
            type=EvidenceType.AUTH_CONTEXT,
            observation=observation or f"Operating under auth context: {context_name}",
            confidence=confidence,
            metadata=meta,
        )

        self._evidence[evidence.evidence_id] = evidence
        return evidence

    def collect_callback(
        self,
        canary_id: str,
        callback_source: str = "",
        test_id: str = "",
        observation: str = "",
        confidence: Confidence = Confidence.CONFIRMED,
        metadata: dict | None = None,
    ) -> Evidence:
        """Collect external callback / SSRF confirmation evidence."""
        meta = dict(metadata or {})
        meta["canary_id"] = canary_id
        meta["callback_source"] = callback_source

        evidence = Evidence(
            evidence_id=_generate_evidence_id(),
            scan_id=self._scan_id,
            test_id=test_id,
            type=EvidenceType.CALLBACK,
            observation=observation or f"External callback received for canary {canary_id}",
            confidence=confidence,
            metadata=meta,
        )

        self._evidence[evidence.evidence_id] = evidence
        return evidence

    def collect_configuration(
        self,
        key: str,
        value: Any,
        test_id: str = "",
        observation: str = "",
        confidence: Confidence = Confidence.LOW,
        metadata: dict | None = None,
    ) -> Evidence:
        """Collect security configuration evidence (e.g. CORS, headers)."""
        meta = dict(metadata or {})
        meta["config_key"] = key
        meta["config_value"] = value

        evidence = Evidence(
            evidence_id=_generate_evidence_id(),
            scan_id=self._scan_id,
            test_id=test_id,
            type=EvidenceType.CONFIGURATION,
            observation=observation or f"Configuration observation: {key}={value}",
            confidence=confidence,
            metadata=meta,
        )

        self._evidence[evidence.evidence_id] = evidence
        return evidence

    def collect_observation(
        self,
        type: EvidenceType = EvidenceType.REQUEST,
        observation: str = "",
        test_id: str = "",
        confidence: Confidence = Confidence.LOW,
        metadata: dict | None = None,
        **kwargs: Any,
    ) -> Evidence:
        """Collect evidence from a non-HTTP observation.

        Also accepts 'evidence_type' keyword argument for convenience.
        """
        resolved_type = kwargs.get("evidence_type", type)

        evidence = Evidence(
            evidence_id=_generate_evidence_id(),
            scan_id=self._scan_id,
            test_id=test_id,
            type=resolved_type,
            observation=observation,
            confidence=confidence,
            metadata=metadata or {},
        )

        self._evidence[evidence.evidence_id] = evidence
        logger.info(
            "evidence.collected",
            extra={
                "evidence_id": evidence.evidence_id,
                "scan_id": self._scan_id,
                "type": resolved_type.value,
            },
        )
        return evidence

    def get(self, evidence_id: str) -> Evidence | None:
        """Retrieve evidence by ID."""
        return self._evidence.get(evidence_id)

    def get_all(self) -> list[Evidence]:
        """Retrieve all evidence for this scan (raw, unredacted).

        Warning:
            Returns raw evidence that may contain unredacted secrets or credentials.
            For reporting, exporting, or serialization, always use get_all_redacted().
        """
        return list(self._evidence.values())

    def get_all_raw(self) -> list[Evidence]:
        """Explicit alias for get_all() indicating raw unredacted evidence is returned."""
        return self.get_all()

    def get_by_scan(self, scan_id: str) -> list[Evidence]:
        """Retrieve all evidence for a specific scan ID."""
        return [e for e in self._evidence.values() if e.scan_id == scan_id]

    def get_by_test(self, test_id: str) -> list[Evidence]:
        """Retrieve all evidence produced by a specific test."""
        return [e for e in self._evidence.values() if e.test_id == test_id]

    def get_by_type(self, evidence_type: EvidenceType) -> list[Evidence]:
        """Retrieve all evidence matching a specific type."""
        return [e for e in self._evidence.values() if e.type == evidence_type]

    def get_by_confidence(self, min_confidence: Confidence) -> list[Evidence]:
        """Retrieve all evidence with at least the specified confidence level."""
        min_level = _CONFIDENCE_ORDER.get(min_confidence, 1)
        return [
            e
            for e in self._evidence.values()
            if _CONFIDENCE_ORDER.get(e.confidence, 1) >= min_level
        ]

    def get_redacted(self, evidence_id: str) -> Evidence | None:
        """Retrieve evidence with sensitive data redacted."""
        evidence = self.get(evidence_id)
        if evidence is None:
            return None
        return self._redact_evidence(evidence)

    def get_all_redacted(self) -> list[Evidence]:
        """Retrieve all evidence with sensitive data redacted."""
        return [self._redact_evidence(e) for e in self._evidence.values()]

    def stats(self) -> dict[str, Any]:
        """Summary statistics of all collected evidence."""
        by_type: dict[str, int] = {}
        by_conf: dict[str, int] = {}
        for e in self._evidence.values():
            by_type[e.type.value] = by_type.get(e.type.value, 0) + 1
            by_conf[e.confidence.value] = by_conf.get(e.confidence.value, 0) + 1

        return {
            "total_evidence": len(self._evidence),
            "by_type": by_type,
            "by_confidence": by_conf,
        }

    def _redact_evidence(self, evidence: Evidence) -> Evidence:
        """Create a redacted copy of an evidence object (PRD Section 31)."""
        redacted_request = None
        if evidence.request:
            redacted_url = Redactor.redact_url(str(evidence.request.url))
            redacted_headers = Redactor.redact_headers(evidence.request.headers)
            redacted_cookies = {
                k: "[REDACTED]" for k in evidence.request.cookies
            }
            redacted_body = (
                Redactor.redact_body(evidence.request.body)
                if evidence.request.body
                else None
            )

            redacted_request = evidence.request.model_copy(
                update={
                    "url": redacted_url,
                    "headers": redacted_headers,
                    "cookies": redacted_cookies,
                    "body": redacted_body,
                }
            )

        redacted_response = None
        if evidence.response:
            redacted_response = evidence.response.model_copy(
                update={
                    "headers": Redactor.redact_headers(evidence.response.headers),
                    "body": Redactor.redact_body(evidence.response.body),
                }
            )

        # Redact observation text and metadata
        redacted_observation = Redactor.redact_body(evidence.observation) or evidence.observation
        redacted_metadata = Redactor.redact_value(evidence.metadata)

        return evidence.model_copy(
            update={
                "request": redacted_request,
                "response": redacted_response,
                "observation": redacted_observation,
                "metadata": redacted_metadata,
            }
        )
