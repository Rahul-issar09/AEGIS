"""AEGIS Agent 1 — Broken Object Level Authorization (BOLA) Testing Engine.

Implements BOLA detection per PRD Sections 14, 17–20, and 35.
Tests whether one authenticated user (User B) can access objects
owned by another authenticated user (User A).
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from typing import Any
from urllib.parse import urljoin, urlparse

from agent1.evidence.confidence import ConfidenceCalculator
from agent1.evidence.diff import compute_response_diff
from agent1.evidence.models import Confidence, EvidenceType
from agent1.findings.models import EndpointInfo, Finding, FindingStatus, Severity, VulnerabilityType
from agent1.http.models import HttpRequest, HttpResponse, RequestResponse
from agent1.tests.base import SecurityTest, TestContext, TestResult

logger = logging.getLogger("aegis.tests.bola")

# Patterns indicating generic error response disguised as HTTP 200
_GENERIC_ERROR_PATTERNS = [
    re.compile(r'"error"\s*:', re.IGNORECASE),
    re.compile(r'"errors"\s*:', re.IGNORECASE),
    re.compile(r'"message"\s*:\s*"(?:not found|forbidden|unauthorized|denied|access denied|invalid)"', re.IGNORECASE),
    re.compile(r'"detail"\s*:\s*"(?:not found|forbidden|unauthorized|denied|access denied)"', re.IGNORECASE),
    re.compile(r'<\s*title\s*>\s*(?:Error|404|403|Forbidden|Not Found|Unauthorized)\s*<\s*/title\s*>', re.IGNORECASE),
]


def _is_generic_error_body(body: str) -> bool:
    """Check if response body represents a generic error despite HTTP 200."""
    if not body or body.strip() in ("{}", "[]", "null", ""):
        return True
    for pat in _GENERIC_ERROR_PATTERNS:
        if pat.search(body):
            return True
    return False


def _extract_concrete_id_from_raw_path(raw_path: str, normalized_path: str) -> str | None:
    """Extract concrete ID if normalized path has {id} and raw path had a value."""
    raw_segments = raw_path.strip("/").split("/")
    norm_segments = normalized_path.strip("/").split("/")

    if len(raw_segments) == len(norm_segments):
        for raw_seg, norm_seg in zip(raw_segments, norm_segments):
            if norm_seg.startswith("{") and norm_seg.endswith("}"):
                return raw_seg
    return None


class BOLATest(SecurityTest):
    """Broken Object Level Authorization (API1:2023 / BOLA) security test.

    PRD Section 17-20:
    - Identifies object-bearing endpoints (/users/{id}, /orders/{id})
    - Establishes baseline access as User A (owner)
    - Re-requests same object as User B (attacker)
    - Compares responses and rules out false positives (public endpoints, generic errors)
    - Emits CONFIRMED finding with full evidence linkage
    """

    @property
    def name(self) -> str:
        return "bola"

    @property
    def vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.BOLA

    def run(self, context: TestContext) -> list[TestResult]:
        """Run BOLA testing across all object-bearing candidate endpoints."""
        results: list[TestResult] = []

        # We need two distinct authenticated identities
        user_a = context.auth_contexts.get("USER_A")
        user_b = context.auth_contexts.get("USER_B")
        anonymous = context.auth_contexts.get("ANONYMOUS")

        if not user_a or not user_b:
            logger.info(
                "bola.skipped",
                extra={"reason": "BOLA testing requires at least USER_A and USER_B auth contexts"},
            )
            return results

        # Filter candidate endpoints: must have path parameters like {id} or dynamic segments
        candidate_endpoints = [
            ep for ep in context.endpoints
            if "{" in ep.path and "}" in ep.path and ep.method in ("GET", "POST")
        ]

        logger.info(
            "bola.started",
            extra={"candidates_count": len(candidate_endpoints)},
        )

        for ep in candidate_endpoints:
            # Determine candidate object IDs to test
            test_object_ids: list[str] = []

            # 1. Use User A's explicit owned objects if configured
            if user_a.owned_objects:
                test_object_ids.extend(user_a.owned_objects)

            # 2. Extract concrete ID observed during discovery if available
            if ep.raw_path:
                concrete_id = _extract_concrete_id_from_raw_path(ep.raw_path, ep.path)
                if concrete_id and concrete_id not in test_object_ids:
                    test_object_ids.append(concrete_id)

            # 3. Fallback common IDs if none known
            if not test_object_ids:
                test_object_ids = ["101", "1", "100", "123"]

            for obj_id in test_object_ids:
                result = self._test_single_object(
                    context=context,
                    endpoint=ep,
                    object_id=obj_id,
                    user_a=user_a,
                    user_b=user_b,
                    anonymous=anonymous,
                )
                if result:
                    results.append(result)
                    # If confirmed vulnerability found for this endpoint, move to next endpoint
                    if result.status == FindingStatus.CONFIRMED:
                        break

        return results

    def _test_single_object(
        self,
        context: TestContext,
        endpoint: Any,
        object_id: str,
        user_a: Any,
        user_b: Any,
        anonymous: Any,
    ) -> TestResult | None:
        """Execute cross-identity access test for a single object identifier."""
        # Replace first {param} in path with object_id
        test_path = re.sub(r"\{[a-zA-Z0-9_]+\}", object_id, endpoint.path, count=1)
        # If there are remaining brackets, don't test
        if "{" in test_path:
            return None

        test_url = urljoin(context.target, test_path)
        test_id = f"bola_{endpoint.id}_{object_id}"

        # -----------------------------------------------------------------
        # Step 1: Request as User A (Owner Baseline)
        # -----------------------------------------------------------------
        try:
            user_a_headers = user_a.get_effective_headers()
            req_resp_a = context.http_client.get(
                test_url,
                headers=user_a_headers,
                cookies=user_a.cookies,
            )
        except Exception as e:
            logger.debug(f"User A request failed for {test_url}: {e}")
            return None

        # Verify baseline access: User A must successfully access their object
        if req_resp_a.response.status_code != 200:
            logger.debug(
                "bola.baseline_failed",
                extra={"url": test_url, "status": req_resp_a.response.status_code},
            )
            return None

        if _is_generic_error_body(req_resp_a.response.body):
            return None

        # Baseline established! Collect User A evidence
        ev_a = context.evidence_collector.collect_request_response(
            req_resp_a,
            test_id=test_id,
            observation=f"User A ('{user_a.name}') successfully accessed object '{object_id}' (HTTP 200 OK)",
            confidence=Confidence.HIGH,
            metadata={"auth_context": user_a.id, "object_id": object_id, "role": "owner"},
        )

        # -----------------------------------------------------------------
        # Step 2: Request as Anonymous (Check Public Endpoint / False Positive)
        # -----------------------------------------------------------------
        is_public_endpoint = False
        try:
            req_resp_anon = context.http_client.get(test_url)
            if req_resp_anon.response.status_code == 200:
                diff_anon = compute_response_diff(req_resp_a.response, req_resp_anon.response)
                # If unauthenticated user gets identical data, it is a public endpoint (PRD Section 20)
                if diff_anon.body_similarity > 0.90:
                    is_public_endpoint = True
                    logger.debug(f"Endpoint {test_url} is public; skipping BOLA")
                    return None
        except Exception:
            pass

        # -----------------------------------------------------------------
        # Step 3: Request as User B (Cross-User Attacker Context)
        # -----------------------------------------------------------------
        try:
            user_b_headers = user_b.get_effective_headers()
            req_resp_b = context.http_client.get(
                test_url,
                headers=user_b_headers,
                cookies=user_b.cookies,
            )
        except Exception as e:
            logger.debug(f"User B request failed for {test_url}: {e}")
            return None

        # If User B is properly denied (401, 403, 404), access control is working!
        if req_resp_b.response.status_code in (401, 403, 404):
            logger.info(
                "bola.protected",
                extra={"url": test_url, "status": req_resp_b.response.status_code},
            )
            return TestResult(
                test_id=test_id,
                test_name=self.name,
                vulnerability_type=self.vulnerability_type,
                status=FindingStatus.FALSE_POSITIVE,
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                endpoint=EndpointInfo(method=endpoint.method, path=endpoint.path),
                details={"outcome": "protected", "user_b_status": req_resp_b.response.status_code},
            )

        # If User B receives 200 OK:
        if req_resp_b.response.status_code == 200:
            # Rule out false positive: generic error disguised in 200
            if _is_generic_error_body(req_resp_b.response.body):
                return None

            # Compute response diff
            diff_ab = compute_response_diff(req_resp_a.response, req_resp_b.response)

            # Both got 200 OK with substantial similarity, or User B accessed User A's private data
            # Record User B evidence
            ev_b = context.evidence_collector.collect_request_response(
                req_resp_b,
                test_id=test_id,
                observation=f"User B ('{user_b.name}') unauthorizedly accessed User A's object '{object_id}' (HTTP 200 OK)",
                confidence=Confidence.CONFIRMED,
                metadata={"auth_context": user_b.id, "object_id": object_id, "role": "attacker"},
            )

            # Record Diff evidence
            ev_diff = context.evidence_collector.collect_diff(
                baseline=req_resp_a,
                tested=req_resp_b,
                diff=diff_ab,
                test_id=test_id,
                observation=(
                    f"BOLA demonstrated: User B received object '{object_id}' data with "
                    f"similarity ratio {diff_ab.body_similarity}."
                ),
                confidence=Confidence.CONFIRMED,
            )

            evidence_ids = [ev_a.evidence_id, ev_b.evidence_id, ev_diff.evidence_id]

            # Generate Finding (PRD Section 32 & 33)
            finding_id = f"finding_bola_{uuid.uuid4().hex[:6]}"
            finding = Finding(
                finding_id=finding_id,
                scan_id=context.scan_session.scan_id,
                title="Confirmed Broken Object Level Authorization (BOLA)",
                vulnerability_type=VulnerabilityType.BOLA,
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                status=FindingStatus.CONFIRMED,
                endpoint=EndpointInfo(method=endpoint.method, path=endpoint.path),
                description=(
                    f"An authenticated user ('{user_b.name}') can access another user's "
                    f"('{user_a.name}') object '{object_id}' at {endpoint.method} {test_path}."
                ),
                impact=(
                    "An unauthorized authenticated user can inspect, access, or manipulate "
                    "sensitive resources and records belonging to other users."
                ),
                evidence=evidence_ids,
                remediation=(
                    "Enforce strict server-side authorization checks on every request. Verify that "
                    "the requesting authenticated session owns or is explicitly authorized to access "
                    "the requested object identifier before returning data."
                ),
                references=[
                    "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
                    "https://cwe.mitre.org/data/definitions/285.html",
                ],
            )

            logger.warning(
                "bola.confirmed",
                extra={"finding_id": finding_id, "endpoint": f"{endpoint.method} {endpoint.path}"},
            )

            return TestResult(
                test_id=test_id,
                test_name=self.name,
                vulnerability_type=self.vulnerability_type,
                status=FindingStatus.CONFIRMED,
                severity=Severity.HIGH,
                confidence=Confidence.CONFIRMED,
                endpoint=EndpointInfo(method=endpoint.method, path=endpoint.path),
                evidence_ids=evidence_ids,
                finding=finding,
                details={
                    "owner_context": user_a.id,
                    "attacker_context": user_b.id,
                    "object_id": object_id,
                    "owner_status": 200,
                    "attacker_status": req_resp_b.response.status_code,
                    "body_similarity": diff_ab.body_similarity,
                },
            )

        return None
