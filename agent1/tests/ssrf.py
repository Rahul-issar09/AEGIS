"""AEGIS Agent 1 — Server-Side Request Forgery (SSRF) Testing Engine.

Implements controlled SSRF detection per PRD Sections 3.3, 10, 21, and 22:
- Identifies URL/destination parameters in discovered endpoints
- Injects unique canary tokens: scan_id + random_token
- Correlates injected URLs with out-of-band canary callbacks
- Enforces strict safety rules (no broad internal scanning, no cloud metadata)
"""

from __future__ import annotations

import logging
import time
from typing import Any
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

from agent1.evidence.models import Confidence, EvidenceType
from agent1.findings.models import EndpointInfo, Finding, FindingStatus, Severity, VulnerabilityType
from agent1.http.models import HttpRequest, HttpResponse, RequestResponse
from agent1.tests.base import SecurityTest, TestContext, TestResult
from agent1.tests.canary import (
    CanaryHit,
    CanaryRecorder,
    EmbeddedCanaryServer,
    generate_canary_token,
)

logger = logging.getLogger("aegis.tests.ssrf")

# Known parameter names commonly vulnerable to SSRF
_SSRF_PARAM_NAMES = {
    "url",
    "uri",
    "target",
    "dest",
    "destination",
    "redirect",
    "redirect_url",
    "redirect_to",
    "callback",
    "webhook",
    "feed",
    "link",
    "src",
    "source",
    "host",
    "domain",
    "fetch",
    "proxy",
    "load",
    "endpoint",
    "image",
    "avatar",
    "file_url",
    "import_url",
}

# Common path indicators for fetching remote resources
_FETCH_PATH_INDICATORS = ("fetch", "proxy", "webhook", "callback", "download", "preview", "import")


class SSRFTest(SecurityTest):
    """Server-Side Request Forgery (SSRF) security test.

    PRD Section 21 & 22:
    - Identifies URL-bearing parameters across discovered endpoints
    - Generates unique canary tokens per test
    - Transmits controlled canary URLs
    - Awaits and correlates callbacks from the target server
    - Strictly avoids cloud metadata and broad internal network probing
    """

    def __init__(
        self,
        canary_recorder: CanaryRecorder | None = None,
        canary_server: EmbeddedCanaryServer | None = None,
        callback_wait_seconds: float = 0.5,
    ) -> None:
        self.canary_recorder = canary_recorder or CanaryRecorder()
        self.canary_server = canary_server
        self.callback_wait_seconds = callback_wait_seconds

    @property
    def name(self) -> str:
        return "ssrf"

    @property
    def vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.SSRF

    def run(self, context: TestContext) -> list[TestResult]:
        """Run SSRF testing against candidate endpoints."""
        results: list[TestResult] = []

        # Determine canary configuration
        canary_domain = ""
        allow_internal = False
        if context.configuration and getattr(context.configuration, "ssrf", None):
            canary_domain = context.configuration.ssrf.canary_domain
            allow_internal = context.configuration.ssrf.allow_internal_targets

        # Start embedded canary server if no external canary domain configured
        owns_canary_server = False
        if not canary_domain and not self.canary_server:
            try:
                self.canary_server = EmbeddedCanaryServer(self.canary_recorder)
                self.canary_server.start()
                owns_canary_server = True
            except Exception as e:
                logger.error(f"Failed to start embedded canary server: {e}")
                return results

        try:
            candidate_endpoints = self._find_candidates(context.endpoints)
            logger.info(
                "ssrf.started",
                extra={"candidates_count": len(candidate_endpoints)},
            )

            for endpoint, param_name, param_location in candidate_endpoints:
                result = self._test_parameter(
                    context=context,
                    endpoint=endpoint,
                    param_name=param_name,
                    param_location=param_location,
                    canary_domain=canary_domain,
                )
                if result:
                    results.append(result)

            return results
        finally:
            # Clean up embedded server if we started it
            if owns_canary_server and self.canary_server:
                self.canary_server.stop()
                self.canary_server = None

    def _find_candidates(self, endpoints: list[Any]) -> list[tuple[Any, str, str]]:
        """Identify (endpoint, param_name, location) candidate tuples for SSRF testing."""
        candidates: list[tuple[Any, str, str]] = []

        for ep in endpoints:
            tested_params: set[str] = set()

            # 1. Inspect explicit parameters (from OpenAPI or crawler forms)
            for param in getattr(ep, "parameters", []):
                p_name_lower = param.name.lower()
                if p_name_lower in _SSRF_PARAM_NAMES and p_name_lower not in tested_params:
                    loc = getattr(param, "location", None)
                    loc_str = loc.value if hasattr(loc, "value") else str(loc or "query")
                    candidates.append((ep, param.name, loc_str))
                    tested_params.add(p_name_lower)

            # 2. Inspect query parameters detected on endpoint
            for q_name in getattr(ep, "query_parameters", []):
                q_name_lower = q_name.lower()
                if q_name_lower in _SSRF_PARAM_NAMES and q_name_lower not in tested_params:
                    candidates.append((ep, q_name, "query"))
                    tested_params.add(q_name_lower)

            # 3. Inspect raw path / URL for query parameters
            raw = getattr(ep, "raw_path", "") or getattr(ep, "path", "")
            if "?" in raw:
                query_str = raw.split("?", 1)[1]
                parsed_q = parse_qs(query_str, keep_blank_values=True)
                for q_name in parsed_q:
                    q_name_lower = q_name.lower()
                    if q_name_lower in _SSRF_PARAM_NAMES and q_name_lower not in tested_params:
                        candidates.append((ep, q_name, "query"))
                        tested_params.add(q_name_lower)

            # 4. If path suggests a fetcher but has no parameters, try standard "url" parameter
            clean_path = getattr(ep, "path", "").lower()
            if any(ind in clean_path for ind in _FETCH_PATH_INDICATORS) and not tested_params:
                candidates.append((ep, "url", "query"))
                tested_params.add("url")

        return candidates

    def _test_parameter(
        self,
        context: TestContext,
        endpoint: Any,
        param_name: str,
        param_location: str,
        canary_domain: str,
    ) -> TestResult | None:
        """Inject canary into parameter and verify callback."""
        scan_id = context.scan_session.scan_id
        token = generate_canary_token(scan_id)

        # Build canary URL
        if canary_domain:
            canary_url = f"http://{canary_domain}/canary/{token}"
        elif self.canary_server:
            canary_url = self.canary_server.build_canary_url(token)
        else:
            return None

        test_id = f"ssrf_{endpoint.id}_{param_name}_{token[:8]}"
        base_endpoint_url = urljoin(context.target, endpoint.path)

        # Construct request with injected canary URL
        method = endpoint.method.upper()
        req_resp: RequestResponse | None = None

        try:
            if method == "POST" and param_location in ("body", "formData"):
                # JSON or form body injection
                req_resp = context.http_client.post(
                    base_endpoint_url,
                    json={param_name: canary_url},
                )
            else:
                # Query parameter injection
                parsed = urlparse(base_endpoint_url)
                query_dict = parse_qs(parsed.query, keep_blank_values=True)
                query_dict[param_name] = [canary_url]
                new_query = urlencode(query_dict, doseq=True)
                target_url = urlunparse((
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    parsed.params,
                    new_query,
                    parsed.fragment,
                ))
                req_resp = context.http_client.get(target_url)

        except Exception as e:
            logger.debug(f"SSRF test request failed for {base_endpoint_url}: {e}")
            return None

        # Poll canary recorder for callback up to callback_wait_seconds
        hits = self.canary_recorder.get_hits(token)
        if not hits and self.callback_wait_seconds > 0:
            deadline = time.monotonic() + self.callback_wait_seconds
            poll_interval = 0.05
            while time.monotonic() < deadline:
                remaining = deadline - time.monotonic()
                time.sleep(min(poll_interval, max(0.01, remaining)))
                hits = self.canary_recorder.get_hits(token)
                if hits:
                    break

        if not hits:
            # No callback received → no confirmed SSRF
            logger.debug(
                "ssrf.no_callback",
                extra={"endpoint": endpoint.path, "param": param_name, "token": token},
            )
            return None

        # Callback CONFIRMED! Target made an outbound request to our canary.
        hit = hits[0]
        logger.warning(
            "ssrf.confirmed",
            extra={
                "endpoint": endpoint.path,
                "param": param_name,
                "token": token,
                "client_ip": hit.client_ip,
            },
        )

        # Collect evidence: Outbound injection request
        ev_req = context.evidence_collector.collect_request_response(
            req_resp,
            test_id=test_id,
            observation=(
                f"Injected canary URL into parameter '{param_name}' at {endpoint.method} {endpoint.path}"
            ),
            confidence=Confidence.CONFIRMED,
            metadata={"param_name": param_name, "canary_token": token, "canary_url": canary_url},
        )

        # Collect evidence: Out-of-band Canary Callback
        ev_canary = context.evidence_collector.collect_callback(
            canary_id=token,
            callback_source=hit.client_ip,
            test_id=test_id,
            observation=(
                f"Target application executed server-side callback to canary "
                f"from IP {hit.client_ip} matching token '{token}'"
            ),
            confidence=Confidence.CONFIRMED,
            metadata={"headers": hit.headers, "path": hit.path},
        )

        evidence_list = [ev for ev in (ev_req, ev_canary) if ev is not None]

        finding = Finding(
            finding_id=f"finding_ssrf_{endpoint.id}_{token[:6]}",
            scan_id=scan_id,
            test_id=test_id,
            vulnerability_type=VulnerabilityType.SSRF,
            title="Confirmed Server-Side Request Forgery (SSRF)",
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            status=FindingStatus.CONFIRMED,
            endpoint=EndpointInfo(
                method=endpoint.method,
                path=endpoint.path,
            ),
            description=(
                f"The endpoint {endpoint.method} {endpoint.path} accepts a destination URL in parameter "
                f"'{param_name}' and executes an outbound server-side HTTP request to that address. "
                f"A controlled canary received a verified callback from the target backend."
            ),
            impact=(
                "An attacker can induce the server-side application to make HTTP requests to arbitrary "
                "domains, potentially probing internal systems, intranet portals, or cloud services."
            ),
            evidence=[ev.evidence_id for ev in evidence_list],
            remediation=(
                "Validate and strictly sanitize destination URLs against a strict allowlist. "
                "Block requests targeting internal networks (RFC 1918), loopback addresses, "
                "and cloud metadata endpoints (169.254.169.254)."
            ),
            references=[
                "https://cwe.mitre.org/data/definitions/918.html",
                "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/",
            ],
        )


        return TestResult(
            test_id=test_id,
            test_name=self.name,
            vulnerability_type=self.vulnerability_type,
            status=FindingStatus.CONFIRMED,
            severity=Severity.HIGH,
            confidence=Confidence.CONFIRMED,
            endpoint=EndpointInfo(
                method=endpoint.method,
                path=endpoint.path,
                url=req_resp.request.url if req_resp else base_endpoint_url,
            ),
            evidence_ids=[ev.evidence_id for ev in evidence_list],
            finding=finding,
            details={"param_name": param_name, "canary_token": token},
        )

