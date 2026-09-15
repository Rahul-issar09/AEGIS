"""AEGIS Agent 1 — Response diff analysis.

Calculates and models differentials between HTTP responses (e.g. across
different auth identities, or baseline vs. injected payloads) for evidence.
"""

from __future__ import annotations

import difflib
from typing import Any

from pydantic import BaseModel, Field

from agent1.http.models import HttpResponse


class HeaderDiff(BaseModel):
    """Difference in headers between two responses."""

    added: dict[str, str] = Field(default_factory=dict, description="Headers present in resp2 but not resp1")
    removed: dict[str, str] = Field(default_factory=dict, description="Headers present in resp1 but not resp2")
    modified: dict[str, tuple[str, str]] = Field(
        default_factory=dict, description="Headers present in both with different values (old, new)"
    )


class ResponseDiff(BaseModel):
    """Structured comparison between two HTTP responses."""

    status_code_1: int = Field(..., description="Status code of first response")
    status_code_2: int = Field(..., description="Status code of second response")
    status_code_match: bool = Field(..., description="True if status codes match")
    headers_diff: HeaderDiff = Field(..., description="Detailed header differences")
    body_hash_match: bool = Field(..., description="True if body hashes match")
    body_similarity: float = Field(
        ..., description="Body text similarity ratio between 0.0 (completely different) and 1.0 (identical)"
    )
    content_length_delta: int = Field(..., description="Difference in body sizes in bytes (len(resp2) - len(resp1))")
    response_time_delta_ms: float = Field(
        default=0.0, description="Difference in response times in ms (resp2 - resp1)"
    )

    @property
    def has_significant_difference(self) -> bool:
        """Heuristic for whether two responses are noticeably different."""
        if not self.status_code_match:
            return True
        if self.body_similarity < 0.85:
            return True
        return False


def compute_response_diff(resp1: HttpResponse, resp2: HttpResponse) -> ResponseDiff:
    """Compute differential between two HTTP responses."""
    status_code_match = resp1.status_code == resp2.status_code

    # Header differences
    h1 = {k.lower(): v for k, v in resp1.headers.items()}
    h2 = {k.lower(): v for k, v in resp2.headers.items()}

    added = {k: h2[k] for k in h2 if k not in h1}
    removed = {k: h1[k] for k in h1 if k not in h2}
    modified = {k: (h1[k], h2[k]) for k in h1 if k in h2 and h1[k] != h2[k]}

    header_diff = HeaderDiff(added=added, removed=removed, modified=modified)

    # Body hash match
    body_hash_match = resp1.body_hash == resp2.body_hash

    # Similarity ratio
    if body_hash_match:
        similarity = 1.0
    elif not resp1.body and not resp2.body:
        similarity = 1.0
    elif not resp1.body or not resp2.body:
        similarity = 0.0
    else:
        # Compute difflib similarity ratio
        # Truncate strings if extremely long to maintain performance
        b1 = resp1.body[:50000]
        b2 = resp2.body[:50000]
        matcher = difflib.SequenceMatcher(None, b1, b2, autojunk=False)
        similarity = round(matcher.ratio(), 3)

    size_delta = resp2.size - resp1.size
    time_delta = resp2.response_time_ms - resp1.response_time_ms

    return ResponseDiff(
        status_code_1=resp1.status_code,
        status_code_2=resp2.status_code,
        status_code_match=status_code_match,
        headers_diff=header_diff,
        body_hash_match=body_hash_match,
        body_similarity=similarity,
        content_length_delta=size_delta,
        response_time_delta_ms=round(time_delta, 2),
    )
