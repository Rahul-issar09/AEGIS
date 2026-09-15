"""AEGIS Agent 1 — Evidence confidence calculation engine.

Implements deterministic confidence scoring based on evidence quality
per PRD Section 47. A generic error must never automatically become a
confirmed vulnerability.
"""

from __future__ import annotations

from typing import Sequence

from agent1.evidence.models import Confidence


class ConfidenceCalculator:
    """Calculates evidence confidence from observed security properties.

    Rules per PRD Section 47:
    - LOW: Weak indicator (e.g. generic error, banner disclosure, single anomaly)
    - MEDIUM: Multiple indicators (e.g. status code shift + header reflection)
    - HIGH: Reproducible deterministic behavior (e.g. consistent response differential across auth contexts)
    - CONFIRMED: Direct security property violation demonstrated (e.g. unauthorized object access, active canary callback)

    Safeguard:
    - A generic HTTP/application error must NEVER automatically become CONFIRMED or HIGH.
    """

    @classmethod
    def evaluate(
        cls,
        indicators: Sequence[str] | None = None,
        direct_violation: bool = False,
        is_reproducible: bool = True,
        is_generic_error: bool = False,
    ) -> Confidence:
        """Evaluate and return appropriate confidence level.

        Args:
            indicators: List of observed indicators/signals.
            direct_violation: Whether a direct security property violation was proven.
            is_reproducible: Whether the behavior was deterministically reproduced.
            is_generic_error: Whether the observation was merely a generic error (e.g. 500 Internal Server Error).

        Returns:
            Calculated Confidence enum value.
        """
        # Critical PRD safeguard: generic errors can never exceed LOW
        if is_generic_error and not direct_violation:
            return Confidence.LOW

        # Direct proof of security property violation
        if direct_violation:
            if is_reproducible:
                return Confidence.CONFIRMED
            return Confidence.HIGH

        # Reproducible deterministic behavior with multiple indicators
        indicator_count = len(indicators or [])

        if is_reproducible:
            if indicator_count >= 2:
                return Confidence.HIGH
            elif indicator_count == 1:
                return Confidence.MEDIUM
            return Confidence.LOW

        # Non-reproducible or intermittent behavior
        if indicator_count >= 2:
            return Confidence.MEDIUM
        return Confidence.LOW
