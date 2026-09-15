"""AEGIS Agent 1 — Scope policy definitions.

Encapsulates what the scanner is and is not allowed to do.
The policy is derived from ScanConfig and never modified during a scan.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlparse


@dataclass(frozen=True)
class ScopePolicy:
    """Immutable scope policy governing all scanner requests.

    Derived once from ScanConfig at scan start. Every outgoing request
    is validated against this policy by the ScopeController.
    """

    allowed_hosts: frozenset[str] = field(default_factory=frozenset)
    allowed_ports: frozenset[int] = field(default_factory=lambda: frozenset({80, 443}))
    allowed_schemes: frozenset[str] = field(
        default_factory=lambda: frozenset({"http", "https"})
    )
    excluded_paths: tuple[str, ...] = field(default_factory=tuple)
    allowed_paths: tuple[str, ...] = field(default_factory=tuple)
    max_requests: int = 1000
    requests_per_second: float = 5.0
    timeout_seconds: float = 10.0
    max_redirects: int = 5
    safe_mode: bool = True
    allow_internal_network: bool = False
    destructive_tests: bool = False

    @classmethod
    def from_config(cls, config) -> ScopePolicy:
        """Build a ScopePolicy from a ScanConfig instance.

        Args:
            config: A ScanConfig with scope, limits, and safety sections.

        Returns:
            An immutable ScopePolicy.
        """
        allowed_hosts = list(config.scope.allowed_hosts)
        allowed_ports = list(config.scope.allowed_ports)

        if getattr(config, "target", None) and getattr(config.target, "url", None):
            from urllib.parse import urlparse
            parsed_target = urlparse(config.target.url)
            if not allowed_hosts and parsed_target.hostname:
                allowed_hosts.append(parsed_target.hostname)
            if parsed_target.port and parsed_target.port not in allowed_ports:
                allowed_ports.append(parsed_target.port)

        allow_internal = config.safety.allow_internal_network
        if getattr(config, "target", None) and getattr(config.target, "url", None):
            from urllib.parse import urlparse
            parsed_target = urlparse(config.target.url)
            if parsed_target.hostname in ("127.0.0.1", "::1"):
                allow_internal = True

        return cls(
            allowed_hosts=frozenset(allowed_hosts),
            allowed_ports=frozenset(allowed_ports),
            allowed_schemes=frozenset(config.scope.allowed_schemes),
            excluded_paths=tuple(config.scope.excluded_paths),
            allowed_paths=tuple(config.scope.allowed_paths),
            max_requests=config.limits.max_requests,
            requests_per_second=config.limits.requests_per_second,
            timeout_seconds=config.limits.timeout_seconds,
            max_redirects=config.limits.max_redirects,
            safe_mode=config.safety.safe_mode,
            allow_internal_network=allow_internal,
            destructive_tests=config.safety.destructive_tests,
        )

