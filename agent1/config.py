"""AEGIS Agent 1 — Configuration models and YAML loading.

Handles scan configuration including target, scope, limits, safety,
and test selection. All settings are Pydantic-validated with safe defaults.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, HttpUrl


class TargetConfig(BaseModel):
    """Target application configuration."""

    url: str = Field(..., description="Target URL to scan")


class ScopeConfig(BaseModel):
    """Scope constraints — what the scanner is allowed to touch."""

    allowed_hosts: list[str] = Field(
        default_factory=list,
        description="Hostnames the scanner may send requests to",
    )
    allowed_ports: list[int] = Field(
        default_factory=lambda: [80, 443],
        description="Allowed TCP ports",
    )
    allowed_schemes: list[str] = Field(
        default_factory=lambda: ["http", "https"],
        description="Allowed URL schemes",
    )
    excluded_paths: list[str] = Field(
        default_factory=list,
        description="URL paths the scanner must never request",
    )
    allowed_paths: list[str] = Field(
        default_factory=list,
        description="If non-empty, only these path prefixes are allowed",
    )


class LimitsConfig(BaseModel):
    """Rate and resource limits for the scan."""

    max_requests: int = Field(
        default=1000,
        ge=1,
        description="Maximum total HTTP requests per scan",
    )
    requests_per_second: float = Field(
        default=5.0,
        gt=0,
        description="Maximum requests per second",
    )
    timeout_seconds: float = Field(
        default=10.0,
        gt=0,
        description="Per-request timeout in seconds",
    )
    max_redirects: int = Field(
        default=5,
        ge=0,
        description="Maximum number of redirects to follow per request",
    )
    scan_timeout_seconds: float = Field(
        default=3600.0,
        gt=0,
        description="Overall scan timeout in seconds",
    )


class SafetyConfig(BaseModel):
    """Safety controls — safe mode is ON by default."""

    safe_mode: bool = Field(
        default=True,
        description="Enable safe mode (limits rate, blocks destructive methods)",
    )
    allow_internal_network: bool = Field(
        default=False,
        description="Allow SSRF tests against internal network ranges",
    )
    destructive_tests: bool = Field(
        default=False,
        description="Allow PUT/DELETE/PATCH and other destructive HTTP methods",
    )


class TestsConfig(BaseModel):
    """Which security test modules to run."""

    __test__ = False

    authentication: bool = Field(default=True)
    bola: bool = Field(default=True)
    ssrf: bool = Field(default=True)
    injection: bool = Field(default=True)
    misconfiguration: bool = Field(default=True)


class SSRFConfig(BaseModel):
    """SSRF-specific configuration."""

    allow_internal_targets: bool = Field(
        default=False,
        description="Allow testing against internal network addresses",
    )
    canary_domain: str = Field(
        default="",
        description="Domain for SSRF canary callbacks",
    )


class ScanConfig(BaseModel):
    """Root configuration for an AEGIS scan."""

    target: TargetConfig
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    limits: LimitsConfig = Field(default_factory=LimitsConfig)
    safety: SafetyConfig = Field(default_factory=SafetyConfig)
    tests: TestsConfig = Field(default_factory=TestsConfig)
    ssrf: SSRFConfig = Field(default_factory=SSRFConfig)


def load_config_from_yaml(path: str | Path) -> dict[str, Any]:
    """Load a YAML configuration file and return it as a dictionary.

    Args:
        path: Path to the YAML configuration file.

    Returns:
        Parsed YAML content as a dictionary.

    Raises:
        FileNotFoundError: If the config file does not exist.
        yaml.YAMLError: If the file contains invalid YAML.
    """
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    with open(config_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    if data is None:
        return {}

    return data


def build_config(
    url: str,
    scope_file: str | Path | None = None,
    max_requests: int | None = None,
    rate_limit: float | None = None,
    timeout: float | None = None,
    tests: list[str] | None = None,
    safe_mode: bool = True,
) -> ScanConfig:
    """Build a ScanConfig from CLI arguments and optional config files.

    CLI arguments override file-based configuration.

    Args:
        url: Target URL to scan.
        scope_file: Optional path to a YAML scope/config file.
        max_requests: Override max requests limit.
        rate_limit: Override requests per second.
        timeout: Override per-request timeout.
        tests: List of test names to enable (disables all others).
        safe_mode: Enable/disable safe mode.

    Returns:
        Fully resolved ScanConfig.
    """
    # Start with file config if provided
    file_data: dict[str, Any] = {}
    if scope_file:
        file_data = load_config_from_yaml(scope_file)

    # Build target — CLI URL overrides file
    target_data = file_data.get("target", {})
    target_data["url"] = url
    target = TargetConfig(**target_data)

    # Build scope — derive allowed_hosts from URL if not specified
    scope_data = file_data.get("scope", {})
    scope = ScopeConfig(**scope_data)

    # Auto-populate allowed_hosts and allowed_ports from target URL
    from urllib.parse import urlparse
    parsed = urlparse(url)

    if not scope.allowed_hosts and parsed.hostname:
        scope.allowed_hosts = [parsed.hostname]

    if parsed.port and parsed.port not in scope.allowed_ports:
        scope.allowed_ports.append(parsed.port)

    # Build limits with CLI overrides
    limits_data = file_data.get("limits", {})
    if max_requests is not None:
        limits_data["max_requests"] = max_requests
    if rate_limit is not None:
        limits_data["requests_per_second"] = rate_limit
    if timeout is not None:
        limits_data["timeout_seconds"] = timeout
    limits = LimitsConfig(**limits_data)

    # Build safety
    safety_data = file_data.get("safety", {})
    safety_data["safe_mode"] = safe_mode
    if parsed.hostname in ("127.0.0.1", "::1"):
        safety_data["allow_internal_network"] = True
    safety = SafetyConfig(**safety_data)

    # Build tests — if specific tests provided, enable only those
    tests_data = file_data.get("tests", {})
    if tests:
        tests_config = TestsConfig(
            authentication="authentication" in tests or "auth" in tests,
            bola="bola" in tests,
            ssrf="ssrf" in tests,
            injection="injection" in tests,
            misconfiguration="misconfiguration" in tests or "misconfig" in tests,
        )
    else:
        tests_config = TestsConfig(**tests_data)

    # Build SSRF config
    ssrf_data = file_data.get("ssrf", {})
    ssrf = SSRFConfig(**ssrf_data)

    return ScanConfig(
        target=target,
        scope=scope,
        limits=limits,
        safety=safety,
        tests=tests_config,
        ssrf=ssrf,
    )
