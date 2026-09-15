"""Unit tests for AEGIS Agent 1 — Configuration models and loading."""

import tempfile
from pathlib import Path

import pytest
import yaml

from agent1.config import (
    LimitsConfig,
    SafetyConfig,
    ScanConfig,
    ScopeConfig,
    TargetConfig,
    TestsConfig,
    build_config,
    load_config_from_yaml,
)


# ── Config model defaults ──────────────────────────────────────────


class TestConfigDefaults:
    """Verify safe default values per PRD Section 39."""

    def test_safety_defaults(self):
        safety = SafetyConfig()
        assert safety.safe_mode is True
        assert safety.allow_internal_network is False
        assert safety.destructive_tests is False

    def test_limits_defaults(self):
        limits = LimitsConfig()
        assert limits.max_requests == 1000
        assert limits.requests_per_second == 5.0
        assert limits.timeout_seconds == 10.0
        assert limits.max_redirects == 5

    def test_scope_defaults(self):
        scope = ScopeConfig()
        assert scope.allowed_ports == [80, 443]
        assert scope.allowed_schemes == ["http", "https"]
        assert scope.excluded_paths == []

    def test_tests_defaults(self):
        tests = TestsConfig()
        assert tests.authentication is True
        assert tests.bola is True
        assert tests.ssrf is True
        assert tests.injection is True
        assert tests.misconfiguration is True


# ── YAML loading ───────────────────────────────────────────────────


class TestYAMLLoading:
    """Tests for load_config_from_yaml()."""

    def test_load_valid_yaml(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(yaml.dump({
            "target": {"url": "https://example.test"},
            "scope": {"allowed_hosts": ["example.test"]},
        }))

        data = load_config_from_yaml(config_file)
        assert data["target"]["url"] == "https://example.test"
        assert "example.test" in data["scope"]["allowed_hosts"]

    def test_load_empty_yaml(self, tmp_path):
        config_file = tmp_path / "empty.yaml"
        config_file.write_text("")

        data = load_config_from_yaml(config_file)
        assert data == {}

    def test_load_missing_file(self):
        with pytest.raises(FileNotFoundError):
            load_config_from_yaml("/nonexistent/config.yaml")


# ── build_config ───────────────────────────────────────────────────


class TestBuildConfig:
    """Tests for build_config() from CLI arguments."""

    def test_minimal_config(self):
        config = build_config(url="https://example.test")

        assert config.target.url == "https://example.test"
        assert "example.test" in config.scope.allowed_hosts
        assert config.safety.safe_mode is True

    def test_auto_populate_allowed_hosts(self):
        config = build_config(url="https://myapp.example.com")
        assert "myapp.example.com" in config.scope.allowed_hosts

    def test_cli_overrides(self):
        config = build_config(
            url="https://example.test",
            max_requests=50,
            rate_limit=2.0,
            timeout=5.0,
        )
        assert config.limits.max_requests == 50
        assert config.limits.requests_per_second == 2.0
        assert config.limits.timeout_seconds == 5.0

    def test_specific_tests(self):
        config = build_config(
            url="https://example.test",
            tests=["bola", "ssrf"],
        )
        assert config.tests.bola is True
        assert config.tests.ssrf is True
        assert config.tests.authentication is False
        assert config.tests.injection is False
        assert config.tests.misconfiguration is False

    def test_misconfig_alias(self):
        config = build_config(
            url="https://example.test",
            tests=["misconfig"],
        )
        assert config.tests.misconfiguration is True

    def test_auth_alias(self):
        config = build_config(
            url="https://example.test",
            tests=["auth"],
        )
        assert config.tests.authentication is True

    def test_safe_mode_override(self):
        config = build_config(
            url="https://example.test",
            safe_mode=False,
        )
        assert config.safety.safe_mode is False

    def test_file_config_with_overrides(self, tmp_path):
        config_file = tmp_path / "scope.yaml"
        config_file.write_text(yaml.dump({
            "scope": {
                "allowed_hosts": ["example.test"],
                "excluded_paths": ["/logout"],
            },
            "limits": {
                "max_requests": 2000,
            },
        }))

        config = build_config(
            url="https://example.test",
            scope_file=str(config_file),
            max_requests=100,  # CLI override
        )

        assert "/logout" in config.scope.excluded_paths
        assert config.limits.max_requests == 100  # CLI wins


# ── ScanConfig validation ──────────────────────────────────────────


class TestScanConfigValidation:
    """Tests for Pydantic validation on config models."""

    def test_negative_max_requests_rejected(self):
        with pytest.raises(Exception):
            LimitsConfig(max_requests=0)

    def test_zero_rate_limit_rejected(self):
        with pytest.raises(Exception):
            LimitsConfig(requests_per_second=0)

    def test_negative_timeout_rejected(self):
        with pytest.raises(Exception):
            LimitsConfig(timeout_seconds=-1)

    def test_full_config_serialization(self):
        config = ScanConfig(
            target=TargetConfig(url="https://example.test"),
        )
        data = config.model_dump()
        assert data["target"]["url"] == "https://example.test"
        assert data["safety"]["safe_mode"] is True
