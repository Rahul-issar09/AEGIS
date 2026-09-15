"""Unit tests for AEGIS Agent 1 — Scope controller and policy."""

import pytest

from agent1.config import LimitsConfig, SafetyConfig, ScanConfig, ScopeConfig, TargetConfig
from agent1.scope.policy import ScopePolicy
from agent1.scope.validator import (
    MaxRequestsExceeded,
    ScopeController,
    ScopeViolation,
)


def _make_policy(**overrides) -> ScopePolicy:
    """Helper to create a ScopePolicy with sensible defaults."""
    defaults = {
        "allowed_hosts": frozenset({"example.test"}),
        "allowed_ports": frozenset({80, 443}),
        "allowed_schemes": frozenset({"http", "https"}),
        "excluded_paths": (),
        "allowed_paths": (),
        "max_requests": 100,
        "requests_per_second": 50.0,  # High limit for tests
        "timeout_seconds": 10.0,
        "max_redirects": 5,
        "safe_mode": True,
        "allow_internal_network": False,
        "destructive_tests": False,
    }
    defaults.update(overrides)
    return ScopePolicy(**defaults)


def _make_controller(**overrides) -> ScopeController:
    """Helper to create a ScopeController with sensible defaults."""
    return ScopeController(_make_policy(**overrides))


# ── Target validation ──────────────────────────────────────────────


class TestTargetValidation:
    """Tests for validate_target()."""

    def test_valid_target(self):
        ctrl = _make_controller()
        ctrl.validate_target("https://example.test/api/users")

    def test_valid_target_http(self):
        ctrl = _make_controller()
        ctrl.validate_target("http://example.test/")

    def test_invalid_host(self):
        ctrl = _make_controller()
        with pytest.raises(ScopeViolation, match="Host.*not in allowed hosts"):
            ctrl.validate_target("https://evil.com/")

    def test_invalid_scheme(self):
        ctrl = _make_controller()
        with pytest.raises(ScopeViolation, match="Scheme.*not in allowed"):
            ctrl.validate_target("ftp://example.test/")

    def test_invalid_port(self):
        ctrl = _make_controller()
        with pytest.raises(ScopeViolation, match="Port.*not in allowed"):
            ctrl.validate_target("https://example.test:8080/")


# ── Request validation ─────────────────────────────────────────────


class TestRequestValidation:
    """Tests for validate()."""

    def test_valid_request(self):
        ctrl = _make_controller()
        ctrl.validate("GET", "https://example.test/api/users")

    def test_invalid_host_request(self):
        ctrl = _make_controller()
        with pytest.raises(ScopeViolation, match="Host"):
            ctrl.validate("GET", "https://attacker.com/steal")

    def test_invalid_port_request(self):
        ctrl = _make_controller()
        with pytest.raises(ScopeViolation, match="Port"):
            ctrl.validate("GET", "https://example.test:9999/")

    def test_invalid_scheme_request(self):
        ctrl = _make_controller()
        with pytest.raises(ScopeViolation, match="Scheme"):
            ctrl.validate("GET", "ftp://example.test/file")


# ── Path validation ────────────────────────────────────────────────


class TestPathValidation:
    """Tests for excluded and allowed path enforcement."""

    def test_excluded_path_exact(self):
        ctrl = _make_controller(excluded_paths=("/logout", "/delete"))
        with pytest.raises(ScopeViolation, match="excluded"):
            ctrl.validate("GET", "https://example.test/logout")

    def test_excluded_path_prefix(self):
        ctrl = _make_controller(excluded_paths=("/admin/destructive",))
        with pytest.raises(ScopeViolation, match="excluded"):
            ctrl.validate("GET", "https://example.test/admin/destructive/action")

    def test_non_excluded_path_allowed(self):
        ctrl = _make_controller(excluded_paths=("/logout",))
        ctrl.validate("GET", "https://example.test/api/users")

    def test_allowed_paths_enforced(self):
        ctrl = _make_controller(allowed_paths=("/api/",))
        ctrl.validate("GET", "https://example.test/api/users")

    def test_allowed_paths_blocks_other(self):
        ctrl = _make_controller(allowed_paths=("/api/",))
        with pytest.raises(ScopeViolation, match="not in allowed paths"):
            ctrl.validate("GET", "https://example.test/admin/panel")


# ── Method validation ──────────────────────────────────────────────


class TestMethodValidation:
    """Tests for destructive method blocking in safe mode."""

    def test_get_allowed_in_safe_mode(self):
        ctrl = _make_controller(safe_mode=True, destructive_tests=False)
        ctrl.validate("GET", "https://example.test/api/users")

    def test_post_allowed_in_safe_mode(self):
        ctrl = _make_controller(safe_mode=True, destructive_tests=False)
        ctrl.validate("POST", "https://example.test/api/users")

    def test_put_blocked_in_safe_mode(self):
        ctrl = _make_controller(safe_mode=True, destructive_tests=False)
        with pytest.raises(ScopeViolation, match="Destructive method"):
            ctrl.validate("PUT", "https://example.test/api/users/1")

    def test_delete_blocked_in_safe_mode(self):
        ctrl = _make_controller(safe_mode=True, destructive_tests=False)
        with pytest.raises(ScopeViolation, match="Destructive method"):
            ctrl.validate("DELETE", "https://example.test/api/users/1")

    def test_patch_blocked_in_safe_mode(self):
        ctrl = _make_controller(safe_mode=True, destructive_tests=False)
        with pytest.raises(ScopeViolation, match="Destructive method"):
            ctrl.validate("PATCH", "https://example.test/api/users/1")

    def test_destructive_allowed_when_enabled(self):
        ctrl = _make_controller(safe_mode=True, destructive_tests=True)
        ctrl.validate("PUT", "https://example.test/api/users/1")

    def test_destructive_allowed_when_safe_mode_off(self):
        ctrl = _make_controller(safe_mode=False)
        ctrl.validate("DELETE", "https://example.test/api/users/1")


# ── Internal network validation ────────────────────────────────────


class TestInternalNetworkValidation:
    """Tests for internal network blocking."""

    def test_private_ip_blocked(self):
        ctrl = _make_controller(
            allowed_hosts=frozenset({"10.0.0.1"}),
        )
        with pytest.raises(ScopeViolation, match="internal network"):
            ctrl.validate("GET", "http://10.0.0.1/api")

    def test_localhost_blocked(self):
        ctrl = _make_controller(
            allowed_hosts=frozenset({"127.0.0.1"}),
        )
        with pytest.raises(ScopeViolation, match="internal network"):
            ctrl.validate("GET", "http://127.0.0.1/api")

    def test_private_ip_allowed_when_enabled(self):
        ctrl = _make_controller(
            allowed_hosts=frozenset({"10.0.0.1"}),
            allow_internal_network=True,
        )
        ctrl.validate("GET", "http://10.0.0.1/api")

    def test_domain_name_not_blocked(self):
        """Domain names are not resolved — only literal IPs are checked."""
        ctrl = _make_controller()
        ctrl.validate("GET", "https://example.test/api")


# ── Redirect validation ───────────────────────────────────────────


class TestRedirectValidation:
    """Tests for redirect scope enforcement."""

    def test_in_scope_redirect(self):
        ctrl = _make_controller()
        ctrl.validate_redirect("https://example.test/other-page")

    def test_out_of_scope_redirect(self):
        ctrl = _make_controller()
        with pytest.raises(ScopeViolation, match="Host"):
            ctrl.validate_redirect("https://evil.com/phish")


# ── Request count limit ────────────────────────────────────────────


class TestRequestCountLimit:
    """Tests for max_requests enforcement."""

    def test_max_requests_enforced(self):
        ctrl = _make_controller(max_requests=3, requests_per_second=100.0)

        ctrl.validate("GET", "https://example.test/1")
        ctrl.validate("GET", "https://example.test/2")
        ctrl.validate("GET", "https://example.test/3")

        with pytest.raises(MaxRequestsExceeded):
            ctrl.validate("GET", "https://example.test/4")

    def test_request_count_tracks(self):
        ctrl = _make_controller(max_requests=10, requests_per_second=100.0)
        assert ctrl.request_count == 0

        ctrl.validate("GET", "https://example.test/1")
        assert ctrl.request_count == 1

        ctrl.validate("GET", "https://example.test/2")
        assert ctrl.request_count == 2


# ── Policy from config ─────────────────────────────────────────────


class TestPolicyFromConfig:
    """Tests for building ScopePolicy from ScanConfig."""

    def test_policy_from_config(self):
        config = ScanConfig(
            target=TargetConfig(url="https://example.test"),
            scope=ScopeConfig(
                allowed_hosts=["example.test"],
                allowed_ports=[443],
                excluded_paths=["/logout"],
            ),
            limits=LimitsConfig(max_requests=500, requests_per_second=10.0),
            safety=SafetyConfig(safe_mode=True),
        )

        policy = ScopePolicy.from_config(config)

        assert "example.test" in policy.allowed_hosts
        assert 443 in policy.allowed_ports
        assert "/logout" in policy.excluded_paths
        assert policy.max_requests == 500
        assert policy.requests_per_second == 10.0
        assert policy.safe_mode is True
