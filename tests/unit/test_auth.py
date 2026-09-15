"""Unit tests for AEGIS Agent 1 — Authentication contexts (Phase 4).

Tests:
- AuthContext model and headers management
- Token & credential redaction
- Anonymous context creation
- Loading contexts from YAML configuration
"""

import tempfile
from pathlib import Path

import pytest
import yaml

from agent1.auth.context import (
    AuthContext,
    create_anonymous_context,
    load_auth_contexts,
)


class TestAuthContext:
    """Tests for AuthContext model."""

    def test_create_auth_context(self):
        ctx = AuthContext(
            id="USER_A",
            name="Alice",
            role="user",
            cookies={"session": "sess_alice_123"},
            headers={"X-User": "alice"},
            token="token_alice",
            owned_objects=["101", "102"],
        )
        assert ctx.id == "USER_A"
        assert ctx.name == "Alice"
        assert ctx.role == "user"
        assert ctx.owned_objects == ["101", "102"]

    def test_get_effective_headers_injects_bearer_token(self):
        ctx = AuthContext(
            id="USER_A",
            name="Alice",
            token="secret_token",
            headers={"X-Custom": "val"},
        )
        headers = ctx.get_effective_headers()
        assert headers["Authorization"] == "Bearer secret_token"
        assert headers["X-Custom"] == "val"

    def test_get_effective_headers_preserves_explicit_auth_header(self):
        ctx = AuthContext(
            id="USER_A",
            name="Alice",
            token="secret_token",
            headers={"Authorization": "ApiKey my_custom_key"},
        )
        headers = ctx.get_effective_headers()
        assert headers["Authorization"] == "ApiKey my_custom_key"

    def test_redacted_context(self):
        ctx = AuthContext(
            id="USER_A",
            name="Alice",
            token="super_secret_token",
            cookies={"session": "secret_cookie"},
            headers={"Authorization": "Bearer super_secret_token"},
            owned_objects=["101"],
        )
        redacted = ctx.redacted()
        assert redacted["token"] == "[REDACTED]"
        assert redacted["cookies"]["session"] == "[REDACTED]"
        assert redacted["headers"]["Authorization"] == "[REDACTED]"
        assert redacted["owned_objects"] == ["101"]

    def test_create_anonymous_context(self):
        anon = create_anonymous_context()
        assert anon.id == "ANONYMOUS"
        assert anon.role == "anonymous"
        assert anon.token is None
        assert anon.cookies == {}
        assert anon.headers == {}


class TestLoadAuthContexts:
    """Tests for YAML auth configuration loading."""

    def test_load_valid_yaml(self):
        yaml_content = """
contexts:
  USER_A:
    name: "User A"
    token: "token_a"
    owned_objects: [101, 102]
  USER_B:
    name: "User B"
    token: "token_b"
    owned_objects: ["201"]
  ADMIN:
    name: "Admin"
    role: "admin"
    headers:
      X-Admin-Key: "secret_admin"
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            temp_path = f.name

        try:
            contexts = load_auth_contexts(temp_path)
            assert "ANONYMOUS" in contexts
            assert "USER_A" in contexts
            assert "USER_B" in contexts
            assert "ADMIN" in contexts

            assert contexts["USER_A"].owned_objects == ["101", "102"]
            assert contexts["USER_B"].owned_objects == ["201"]
            assert contexts["ADMIN"].role == "admin"
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_load_none_returns_anonymous(self):
        contexts = load_auth_contexts(None)
        assert len(contexts) == 1
        assert "ANONYMOUS" in contexts

    def test_load_missing_file_returns_anonymous(self):
        contexts = load_auth_contexts("non_existent_file_xyz.yaml")
        assert len(contexts) == 1
        assert "ANONYMOUS" in contexts

    def test_load_string_owned_objects_treated_as_single_item(self):
        """F-10 Regression: String owned_objects is wrapped as single item list."""
        yaml_content = """
contexts:
  USER_A:
    name: "User A"
    token: "token_a"
    owned_objects: "101"
"""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write(yaml_content)
            temp_path = f.name

        try:
            contexts = load_auth_contexts(temp_path)
            assert contexts["USER_A"].owned_objects == ["101"]
        finally:
            Path(temp_path).unlink(missing_ok=True)
