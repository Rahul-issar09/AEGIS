"""AEGIS Agent 1 — Authentication context management.

Models and manages multiple user identities per PRD Section 14:
Anonymous, User A, User B, Admin. Tokens and credentials must never
appear unredacted in reports.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from agent1.evidence.redactor import Redactor

logger = logging.getLogger("aegis.auth")


class AuthContext(BaseModel):
    """Represents an authenticated or unauthenticated identity (PRD Section 14).

    Fields:
        id: Unique identifier (e.g. 'USER_A', 'USER_B', 'ADMIN', 'ANONYMOUS')
        name: Descriptive label (e.g. 'User A (Owner)', 'User B (Attacker)')
        cookies: Cookie key-value pairs for this identity
        headers: Additional headers (e.g. Authorization: Bearer <token>)
        token: Optional raw authentication token
        role: Identity role ('user', 'admin', 'anonymous', etc.)
        owned_objects: List of object IDs known to belong to this identity
    """

    id: str = Field(..., description="Unique context identifier (e.g. USER_A)")
    name: str = Field(..., description="Human-readable name")
    cookies: dict[str, str] = Field(default_factory=dict, description="Session cookies")
    headers: dict[str, str] = Field(default_factory=dict, description="Authentication headers")
    token: str | None = Field(default=None, description="Raw token if applicable")
    role: str = Field(default="user", description="Identity role")
    owned_objects: list[str] = Field(
        default_factory=list,
        description="Object IDs belonging to this user for cross-testing",
    )

    def get_effective_headers(self) -> dict[str, str]:
        """Combine explicit headers with bearer token if present."""
        headers = dict(self.headers)
        if self.token and "authorization" not in {k.lower(): v for k, v in headers.items()}:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def redacted(self) -> dict[str, Any]:
        """Return a copy of the context with all sensitive credentials redacted."""
        return {
            "id": self.id,
            "name": self.name,
            "role": self.role,
            "owned_objects": self.owned_objects,
            "headers": Redactor.redact_headers(self.headers),
            "cookies": {k: "[REDACTED]" for k in self.cookies},
            "token": "[REDACTED]" if self.token else None,
        }


def create_anonymous_context() -> AuthContext:
    """Create a default unauthenticated identity."""
    return AuthContext(
        id="ANONYMOUS",
        name="Anonymous User",
        role="anonymous",
        cookies={},
        headers={},
        token=None,
        owned_objects=[],
    )


def load_auth_contexts(path: str | Path | None) -> dict[str, AuthContext]:
    """Load authentication contexts from a YAML/JSON configuration file.

    Always includes an ANONYMOUS context.

    Example YAML:
    contexts:
      USER_A:
        name: "User A"
        token: "token_user_a"
        owned_objects: ["101", "102"]
      USER_B:
        name: "User B"
        token: "token_user_b"
        owned_objects: ["201", "202"]
      ADMIN:
        name: "Administrator"
        headers:
          X-API-Key: "admin-secret-key"
        role: "admin"
    """
    contexts: dict[str, AuthContext] = {
        "ANONYMOUS": create_anonymous_context()
    }

    if not path:
        return contexts

    file_path = Path(path)
    if not file_path.exists():
        logger.warning(f"Auth config file not found: {path}")
        return contexts

    try:
        content = file_path.read_text(encoding="utf-8")
        data = yaml.safe_load(content) or {}
    except Exception as e:
        logger.error(f"Failed to parse auth config file {path}: {e}")
        return contexts

    raw_contexts = data.get("contexts", data) if isinstance(data, dict) else {}
    if not isinstance(raw_contexts, dict):
        return contexts

    for key, ctx_data in raw_contexts.items():
        if not isinstance(ctx_data, dict):
            continue

        ctx_id = ctx_data.get("id", key).upper()
        name = ctx_data.get("name", ctx_id)
        role = ctx_data.get("role", "user")
        cookies = ctx_data.get("cookies", {})
        headers = ctx_data.get("headers", {})
        token = ctx_data.get("token")
        owned = ctx_data.get("owned_objects", [])

        # Ensure owned_objects are strings
        owned_str = [str(o) for o in owned]

        contexts[ctx_id] = AuthContext(
            id=ctx_id,
            name=name,
            role=role,
            cookies=cookies if isinstance(cookies, dict) else {},
            headers=headers if isinstance(headers, dict) else {},
            token=token,
            owned_objects=owned_str,
        )

    logger.info(f"Loaded {len(contexts)} auth contexts: {list(contexts.keys())}")
    return contexts
