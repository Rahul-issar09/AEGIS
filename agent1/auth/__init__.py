"""AEGIS Agent 1 — Authentication package.

Provides multi-identity management and authentication context models
per PRD Section 14.
"""

from agent1.auth.context import (
    AuthContext,
    create_anonymous_context,
    load_auth_contexts,
)

__all__ = [
    "AuthContext",
    "create_anonymous_context",
    "load_auth_contexts",
]
