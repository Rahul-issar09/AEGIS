"""AEGIS Agent 1 — SSRF Canary and Callback System.

Implements controlled callback recording and token correlation per PRD
Sections 3.3, 10, 21, and 22:
- Unique canary token per test: scan_id + random_token
- Thread-safe callback recorder
- Embedded lightweight HTTP canary callback server
- Canary URL generation
"""

from __future__ import annotations

import logging
import socket
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger("aegis.tests.canary")


@dataclass
class CanaryHit:
    """Represents a recorded callback from a target server to the canary."""

    token: str
    client_ip: str
    method: str
    path: str
    headers: dict[str, str] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    raw_query: str = ""


class CanaryRecorder:
    """Thread-safe in-memory store for canary callback tokens."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._hits: list[CanaryHit] = []
        self._token_hits: dict[str, list[CanaryHit]] = {}

    def record_hit(
        self,
        token: str,
        client_ip: str,
        method: str = "GET",
        path: str = "",
        headers: dict[str, str] | None = None,
        raw_query: str = "",
    ) -> CanaryHit:
        """Record a callback hit for a token."""
        hit = CanaryHit(
            token=token,
            client_ip=client_ip,
            method=method,
            path=path,
            headers=headers or {},
            raw_query=raw_query,
        )
        with self._lock:
            self._hits.append(hit)
            if token not in self._token_hits:
                self._token_hits[token] = []
            self._token_hits[token].append(hit)

        logger.info(
            "canary.callback_recorded",
            extra={"token": token, "client_ip": client_ip, "path": path},
        )
        return hit

    def has_hit(self, token: str) -> bool:
        """Check if any callback was received for the given token."""
        with self._lock:
            return token in self._token_hits and len(self._token_hits[token]) > 0

    def get_hits(self, token: str) -> list[CanaryHit]:
        """Get all hits recorded for a specific token."""
        with self._lock:
            return list(self._token_hits.get(token, []))

    def clear(self) -> None:
        """Clear all recorded hits."""
        with self._lock:
            self._hits.clear()
            self._token_hits.clear()


def generate_canary_token(scan_id: str) -> str:
    """Generate a unique per-test token (PRD Section 21: scan_id + random_token)."""
    random_part = uuid.uuid4().hex[:12]
    # Clean scan_id to keep token URL-safe
    clean_scan = scan_id.replace("-", "_").lower()
    return f"{clean_scan}_{random_part}"


class _CanaryHTTPHandler(BaseHTTPRequestHandler):
    """Internal HTTP handler for embedded canary server."""

    def log_message(self, format: str, *args: object) -> None:
        # Suppress noisy standard server logging
        logger.debug(f"Canary server: {format % args}")

    def do_GET(self) -> None:
        self._handle_callback("GET")

    def do_POST(self) -> None:
        self._handle_callback("POST")

    def do_HEAD(self) -> None:
        self._handle_callback("HEAD")

    def _handle_callback(self, method: str) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.strip("/")
        # Expected path format: /canary/<token> or /<token>
        parts = path.split("/")
        token = ""
        if len(parts) >= 2 and parts[0] == "canary":
            token = parts[1]
        elif len(parts) == 1 and parts[0]:
            token = parts[0]

        client_ip = self.client_address[0]
        headers_dict = {k: v for k, v in self.headers.items()}

        recorder: CanaryRecorder | None = getattr(self.server, "recorder", None)
        if recorder and token:
            recorder.record_hit(
                token=token,
                client_ip=client_ip,
                method=method,
                path=self.path,
                headers=headers_dict,
                raw_query=parsed.query,
            )

        # Respond with harmless 200 OK
        body = b'{"status": "ok", "service": "aegis-canary"}\n'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if method != "HEAD":
            self.wfile.write(body)


def _find_free_port() -> int:
    """Find an available port on localhost."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class EmbeddedCanaryServer:
    """Lightweight background HTTP server for receiving SSRF callbacks."""

    def __init__(
        self,
        recorder: CanaryRecorder,
        host: str = "127.0.0.1",
        port: int | None = None,
    ) -> None:
        self.recorder = recorder
        self.host = host
        self.port = port or _find_free_port()
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._running = False

    def start(self) -> None:
        """Start the canary server in a daemon background thread."""
        if self._running:
            return

        self._server = HTTPServer((self.host, self.port), _CanaryHTTPHandler)
        setattr(self._server, "recorder", self.recorder)

        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="aegis-canary-server",
            daemon=True,
        )
        self._thread.start()
        self._running = True
        logger.info(
            "canary.server_started",
            extra={"host": self.host, "port": self.port},
        )

    def stop(self) -> None:
        """Shut down the canary server."""
        if not self._running or not self._server:
            return

        self._server.shutdown()
        self._server.server_close()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        self._running = False
        logger.info("canary.server_stopped")

    @property
    def base_url(self) -> str:
        """Get the base URL for constructing canary targets."""
        return f"http://{self.host}:{self.port}"

    def build_canary_url(self, token: str) -> str:
        """Construct a full canary URL for the given token."""
        return f"{self.base_url}/canary/{token}"
