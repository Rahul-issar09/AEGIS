"""AEGIS Local Vulnerable Target Server (Standard Library HTTP).

Provides a realistic API testbed for validating AEGIS Agent 1:
- Serves OpenAPI 3.0 specification at /openapi.json
- Serves HTML application pages at / and /dashboard
- Endpoints:
    * GET /api/v1/users/{id}/profile (VULNERABLE to BOLA - User B can read User A's profile)
    * GET /api/v1/orders/{id} (SECURE - User B receives 403 Forbidden for User A's order)
    * GET /api/v1/products/{id} (PUBLIC - Unauthenticated access allowed, tests FP suppression)
    * GET /api/v1/documents/{id} (VULNERABLE to BOLA)
    * GET /api/v1/health (Public healthcheck)
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("testbed")

OPENAPI_SPEC = {
    "openapi": "3.0.0",
    "info": {
        "title": "AEGIS Vulnerable Benchmark API",
        "version": "1.0.0",
        "description": "Mock API designed for testing authorization security agents (BOLA/IDOR).",
    },
    "paths": {
        "/api/v1/users/{id}/profile": {
            "get": {
                "summary": "Get user profile",
                "description": "Returns user profile details. Vulnerable to BOLA.",
                "parameters": [
                    {
                        "name": "id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {
                    "200": {"description": "User profile details"},
                    "401": {"description": "Unauthorized"},
                },
            }
        },
        "/api/v1/orders/{id}": {
            "get": {
                "summary": "Get order details",
                "description": "Returns customer order details. Properly checks authorization (Secure).",
                "parameters": [
                    {
                        "name": "id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {
                    "200": {"description": "Order details"},
                    "403": {"description": "Forbidden"},
                },
            }
        },
        "/api/v1/documents/{id}": {
            "get": {
                "summary": "Get confidential document",
                "description": "Returns confidential document. Vulnerable to cross-tenant BOLA.",
                "parameters": [
                    {
                        "name": "id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {
                    "200": {"description": "Document content"},
                    "401": {"description": "Unauthorized"},
                },
            }
        },
        "/api/v1/products/{id}": {
            "get": {
                "summary": "Get product information",
                "description": "Public catalog item. Tests false-positive suppression.",
                "parameters": [
                    {
                        "name": "id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {
                    "200": {"description": "Product details"},
                },
            }
        },
        "/api/v1/webhook/test": {
            "get": {
                "summary": "Trigger test webhook",
                "description": "Sends a webhook notification to destination URL. Vulnerable to SSRF.",
                "parameters": [
                    {
                        "name": "url",
                        "in": "query",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {
                    "200": {"description": "Webhook dispatched"},
                },
            }
        },
        "/api/v1/health": {
            "get": {
                "summary": "Health check",
                "responses": {"200": {"description": "API is healthy"}},
            }
        },
    },
}

HTML_HOME = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>AEGIS Vulnerable Benchmark Portal</title>
</head>
<body>
    <h1>Benchmark Testbed</h1>
    <p>Welcome to the API Security Benchmark application.</p>
    <nav>
        <a href="/openapi.json">OpenAPI Specification</a>
        <a href="/api/v1/health">Health Check</a>
        <a href="/api/v1/products/101">Public Product 101</a>
        <a href="/api/v1/users/101/profile">User Profile 101</a>
        <a href="/api/v1/orders/101">Order 101</a>
        <a href="/api/v1/webhook/test?url=http://example.test">Webhook Test</a>
    </nav>
</body>
</html>
"""



class BenchmarkRequestHandler(BaseHTTPRequestHandler):
    """Request handler implementing vulnerable and secure authorization endpoints."""

    def log_message(self, format: str, *args: object) -> None:
        logger.info("%s - - [%s] %s", self.client_address[0], self.log_date_time_string(), format % args)

    def _get_bearer_token(self) -> str | None:
        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            return auth_header[7:].strip()
        # Also check cookie session if present
        cookie_header = self.headers.get("Cookie", "")
        for part in cookie_header.split(";"):
            if "session=" in part:
                return part.split("session=", 1)[1].strip()
        return None

    def _send_json(self, status: int, data: dict | list) -> None:
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, status: int, html: str) -> None:
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        if not path:
            path = "/"

        # 1. Landing Page
        if path == "/":
            self._send_html(200, HTML_HOME)
            return

        # 2. OpenAPI Specification
        if path in ("/openapi.json", "/swagger.json"):
            self._send_json(200, OPENAPI_SPEC)
            return

        # 3. Health Check
        if path == "/api/v1/health":
            self._send_json(200, {"status": "ok", "service": "benchmark-api"})
            return

        token = self._get_bearer_token()

        # 4. Public Product (False Positive Test)
        if path.startswith("/api/v1/products/"):
            product_id = path.split("/")[-1]
            self._send_json(200, {
                "product_id": product_id,
                "name": f"Enterprise Widget #{product_id}",
                "price": 299.99,
                "public": True,
            })
            return

        # 5. VULNERABLE: User Profile (/api/v1/users/{id}/profile)
        if path.startswith("/api/v1/users/") and path.endswith("/profile"):
            parts = path.split("/")
            user_id = parts[4]  # /api/v1/users/{id}/profile

            if not token:
                self._send_json(401, {"error": "Authentication required"})
                return

            # Vulnerability: Accepts token_user_b to view User A's (101) profile!
            if user_id == "101":
                self._send_json(200, {
                    "user_id": "101",
                    "name": "Alice Wonderland",
                    "email": "alice@example.com",
                    "secret_api_key": "sec_live_998877665544332211",
                    "phone": "+1-555-0199",
                    "account_type": "enterprise_owner",
                })
                return
            else:
                self._send_json(200, {
                    "user_id": user_id,
                    "name": f"User {user_id}",
                    "email": f"user{user_id}@example.com",
                })
                return

        # 6. VULNERABLE: Documents (/api/v1/documents/{id})
        if path.startswith("/api/v1/documents/"):
            doc_id = path.split("/")[-1]
            if not token:
                self._send_json(401, {"error": "Authentication required"})
                return

            # Vulnerability: Any authenticated user can read document 101
            self._send_json(200, {
                "document_id": doc_id,
                "title": f"Confidential Report #{doc_id}",
                "owner_id": "101",
                "classification": "RESTRICTED",
                "content": "Confidential financial projections for Q4.",
            })
            return

        # 7. SECURE: Orders (/api/v1/orders/{id})
        if path.startswith("/api/v1/orders/"):
            order_id = path.split("/")[-1]
            if not token:
                self._send_json(401, {"error": "Authentication required"})
                return

            # Proper access control enforcement:
            # Only User A (token_user_a) can view order 101!
            if order_id == "101":
                if token == "token_user_a":
                    self._send_json(200, {
                        "order_id": "101",
                        "customer": "Alice",
                        "total": "$1,499.00",
                        "status": "shipped",
                    })
                    return
                else:
                    self._send_json(403, {
                        "error": "Forbidden: You do not have permission to access order 101."
                    })
                    return
            else:
                self._send_json(404, {"error": f"Order {order_id} not found."})
                return

        # 8. VULNERABLE SSRF: Webhook (/api/v1/webhook/test?url=...)
        if path == "/api/v1/webhook/test":
            query_params = parse_qs(parsed.query)
            target_webhook = query_params.get("url", [""])[0]
            if target_webhook:
                try:
                    import urllib.request
                    req = urllib.request.Request(
                        target_webhook,
                        headers={"User-Agent": "BenchmarkWebhook/1.0"},
                    )
                    with urllib.request.urlopen(req, timeout=2.0) as resp:
                        pass
                except Exception as e:
                    logger.debug(f"Webhook dispatch error: {e}")
            self._send_json(200, {"status": "dispatched", "url": target_webhook})
            return

        # Default 404
        self._send_json(404, {"error": "Endpoint not found"})



def run_server(port: int = 8000) -> None:
    server = HTTPServer(("127.0.0.1", port), BenchmarkRequestHandler)
    logger.info(f"Target benchmark server running at http://127.0.0.1:{port}")
    logger.info(f"OpenAPI spec available at http://127.0.0.1:{port}/openapi.json")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Server stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AEGIS Benchmark Vulnerable Server")
    parser.add_argument("--port", type=int, default=8000, help="Port to listen on (default: 8000)")
    args = parser.parse_args()
    run_server(args.port)
