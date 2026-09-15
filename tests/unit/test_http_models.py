"""Unit tests for AEGIS Agent 1 — HTTP models."""

import pytest

from agent1.http.models import (
    DESTRUCTIVE_METHODS,
    HttpMethod,
    HttpRequest,
    HttpResponse,
    RequestResponse,
)


class TestHttpRequest:
    """Tests for HttpRequest model."""

    def test_create_get_request(self):
        req = HttpRequest(method=HttpMethod.GET, url="https://example.test/api")
        assert req.method == HttpMethod.GET
        assert req.url == "https://example.test/api"
        assert req.headers == {}
        assert req.cookies == {}
        assert req.body is None
        assert req.auth_context is None
        assert req.timestamp is not None

    def test_create_post_with_body(self):
        req = HttpRequest(
            method=HttpMethod.POST,
            url="https://example.test/api/users",
            headers={"Content-Type": "application/json"},
            body='{"name": "test"}',
            auth_context="USER_A",
        )
        assert req.method == HttpMethod.POST
        assert req.body == '{"name": "test"}'
        assert req.auth_context == "USER_A"

    def test_serialization(self):
        req = HttpRequest(method=HttpMethod.GET, url="https://example.test/")
        data = req.model_dump(mode="json")
        assert data["method"] == "GET"
        assert data["url"] == "https://example.test/"


class TestHttpResponse:
    """Tests for HttpResponse model."""

    def test_create_response(self):
        resp = HttpResponse(
            status_code=200,
            headers={"Content-Type": "text/html"},
            body="<html></html>",
            response_time_ms=42.5,
        )
        assert resp.status_code == 200
        assert resp.size == 0  # Explicit size not provided
        assert resp.response_time_ms == 42.5

    def test_body_hash_computation(self):
        body = "Hello, World!"
        hash1 = HttpResponse.compute_body_hash(body)
        hash2 = HttpResponse.compute_body_hash(body)
        assert hash1 == hash2  # Deterministic
        assert len(hash1) == 64  # SHA-256 hex

    def test_different_bodies_different_hashes(self):
        hash1 = HttpResponse.compute_body_hash("body1")
        hash2 = HttpResponse.compute_body_hash("body2")
        assert hash1 != hash2


class TestRequestResponse:
    """Tests for RequestResponse pairing."""

    def test_pair_creation(self):
        req = HttpRequest(method=HttpMethod.GET, url="https://example.test/")
        resp = HttpResponse(status_code=200, body="OK")
        pair = RequestResponse(request=req, response=resp)

        assert pair.request.method == HttpMethod.GET
        assert pair.response.status_code == 200


class TestDestructiveMethods:
    """Tests for destructive method classification."""

    def test_put_is_destructive(self):
        assert HttpMethod.PUT in DESTRUCTIVE_METHODS

    def test_delete_is_destructive(self):
        assert HttpMethod.DELETE in DESTRUCTIVE_METHODS

    def test_patch_is_destructive(self):
        assert HttpMethod.PATCH in DESTRUCTIVE_METHODS

    def test_get_is_not_destructive(self):
        assert HttpMethod.GET not in DESTRUCTIVE_METHODS

    def test_post_is_not_destructive(self):
        assert HttpMethod.POST not in DESTRUCTIVE_METHODS
