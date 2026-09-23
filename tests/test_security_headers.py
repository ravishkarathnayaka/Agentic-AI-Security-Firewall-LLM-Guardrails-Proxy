"""Tests for HTTP Security Headers and Anti-Caching Middleware."""

import pytest
import httpx
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route

from proxy.main import app as proxy_app
from proxy.middleware.security_headers import SecurityHeadersMiddleware


@pytest.fixture
async def client():
    transport = httpx.ASGITransport(app=proxy_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testproxy") as ac:
        yield ac


@pytest.mark.asyncio
async def test_security_headers_present_on_health(client):
    """Test that standard API endpoints return strict zero-trust security headers."""
    resp = await client.get("/health")
    assert resp.status_code == 200

    headers = resp.headers
    assert headers.get("x-content-type-options") == "nosniff"
    assert headers.get("x-frame-options") == "DENY"
    assert headers.get("x-xss-protection") == "1; mode=block"
    assert headers.get("referrer-policy") == "strict-origin-when-cross-origin"
    assert "default-src 'none'" in headers.get("content-security-policy", "")
    assert "max-age=" in headers.get("strict-transport-security", "")
    assert headers.get("pragma") == "no-cache"
    assert headers.get("expires") == "0"


@pytest.mark.asyncio
async def test_no_store_cache_control_header(client):
    """Verify that proxy responses strictly forbid intermediary caching."""
    resp = await client.get("/health")
    cache_control = resp.headers.get("cache-control", "")
    assert "no-store" in cache_control
    assert "no-cache" in cache_control
    assert "must-revalidate" in cache_control


@pytest.mark.asyncio
async def test_custom_security_headers_middleware():
    """Verify customizable headers in standalone Starlette app."""
    async def homepage(request):
        res = PlainTextResponse("OK")
        res.headers["server"] = "VulnerableServer/1.0"
        return res

    app = Starlette(routes=[Route("/", homepage)])
    app.add_middleware(
        SecurityHeadersMiddleware,
        custom_headers={"X-Custom-Defense": "active-shield-v1"}
    )

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/")
        assert resp.status_code == 200
        assert resp.headers.get("x-custom-defense") == "active-shield-v1"
        assert resp.headers.get("x-frame-options") == "DENY"
        assert "server" not in resp.headers
