"""Tests for FastAPI proxy server with health checks, content scanning, and tool calls."""

import pytest
from httpx import ASGITransport, AsyncClient

from canary_fabric.proxy.server import create_proxy_app


@pytest.mark.asyncio
async def test_proxy_health():
    app = create_proxy_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["service"] == "canary-fabric-proxy"


@pytest.mark.asyncio
async def test_proxy_rejects_untrusted_upstream():
    app = create_proxy_app(upstream_url="https://api.openai.com", allowed_upstreams=["https://api.openai.com"])
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Caller tries to target an unauthorized internal metadata endpoint
        resp = await client.post(
            "/v1/chat/completions",
            json={"messages": [{"role": "user", "content": "hi"}]},
            headers={"x-upstream-url": "http://169.254.169.254/latest/meta-data"},
        )
        assert resp.status_code == 403
        data = resp.json()
        assert "Forbidden" in data["error"]