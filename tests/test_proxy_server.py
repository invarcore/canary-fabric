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