"""Comprehensive tests for FastAPI proxy server covering streaming, non-streaming, tool calls, and edge cases."""

import json

import httpx
import pytest
from httpx import ASGITransport, AsyncClient, MockTransport

from canary_fabric.breaker.circuit import BreakerAction
from canary_fabric.core.crypto import derive_canary_token
from canary_fabric.core.watermark import WatermarkEncoder
from canary_fabric.proxy.server import create_proxy_app


@pytest.mark.asyncio
async def test_proxy_non_streaming_clean_passthrough():
    upstream_response_data = {
        "id": "chatcmpl-123",
        "object": "chat.completion",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "Hello! How can I help you today?"},
                "finish_reason": "stop",
            }
        ],
    }

    def mock_handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/chat/completions"
        return httpx.Response(200, json=upstream_response_data)

    mock_client = AsyncClient(transport=MockTransport(mock_handler))
    app = create_proxy_app(upstream_url="https://api.openai.com", http_client=mock_client)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/v1/chat/completions",
            json={"messages": [{"role": "user", "content": "Hello"}]},
            headers={"x-tenant-id": "tenant_1"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["choices"][0]["message"]["content"] == "Hello! How can I help you today?"


@pytest.mark.asyncio
async def test_proxy_non_streaming_watermarked_content_blocked():
    token = derive_canary_token("secret", "tenant_corp", "doc_confidential", "chunk_1")
    leaked_content = WatermarkEncoder.inject_watermark("Confidential acquisition price is $500M.", token)

    upstream_response_data = {
        "id": "chatcmpl-124",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": leaked_content},
            }
        ],
    }

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=upstream_response_data)

    mock_client = AsyncClient(transport=MockTransport(mock_handler))
    app = create_proxy_app(
        upstream_url="https://api.openai.com",
        secret_key="secret",
        active_canary_tokens={token},
        default_action=BreakerAction.BLOCK_AND_SEVER,
        http_client=mock_client,
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/v1/chat/completions",
            json={"messages": [{"role": "user", "content": "Tell me secrets"}]},
            headers={"x-tenant-id": "tenant_corp"},
        )
        assert resp.status_code == 200
        data = resp.json()
        content = data["choices"][0]["message"]["content"]
        assert "SECURITY ALERT: CanaryFabric Circuit Breaker Tripped" in content


@pytest.mark.asyncio
async def test_proxy_non_streaming_tool_call_blocked():
    token = derive_canary_token("secret", "tenant_corp", "doc_db", "chunk_0")
    leaked_args = json.dumps({"query": WatermarkEncoder.inject_watermark("SELECT * FROM secret_table", token)}, ensure_ascii=False)

    upstream_response_data = {
        "id": "chatcmpl-125",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {"name": "run_sql", "arguments": leaked_args},
                        }
                    ],
                },
            }
        ],
    }

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=upstream_response_data)

    mock_client = AsyncClient(transport=MockTransport(mock_handler))
    app = create_proxy_app(
        upstream_url="https://api.openai.com",
        secret_key="secret",
        active_canary_tokens={token},
        http_client=mock_client,
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/v1/chat/completions",
            json={"messages": [{"role": "user", "content": "Execute query"}]},
            headers={"x-tenant-id": "tenant_corp"},
        )
        assert resp.status_code == 200
        data = resp.json()
        tc = data["choices"][0]["message"]["tool_calls"][0]
        assert "[BLOCKED_BY_CANARY_FABRIC]" in tc["function"]["arguments"]


@pytest.mark.asyncio
async def test_proxy_streaming_clean_with_flush():
    chunks = [
        ': ping\n\n',
        'data: {"choices": []}\n\n',
        'data: {"id": "c1", "choices": [{"index": 0, "delta": {"content": "First token "}}]}\n\n',
        'data: {"id": "c2", "choices": [{"index": 0, "delta": {"content": "second token."}}]}\n\n',
        'data: invalid-json-line\n\n',
        'data: [DONE]\n\n',
    ]

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content="".join(chunks).encode("utf-8"), headers={"content-type": "text/event-stream"})

    mock_client = AsyncClient(transport=MockTransport(mock_handler))
    app = create_proxy_app(
        upstream_url="https://api.openai.com",
        stream_holdback_chars=16,
        http_client=mock_client,
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/v1/chat/completions",
            json={"messages": [{"role": "user", "content": "Stream me"}], "stream": True},
        )
        assert resp.status_code == 200
        body = resp.text
        assert "data: [DONE]" in body
        assert "chat.completion.chunk" in body


@pytest.mark.asyncio
async def test_proxy_streaming_watermark_trip():
    token = derive_canary_token("secret", "tenant_corp", "secret_project", "chunk_0")
    wm_chunk = WatermarkEncoder.inject_watermark("TopSecretM&A", token)

    chunks = [
        'data: {"id": "c1", "choices": [{"index": 0, "delta": {"content": "Here is the data: "}}]}\n\n',
        f'data: {{"id": "c2", "choices": [{{"index": 0, "delta": {{"content": "{wm_chunk}"}}}}]}}\n\n',
        'data: {"id": "c3", "choices": [{"index": 0, "delta": {"content": " trailing content"}}]}\n\n',
        'data: [DONE]\n\n',
    ]

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content="".join(chunks).encode("utf-8"), headers={"content-type": "text/event-stream"})

    mock_client = AsyncClient(transport=MockTransport(mock_handler))
    app = create_proxy_app(
        upstream_url="https://api.openai.com",
        secret_key="secret",
        active_canary_tokens={token},
        stream_holdback_chars=0,
        http_client=mock_client,
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/v1/chat/completions",
            json={"messages": [{"role": "user", "content": "Leak secrets"}], "stream": True},
            headers={"x-tenant-id": "tenant_corp"},
        )
        assert resp.status_code == 200
        body = resp.text
        assert "data: [DONE]" in body
        assert "SECURITY ALERT: CanaryFabric Circuit Breaker Tripped" in body


@pytest.mark.asyncio
async def test_proxy_streaming_tool_call_trip():
    token = derive_canary_token("secret", "tenant_corp", "tool_target", "chunk_0")
    wm_args = WatermarkEncoder.inject_watermark("leaked_api_token", token)

    chunks = [
        f'data: {{"id": "c1", "choices": [{{"index": 0, "delta": {{"tool_calls": [{{"id": "call_99", "type": "function", "function": {{"name": "fetch", "arguments": "{wm_args}"}}}}]}}}}]}}\n\n',
        'data: [DONE]\n\n',
    ]

    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content="".join(chunks).encode("utf-8"), headers={"content-type": "text/event-stream"})

    mock_client = AsyncClient(transport=MockTransport(mock_handler))
    app = create_proxy_app(
        upstream_url="https://api.openai.com",
        secret_key="secret",
        active_canary_tokens={token},
        http_client=mock_client,
    )

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/v1/chat/completions",
            json={"messages": [{"role": "user", "content": "Call tool"}], "stream": True},
            headers={"x-tenant-id": "tenant_corp"},
        )
        assert resp.status_code == 200
        body = resp.text
        assert "CANARY_FABRIC_TRIPWIRE_TRIGGERED" in body


@pytest.mark.asyncio
async def test_proxy_env_upstream_resolution(monkeypatch):
    monkeypatch.setenv("CANARY_UPSTREAM_URL", "https://api.groq.com/openai")
    monkeypatch.setenv("CANARY_ALLOWED_UPSTREAMS", "https://api.groq.com/openai")

    def mock_handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url).startswith("https://api.groq.com/openai")
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    mock_client = AsyncClient(transport=MockTransport(mock_handler))
    app = create_proxy_app(http_client=mock_client)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/v1/chat/completions",
            json={"messages": [{"role": "user", "content": "hi"}]},
        )
        assert resp.status_code == 200
