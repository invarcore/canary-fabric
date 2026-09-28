"""FastAPI-based streaming reverse proxy for LLM endpoints (OpenAI / Anthropic / LiteLLM)."""

import json

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse

from canary_fabric.breaker.circuit import BreakerAction, CircuitBreaker
from canary_fabric.proxy.streamer import StreamWatcher


def create_proxy_app(
    upstream_url: str = "https://api.openai.com",
    secret_key: str = "canary_default_secret_key",
    default_action: BreakerAction = BreakerAction.BLOCK_AND_SEVER,
) -> FastAPI:
    """Create a FastAPI application acting as a wire-level canary egress gateway."""
    app = FastAPI(
        title="CanaryFabric Reverse Proxy",
        description="Zero-trust streaming cryptographic tripwire proxy for LLM APIs.",
        version="0.1.0",
    )

    breaker = CircuitBreaker(secret_key=secret_key, default_action=default_action)

    @app.get("/health")
    async def health_check() -> dict[str, str]:
        return {"status": "ok", "service": "canary-fabric-proxy", "version": "0.1.0"}

    @app.post("/v1/chat/completions")
    async def chat_completions_proxy(request: Request) -> Response:
        body = await request.json()
        headers = dict(request.headers)
        headers.pop("host", None)
        headers.pop("content-length", None)

        is_stream = body.get("stream", False)
        tenant_id = headers.get("x-tenant-id", "default_tenant")

        client = httpx.AsyncClient(timeout=60.0)

        if not is_stream:
            try:
                resp = await client.post(
                    f"{upstream_url}/v1/chat/completions",
                    json=body,
                    headers=headers,
                )
                data = resp.json()
                # Scan full completion output
                choices = data.get("choices", [])
                for choice in choices:
                    content = choice.get("message", {}).get("content", "")
                    watcher = StreamWatcher(
                        circuit_breaker=breaker,
                        tenant_id=tenant_id,
                    )
                    safe_content, tripped, _ = watcher.scan_chunk(content)
                    if tripped:
                        choice["message"]["content"] = safe_content
                return JSONResponse(content=data, status_code=resp.status_code)
            finally:
                await client.aclose()

        # Streaming SSE Mode
        async def stream_generator():
            watcher = StreamWatcher(
                circuit_breaker=breaker,
                tenant_id=tenant_id,
            )
            try:
                async with client.stream(
                    "POST",
                    f"{upstream_url}/v1/chat/completions",
                    json=body,
                    headers=headers,
                ) as resp:
                    async for raw_line in resp.aiter_lines():
                        if not raw_line:
                            continue
                        if raw_line.startswith("data: ") and raw_line != "data: [DONE]":
                            json_str = raw_line[6:]
                            try:
                                chunk_json = json.loads(json_str)
                                delta_content = (
                                    chunk_json.get("choices", [{}])[0]
                                    .get("delta", {})
                                    .get("content", "")
                                )
                                safe_chunk, tripped, _ = watcher.scan_chunk(
                                    delta_content
                                )
                                if tripped:
                                    chunk_json["choices"][0]["delta"]["content"] = (
                                        safe_chunk
                                    )
                                    yield f"data: {json.dumps(chunk_json)}\n\n"
                                    yield "data: [DONE]\n\n"
                                    break
                                else:
                                    yield f"{raw_line}\n\n"
                            except json.JSONDecodeError:
                                yield f"{raw_line}\n\n"
                        else:
                            yield f"{raw_line}\n\n"
            finally:
                await client.aclose()

        return StreamingResponse(stream_generator(), media_type="text/event-stream")

    return app
