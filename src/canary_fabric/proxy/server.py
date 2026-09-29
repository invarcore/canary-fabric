"""FastAPI-based streaming reverse proxy for LLM endpoints (OpenAI / Anthropic / LiteLLM)."""

import json
import os
from contextlib import asynccontextmanager

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

    # Reusable HTTP client pool across lifespan
    http_client: httpx.AsyncClient | None = None

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        nonlocal http_client
        http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(connect=10.0, read=60.0, write=10.0, pool=60.0),
            limits=httpx.Limits(max_keepalive_connections=50, max_connections=200),
        )
        yield
        if http_client:
            await http_client.aclose()

    app = FastAPI(
        title="Canary Fabric Reverse Proxy",
        description="Zero-trust streaming cryptographic tripwire proxy for LLM APIs.",
        version="0.1.0",
        lifespan=lifespan,
    )

    breaker = CircuitBreaker(secret_key=secret_key, default_action=default_action)

    def resolve_upstream(request: Request) -> str:
        """Resolve upstream endpoint: header override -> env var -> default."""
        return (
            request.headers.get("x-upstream-url")
            or os.environ.get("CANARY_UPSTREAM_URL")
            or upstream_url
        ).rstrip("/")

    @app.get("/health")
    async def health_check() -> dict[str, str]:
        return {"status": "ok", "service": "canary-fabric-proxy", "version": "0.1.0"}

    @app.post("/v1/chat/completions")
    async def chat_completions_proxy(request: Request) -> Response:
        body = await request.json()
        headers = dict(request.headers)
        headers.pop("host", None)
        headers.pop("content-length", None)

        target_upstream = resolve_upstream(request)
        is_stream = body.get("stream", False)
        tenant_id = headers.get("x-tenant-id", "default_tenant")

        client = http_client or httpx.AsyncClient(timeout=60.0)

        # -------------------------------------------------------------
        # Non-Streaming Mode
        # -------------------------------------------------------------
        if not is_stream:
            resp = await client.post(
                f"{target_upstream}/v1/chat/completions",
                json=body,
                headers=headers,
            )
            data = resp.json()
            choices = data.get("choices", [])
            for choice in choices:
                message = choice.get("message", {})
                watcher = StreamWatcher(circuit_breaker=breaker, tenant_id=tenant_id)

                # 1. Scan conversational content
                content = message.get("content", "") or ""
                if content:
                    safe_content, tripped, _ = watcher.scan_chunk(content)
                    if tripped:
                        message["content"] = safe_content

                # 2. Scan tool calls arguments
                tool_calls = message.get("tool_calls", [])
                for tc in tool_calls:
                    tc_args = tc.get("function", {}).get("arguments", "")
                    if tc_args:
                        _, tc_tripped, _ = watcher.scan_chunk(tc_args)
                        if tc_tripped:
                            tc["function"]["arguments"] = '{"error": "[BLOCKED_BY_CANARY_FABRIC]"}'

            return JSONResponse(content=data, status_code=resp.status_code)

        # -------------------------------------------------------------
        # Streaming SSE Mode with Tool Call Argument Inspection
        # -------------------------------------------------------------
        async def stream_generator():
            watcher = StreamWatcher(circuit_breaker=breaker, tenant_id=tenant_id)
            async with client.stream(
                "POST",
                f"{target_upstream}/v1/chat/completions",
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
                            choice_list = chunk_json.get("choices", [])
                            if not choice_list:
                                yield f"{raw_line}\n\n"
                                continue

                            delta = choice_list[0].get("delta", {})

                            # A. Scan Content Tokens
                            delta_content = delta.get("content", "")
                            if delta_content:
                                safe_chunk, tripped, _ = watcher.scan_chunk(delta_content)
                                if tripped:
                                    choice_list[0]["delta"]["content"] = safe_chunk
                                    yield f"data: {json.dumps(chunk_json)}\n\n"
                                    yield "data: [DONE]\n\n"
                                    break

                            # B. Scan Streaming Tool Call Arguments
                            tool_calls = delta.get("tool_calls", [])
                            if tool_calls:
                                safe_tc, tc_tripped, _ = watcher.scan_tool_call_delta(tool_calls[0])
                                if tc_tripped:
                                    choice_list[0]["delta"]["tool_calls"] = [safe_tc]
                                    yield f"data: {json.dumps(chunk_json)}\n\n"
                                    yield "data: [DONE]\n\n"
                                    break

                            yield f"{raw_line}\n\n"
                        except json.JSONDecodeError:
                            yield f"{raw_line}\n\n"
                    else:
                        yield f"{raw_line}\n\n"

        return StreamingResponse(stream_generator(), media_type="text/event-stream")

    return app