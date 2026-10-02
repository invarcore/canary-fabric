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
    secret_key: str | None = None,
    default_action: BreakerAction = BreakerAction.BLOCK_AND_SEVER,
    allowed_upstreams: list[str] | None = None,
    active_canary_tokens: set[str] | None = None,
    stream_holdback_chars: int = 32,
) -> FastAPI:
    """Create a FastAPI application acting as a wire-level canary egress gateway."""
    import secrets

    actual_secret = (
        secret_key
        or os.environ.get("CANARY_SECRET_KEY")
        or secrets.token_hex(32)
    )

    configured_upstreams: set[str] = set()
    if allowed_upstreams:
        configured_upstreams.update(u.rstrip("/") for u in allowed_upstreams)
    configured_upstreams.add(upstream_url.rstrip("/"))
    env_allowed = os.environ.get("CANARY_ALLOWED_UPSTREAMS")
    if env_allowed:
        configured_upstreams.update(u.strip().rstrip("/") for u in env_allowed.split(",") if u.strip())

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

    breaker = CircuitBreaker(secret_key=actual_secret, default_action=default_action)

    def resolve_upstream(request: Request) -> tuple[str | None, str | None]:
        """Resolve upstream endpoint ensuring caller cannot redirect to arbitrary SSRF targets."""
        req_upstream = request.headers.get("x-upstream-url")
        if req_upstream:
            cleaned = req_upstream.strip().rstrip("/")
            if cleaned not in configured_upstreams:
                return None, f"Upstream '{req_upstream}' is not in the permitted allowlist"
            return cleaned, None

        env_upstream = os.environ.get("CANARY_UPSTREAM_URL")
        if env_upstream:
            return env_upstream.rstrip("/"), None
        return upstream_url.rstrip("/"), None

    @app.get("/health")
    async def health_check() -> dict[str, str]:
        return {"status": "ok", "service": "canary-fabric-proxy", "version": "0.1.0"}

    @app.post("/v1/chat/completions")
    async def chat_completions_proxy(request: Request) -> Response:
        body = await request.json()
        headers = dict(request.headers)
        headers.pop("host", None)
        headers.pop("content-length", None)
        headers.pop("x-upstream-url", None)

        target_upstream, upstream_err = resolve_upstream(request)
        if upstream_err or not target_upstream:
            return JSONResponse(
                status_code=403,
                content={"error": "Forbidden: upstream validation failed", "detail": upstream_err},
            )

        # Do not blindly forward incoming caller Authorization credentials to upstream
        headers.pop("authorization", None)

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
                watcher = StreamWatcher(
                    circuit_breaker=breaker,
                    tenant_id=tenant_id,
                    active_canary_tokens=active_canary_tokens,
                )

                # 1. Scan conversational content
                content = message.get("content", "") or ""
                if content:
                    safe_content, tripped, _ = watcher.scan_chunk(content)
                    if tripped:
                        message["content"] = safe_content

                # 2. Scan all tool call arguments
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
            watcher = StreamWatcher(
                circuit_breaker=breaker,
                tenant_id=tenant_id,
                active_canary_tokens=active_canary_tokens,
                holdback_chars=stream_holdback_chars,
            )
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

                            tripped_any = False
                            for choice in choice_list:
                                delta = choice.get("delta", {})

                                # A. Scan Content Tokens across all choices
                                delta_content = delta.get("content", "")
                                if delta_content:
                                    safe_chunk, tripped, _ = watcher.scan_chunk(delta_content)
                                    if tripped:
                                        delta["content"] = safe_chunk
                                        tripped_any = True
                                        break
                                    elif stream_holdback_chars > 0:
                                        delta["content"] = safe_chunk

                                # B. Scan Streaming Tool Call Arguments across all tool calls
                                tool_calls = delta.get("tool_calls", [])
                                for tc in tool_calls:
                                    safe_tc, tc_tripped, _ = watcher.scan_tool_call_delta(tc)
                                    if tc_tripped:
                                        delta["tool_calls"] = [safe_tc]
                                        tripped_any = True
                                        break
                                if tripped_any:
                                    break

                            if tripped_any:
                                yield f"data: {json.dumps(chunk_json)}\n\n"
                                yield "data: [DONE]\n\n"
                                break

                            # If not completely suppressed by holdback
                            yield f"data: {json.dumps(chunk_json)}\n\n"
                        except json.JSONDecodeError:
                            yield f"{raw_line}\n\n"
                    else:
                        if raw_line == "data: [DONE]":
                            flush_text = watcher.flush()
                            if flush_text:
                                flush_chunk = {
                                    "id": "flush",
                                    "object": "chat.completion.chunk",
                                    "choices": [{"index": 0, "delta": {"content": flush_text}}],
                                }
                                yield f"data: {json.dumps(flush_chunk)}\n\n"
                        yield f"{raw_line}\n\n"

        return StreamingResponse(stream_generator(), media_type="text/event-stream")

    return app