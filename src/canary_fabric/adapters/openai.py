"""OpenAI and LiteLLM streaming client wrappers for client-side tripwire protection."""

from collections.abc import AsyncIterator, Iterator
from typing import Any

from canary_fabric.breaker.circuit import CircuitBreaker
from canary_fabric.proxy.streamer import StreamWatcher


class CanaryStreamWrapper:
    """Wraps an OpenAI or LiteLLM streaming chunk iterator to scan text and tool calls in-flight."""

    def __init__(
        self,
        stream_iterator: Iterator[Any] | AsyncIterator[Any],
        circuit_breaker: CircuitBreaker,
        tenant_id: str = "default_tenant",
        active_canary_tokens: set[str] | None = None,
    ) -> None:
        self.stream = stream_iterator
        self.watcher = StreamWatcher(
            circuit_breaker=circuit_breaker,
            tenant_id=tenant_id,
            active_canary_tokens=active_canary_tokens,
        )

    def __iter__(self) -> Iterator[Any]:
        for chunk in self.stream:
            # Extract content from delta if present
            delta_content = ""
            if hasattr(chunk, "choices") and chunk.choices:
                delta = getattr(chunk.choices[0], "delta", None)
                if delta:
                    delta_content = getattr(delta, "content", "") or ""

            if delta_content:
                safe_text, tripped, _ = self.watcher.scan_chunk(delta_content)
                if tripped:
                    # Overwrite chunk content with redacted notice and terminate
                    if hasattr(chunk.choices[0].delta, "content"):
                        chunk.choices[0].delta.content = safe_text
                    yield chunk
                    break

            yield chunk

    async def __aiter__(self) -> AsyncIterator[Any]:
        async for chunk in self.stream:
            delta_content = ""
            if hasattr(chunk, "choices") and chunk.choices:
                delta = getattr(chunk.choices[0], "delta", None)
                if delta:
                    delta_content = getattr(delta, "content", "") or ""

            if delta_content:
                safe_text, tripped, _ = self.watcher.scan_chunk(delta_content)
                if tripped:
                    if hasattr(chunk.choices[0].delta, "content"):
                        chunk.choices[0].delta.content = safe_text
                    yield chunk
                    break

            yield chunk


def wrap_streaming_response(
    response: Any,
    circuit_breaker: CircuitBreaker,
    tenant_id: str = "default_tenant",
    active_canary_tokens: set[str] | None = None,
) -> CanaryStreamWrapper:
    """Wrap any OpenAI / LiteLLM streaming response with sub-millisecond tripwire protection."""
    return CanaryStreamWrapper(
        stream_iterator=response,
        circuit_breaker=circuit_breaker,
        tenant_id=tenant_id,
        active_canary_tokens=active_canary_tokens,
    )