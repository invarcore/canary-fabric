"""Ultra-low-latency streaming SSE token watcher with sliding ring-buffer inspection."""

import time
from collections.abc import AsyncIterator, Iterator
from typing import Any

from canary_fabric.breaker.circuit import CircuitBreaker, TripwireEvent
from canary_fabric.core.honeytoken import HoneytokenRegistry
from canary_fabric.core.watermark import WatermarkDecoder


class StreamWatcher:
    """Zero-buffering sliding-window scanner for LLM output streams (<0.8ms latency tax).

    Inspects both standard conversational content tokens and partial streaming JSON
    parameters in agent tool/function calls to prevent context exfiltration.
    """

    def __init__(
        self,
        circuit_breaker: CircuitBreaker,
        honeytoken_registry: HoneytokenRegistry | None = None,
        active_canary_tokens: set[str] | None = None,
        tenant_id: str = "default_tenant",
        doc_id: str = "unknown_doc",
        chunk_id: str = "chunk_0",
        buffer_window_chars: int = 128,
    ) -> None:
        self.breaker = circuit_breaker
        self.honeytoken_registry = honeytoken_registry or HoneytokenRegistry()
        self.active_canary_tokens = active_canary_tokens or set()
        self.tenant_id = tenant_id
        self.doc_id = doc_id
        self.chunk_id = chunk_id
        self.buffer_window_chars = buffer_window_chars
        self._sliding_buffer = ""
        self._tool_arg_buffer = ""
        self._is_tripped = False

    @property
    def is_tripped(self) -> bool:
        """Return True if a tripwire has been tripped during this stream."""
        return self._is_tripped

    def scan_chunk(self, raw_chunk: str) -> tuple[str, bool, list[str]]:
        """Process an incoming streaming text chunk.

        Returns:
            (safe_chunk_to_yield, is_tripped, detected_tokens)
        """
        if self._is_tripped:
            return "", True, []

        _t0 = time.perf_counter()

        # Append to sliding window
        self._sliding_buffer += raw_chunk
        if len(self._sliding_buffer) > self.buffer_window_chars * 2:
            self._sliding_buffer = self._sliding_buffer[-self.buffer_window_chars :]

        # 1. Check for Zero-Width Watermark Tokens
        extracted_tokens = WatermarkDecoder.extract_tokens(self._sliding_buffer)
        matched_tokens = []
        for token in extracted_tokens:
            if not self.active_canary_tokens or token in self.active_canary_tokens:
                matched_tokens.append(token)

        # 2. Check for Synthetic Honeytokens
        ht_matches = self.honeytoken_registry.find_matches(self._sliding_buffer)
        for ht in ht_matches:
            matched_tokens.append(ht.value)

        if matched_tokens:
            self._is_tripped = True
            primary_token = matched_tokens[0]

            event = TripwireEvent(
                canary_token=primary_token,
                tenant_id=self.tenant_id,
                source_doc_id=self.doc_id,
                source_chunk_id=self.chunk_id,
                matched_text_snippet=raw_chunk,
            )
            _, replacement = self.breaker.handle_tripwire(event)
            return replacement, True, matched_tokens

        return raw_chunk, False, []

    def scan_tool_call_delta(
        self,
        tool_call_delta: dict[str, Any],
    ) -> tuple[dict[str, Any], bool, list[str]]:
        """Inspect partial streaming tool call delta chunks for canary leaks in function arguments.

        Returns:
            (safe_tool_call_delta, is_tripped, detected_tokens)
        """
        if self._is_tripped:
            return {"function": {"arguments": '{"error": "[BLOCKED_BY_CANARY_FABRIC]"}'}}, True, []

        func = tool_call_delta.get("function", {})
        args_delta = func.get("arguments", "")

        if not args_delta:
            return tool_call_delta, False, []

        self._tool_arg_buffer += args_delta
        if len(self._tool_arg_buffer) > self.buffer_window_chars * 2:
            self._tool_arg_buffer = self._tool_arg_buffer[-self.buffer_window_chars :]

        extracted_tokens = WatermarkDecoder.extract_tokens(self._tool_arg_buffer)
        matched_tokens = []
        for token in extracted_tokens:
            if not self.active_canary_tokens or token in self.active_canary_tokens:
                matched_tokens.append(token)

        ht_matches = self.honeytoken_registry.find_matches(self._tool_arg_buffer)
        for ht in ht_matches:
            matched_tokens.append(ht.value)

        if matched_tokens:
            self._is_tripped = True
            primary_token = matched_tokens[0]

            event = TripwireEvent(
                canary_token=primary_token,
                tenant_id=self.tenant_id,
                source_doc_id=f"{self.doc_id}:tool_argument",
                source_chunk_id=self.chunk_id,
                matched_text_snippet=args_delta,
            )
            _, replacement = self.breaker.handle_tripwire(event)
            safe_delta = dict(tool_call_delta)
            safe_delta["function"] = {
                "name": func.get("name", "blocked_tool"),
                "arguments": f'{{"error": "CANARY_FABRIC_TRIPWIRE_TRIGGERED", "details": "{replacement}"}}',
            }
            return safe_delta, True, matched_tokens

        return tool_call_delta, False, []

    def wrap_sync_stream(self, stream_iterator: Iterator[str]) -> Iterator[str]:
        """Wrap a synchronous token iterator with active tripwire protection."""
        for chunk in stream_iterator:
            safe_chunk, tripped, _ = self.scan_chunk(chunk)
            yield safe_chunk
            if tripped:
                break

    async def wrap_async_stream(self, stream_iterator: AsyncIterator[str]) -> AsyncIterator[str]:
        """Wrap an asynchronous token iterator with active tripwire protection."""
        async for chunk in stream_iterator:
            safe_chunk, tripped, _ = self.scan_chunk(chunk)
            yield safe_chunk
            if tripped:
                break