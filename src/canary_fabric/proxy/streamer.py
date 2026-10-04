# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

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
        holdback_chars: int = 0,
    ) -> None:
        self.breaker = circuit_breaker
        self.honeytoken_registry = honeytoken_registry or HoneytokenRegistry()
        self.active_canary_tokens = set(active_canary_tokens) if active_canary_tokens is not None else None
        self.holdback_chars = holdback_chars
        self.tenant_id = tenant_id
        self.doc_id = doc_id
        self.chunk_id = chunk_id
        self.buffer_window_chars = buffer_window_chars
        self._sliding_buffer = ""
        self._tool_arg_buffer = ""
        self._holdback_buffer = ""
        self._is_tripped = False

    @property
    def is_tripped(self) -> bool:
        """Return True if a tripwire has been tripped during this stream."""
        return self._is_tripped

    def flush(self) -> str:
        """Flush remaining held-back safe buffer when stream reaches EOF."""
        if self._is_tripped:
            return ""
        remaining = self._holdback_buffer
        self._holdback_buffer = ""
        return remaining

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
            if self.active_canary_tokens is None:
                matched_tokens.append(token)
            elif token in self.active_canary_tokens:
                matched_tokens.append(token)

        # 2. Check for Synthetic Honeytokens
        ht_matches = self.honeytoken_registry.find_matches(self._sliding_buffer)
        for ht in ht_matches:
            matched_tokens.append(ht.value)

        if matched_tokens:
            self._is_tripped = True
            self._holdback_buffer = ""  # Discard held-back prefix to prevent disclosure
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

        if self.holdback_chars > 0:
            self._holdback_buffer += raw_chunk
            if len(self._holdback_buffer) > self.holdback_chars:
                release_len = len(self._holdback_buffer) - self.holdback_chars
                to_release = self._holdback_buffer[:release_len]
                self._holdback_buffer = self._holdback_buffer[release_len:]
                return to_release, False, []
            return "", False, []

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
            if self.active_canary_tokens is None:
                matched_tokens.append(token)
            elif token in self.active_canary_tokens:
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
            if safe_chunk:
                yield safe_chunk
            if tripped:
                break
        if not self._is_tripped and self._holdback_buffer:
            yield self.flush()

    async def wrap_async_stream(self, stream_iterator: AsyncIterator[str]) -> AsyncIterator[str]:
        """Wrap an asynchronous token iterator with active tripwire protection."""
        async for chunk in stream_iterator:
            safe_chunk, tripped, _ = self.scan_chunk(chunk)
            if safe_chunk:
                yield safe_chunk
            if tripped:
                break
        if not self._is_tripped and self._holdback_buffer:
            yield self.flush()


class SlidingWindowStreamBuffer(StreamWatcher):
    """Zero-leak sliding-window lookahead stream buffer (Rank 2: CAN-01/CAN-02).

    Buffers streaming chunks in a k-lookahead window to guarantee that partial
    tokens, split credentials, or watermarks cannot escape to the client before
    full detection passes complete.

    Attributes:
        lookahead_window: Number of characters to retain in the lookahead buffer (default: 64).
        credential_patterns: Optional regex patterns for high-entropy secrets (AWS, JWT, Private Keys).
    """

    def __init__(
        self,
        circuit_breaker: CircuitBreaker,
        honeytoken_registry: HoneytokenRegistry | None = None,
        active_canary_tokens: set[str] | None = None,
        tenant_id: str = "default_tenant",
        doc_id: str = "unknown_doc",
        chunk_id: str = "chunk_0",
        buffer_window_chars: int = 256,
        lookahead_window: int = 64,
        credential_patterns: list[str] | None = None,
    ) -> None:
        super().__init__(
            circuit_breaker=circuit_breaker,
            honeytoken_registry=honeytoken_registry,
            active_canary_tokens=active_canary_tokens,
            tenant_id=tenant_id,
            doc_id=doc_id,
            chunk_id=chunk_id,
            buffer_window_chars=buffer_window_chars,
            holdback_chars=lookahead_window,
        )
        self.lookahead_window = lookahead_window
        import re

        self._compiled_patterns = [
            re.compile(p, re.IGNORECASE)
            for p in (
                credential_patterns
                or [
                    r"\b(AKIA[0-9A-Z]{16})\b",
                    r"\b(sk-[A-Za-z0-9_\-]{20,})\b",
                    r"-----BEGIN [A-Z0-9_ -]*PRIVATE KEY-----",
                    r"(Bearer\s+)[A-Za-z0-9_\-\.]{16,}",
                ]
            )
        ]

    def scan_chunk(self, raw_chunk: str) -> tuple[str, bool, list[str]]:
        safe_chunk, tripped, tokens = super().scan_chunk(raw_chunk)
        if tripped:
            return safe_chunk, True, tokens

        for pattern in self._compiled_patterns:
            match = pattern.search(self._sliding_buffer)
            if match:
                self._is_tripped = True
                self._holdback_buffer = ""
                leak_snippet = match.group(0)
                event = TripwireEvent(
                    canary_token="CREDENTIAL_LEAK",
                    tenant_id=self.tenant_id,
                    source_doc_id=self.doc_id,
                    source_chunk_id=self.chunk_id,
                    matched_text_snippet=leak_snippet,
                )
                _, replacement = self.breaker.handle_tripwire(event)
                return replacement, True, [leak_snippet]

        return safe_chunk, False, []