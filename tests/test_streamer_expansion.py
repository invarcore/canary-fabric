"""Streamer edge cases and wrapper tests."""

import pytest

from canary_fabric.breaker.circuit import CircuitBreaker
from canary_fabric.core.crypto import derive_canary_token
from canary_fabric.core.watermark import WatermarkEncoder
from canary_fabric.proxy.streamer import StreamWatcher


def test_wrap_sync_stream_clean_and_tripped():
    breaker = CircuitBreaker(secret_key="secret")
    token = derive_canary_token("secret", "tenant_a", "doc_1", "chunk_0")
    wm_text = WatermarkEncoder.inject_watermark("leaked confidential text", token)

    # Clean stream
    clean_watcher = StreamWatcher(circuit_breaker=breaker, holdback_chars=10)
    clean_chunks = ["Hello ", "world, ", "this is ", "safe text."]
    res = list(clean_watcher.wrap_sync_stream(iter(clean_chunks)))
    assert "".join(res) == "Hello world, this is safe text."

    # Tripped stream
    tripped_watcher = StreamWatcher(circuit_breaker=breaker, active_canary_tokens={token}, holdback_chars=0)
    bad_chunks = ["Normal intro. ", wm_text, " this should be cut off."]
    tripped_res = list(tripped_watcher.wrap_sync_stream(iter(bad_chunks)))
    joined = "".join(tripped_res)
    assert "SECURITY ALERT: CanaryFabric Circuit Breaker Tripped" in joined
    assert "cut off" not in joined


@pytest.mark.asyncio
async def test_wrap_async_stream_clean_and_tripped():
    breaker = CircuitBreaker(secret_key="secret")
    token = derive_canary_token("secret", "tenant_a", "doc_1", "chunk_0")
    wm_text = WatermarkEncoder.inject_watermark("leaked secret token", token)

    async def async_gen(chunks):
        for c in chunks:
            yield c

    # Clean async stream
    clean_watcher = StreamWatcher(circuit_breaker=breaker, holdback_chars=8)
    clean_chunks = ["Async ", "token ", "stream ", "done."]
    res = []
    async for item in clean_watcher.wrap_async_stream(async_gen(clean_chunks)):
        res.append(item)
    assert "".join(res) == "Async token stream done."

    # Tripped async stream
    tripped_watcher = StreamWatcher(circuit_breaker=breaker, active_canary_tokens={token}, holdback_chars=0)
    bad_chunks = ["Start stream. ", wm_text, " suffix that is pruned."]
    tripped_res = []
    async for item in tripped_watcher.wrap_async_stream(async_gen(bad_chunks)):
        tripped_res.append(item)
    assert "SECURITY ALERT: CanaryFabric Circuit Breaker Tripped" in "".join(tripped_res)


def test_tool_call_delta_edge_cases():
    breaker = CircuitBreaker(secret_key="secret")
    token = derive_canary_token("secret", "tenant_tool", "doc_tool", "chunk_0")
    wm_arg = WatermarkEncoder.inject_watermark("admin_password_123", token)

    watcher = StreamWatcher(circuit_breaker=breaker, active_canary_tokens={token}, buffer_window_chars=128)

    # Empty arguments in delta
    delta_empty = {"function": {"arguments": ""}}
    safe, tripped, _ = watcher.scan_tool_call_delta(delta_empty)
    assert not tripped
    assert safe == delta_empty

    # Buffer truncation trigger by sending more than buffer_window_chars * 2
    long_safe_arg = "safe_long_padding_arg_" * 20
    safe_delta = {"function": {"arguments": long_safe_arg}}
    watcher.scan_tool_call_delta(safe_delta)
    assert len(watcher._tool_arg_buffer) <= 256

    # Trip tool call
    trip_delta = {"function": {"name": "query_db", "arguments": wm_arg}}
    safe_tripped, tripped, tokens = watcher.scan_tool_call_delta(trip_delta)
    assert tripped
    assert "CANARY_FABRIC_TRIPWIRE_TRIGGERED" in safe_tripped["function"]["arguments"]

    # Subsequent call when already tripped
    subsequent_delta = {"function": {"arguments": "extra_arg"}}
    safe_sub, tripped_sub, _ = watcher.scan_tool_call_delta(subsequent_delta)
    assert tripped_sub
    assert "[BLOCKED_BY_CANARY_FABRIC]" in safe_sub["function"]["arguments"]
