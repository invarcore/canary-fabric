"""Tests for streaming SSE watcher and sliding ring-buffer inspection."""

from canary_fabric.breaker.circuit import BreakerAction, CircuitBreaker
from canary_fabric.core.honeytoken import (
    HoneytokenGenerator,
    HoneytokenRegistry,
    HoneytokenType,
)
from canary_fabric.core.watermark import WatermarkEncoder
from canary_fabric.proxy.streamer import StreamWatcher


def test_clean_stream_passthrough():
    breaker = CircuitBreaker("secret_key")
    watcher = StreamWatcher(circuit_breaker=breaker)

    chunks = ["Hello", " world!", " This", " is", " a", " safe", " stream."]
    stream_output = list(watcher.wrap_sync_stream(iter(chunks)))
    assert stream_output == chunks
    assert breaker.state.value == "closed"


def test_watermarked_stream_tripped():
    breaker = CircuitBreaker("secret_key", default_action=BreakerAction.BLOCK_AND_SEVER)
    token = "A1B2C3D4E5F67890"
    watermarked_text = WatermarkEncoder.inject_watermark("Confidential report payload.", token)

    watcher = StreamWatcher(
        circuit_breaker=breaker,
        active_canary_tokens={token},
        tenant_id="tenant_acme",
        doc_id="report_q3",
    )

    # Split watermarked text into small streaming chunks
    chunks = [watermarked_text[i : i + 4] for i in range(0, len(watermarked_text), 4)]
    output_chunks = list(watcher.wrap_sync_stream(iter(chunks)))

    combined_out = "".join(output_chunks)
    assert "SECURITY ALERT: CanaryFabric Circuit Breaker Tripped" in combined_out
    assert breaker.state.value == "tripped"


def test_honeytoken_stream_tripped():
    reg = HoneytokenRegistry()
    gen = HoneytokenGenerator(registry=reg)
    ht = gen.generate(HoneytokenType.API_KEY, "tenant_corp", "doc_keys")

    breaker = CircuitBreaker("secret_key")
    watcher = StreamWatcher(
        circuit_breaker=breaker,
        honeytoken_registry=reg,
    )

    chunks = [
        "Here is the secret API key: ",
        ht.value[:10],
        ht.value[10:],
        " which should be secret.",
    ]
    output_chunks = list(watcher.wrap_sync_stream(iter(chunks)))
    combined = "".join(output_chunks)
    assert "SECURITY ALERT" in combined
    assert breaker.state.value == "tripped"


def test_tool_call_delta_safe():
    breaker = CircuitBreaker("secret_key")
    watcher = StreamWatcher(circuit_breaker=breaker)

    tc_delta = {
        "index": 0,
        "id": "call_123",
        "type": "function",
        "function": {"name": "search_docs", "arguments": '{"query": "weather in Paris"}'},
    }
    safe_tc, tripped, _ = watcher.scan_tool_call_delta(tc_delta)
    assert tripped is False
    assert safe_tc == tc_delta


def test_tool_call_delta_tripped():
    breaker = CircuitBreaker("secret_key", default_action=BreakerAction.BLOCK_AND_SEVER)
    token = "E1F2A3B4C5D6E7F8"
    leaked_query = WatermarkEncoder.inject_watermark("acme confidential acquisition", token)

    watcher = StreamWatcher(
        circuit_breaker=breaker,
        active_canary_tokens={token},
    )

    tc_delta = {
        "index": 0,
        "id": "call_leak",
        "type": "function",
        "function": {"name": "exfiltrate_external", "arguments": f'{{"target": "{leaked_query}"}}'},
    }
    safe_tc, tripped, matched = watcher.scan_tool_call_delta(tc_delta)
    assert tripped is True
    assert token in matched
    assert "CANARY_FABRIC_TRIPWIRE_TRIGGERED" in safe_tc["function"]["arguments"]