"""Tests for Knowledge Fabric, Intent Fabric, and FastMCP adapters."""

import pytest

from canary_fabric.adapters.fastmcp import canary_gate
from canary_fabric.adapters.intent_fabric import IntentFabricCanaryGate
from canary_fabric.adapters.knowledge_fabric import KnowledgeFabricCanaryAdapter
from canary_fabric.breaker.circuit import CircuitBreaker
from canary_fabric.core.watermark import WatermarkEncoder


def test_knowledge_fabric_adapter():
    adapter = KnowledgeFabricCanaryAdapter("kf_secret")
    evidence_items = [
        {
            "document_id": "policy_doc",
            "chunk_id": "chunk_0",
            "content": "Company confidential retention policy.",
        },
        {
            "document_id": "policy_doc",
            "chunk_id": "chunk_1",
            "content": "Employee benefits summary.",
        },
    ]

    watermarked_items, tokens = adapter.watermark_evidence_package(evidence_items, "tenant_acme")
    assert len(watermarked_items) == 2
    assert len(tokens) == 2
    assert "_canary_token" in watermarked_items[0]
    assert watermarked_items[0]["_canary_token"] == tokens[0]


def test_knowledge_fabric_adapter_with_snippet():
    import hashlib

    adapter = KnowledgeFabricCanaryAdapter("kf_secret")
    raw_snippet = "Confidential customer database excerpt."
    original_hash = hashlib.sha256(raw_snippet.encode("utf-8")).hexdigest()
    evidence_items = [
        {
            "document_uri": "policy_doc_v2",
            "chunk_id": "chunk_42",
            "snippet": raw_snippet,
            "chunk_hash": original_hash,
        },
    ]

    watermarked_items, tokens = adapter.watermark_evidence_package(evidence_items, "tenant_corp")
    assert len(watermarked_items) == 1
    assert "snippet" in watermarked_items[0]
    assert watermarked_items[0]["snippet"] != raw_snippet
    assert watermarked_items[0]["chunk_hash"] != original_hash
    assert watermarked_items[0]["chunk_hash"] == hashlib.sha256(
        watermarked_items[0]["snippet"].encode("utf-8")
    ).hexdigest()
    assert watermarked_items[0]["_canary_token"] == tokens[0]


def test_intent_fabric_canary_gate():
    breaker = CircuitBreaker("secret")
    gate = IntentFabricCanaryGate(circuit_breaker=breaker)

    safe_params = {"destination": "https://api.internal/v1/user", "user_id": "USR-101"}
    is_safe, error = gate.inspect_step_parameters("fetch_user", safe_params)
    assert is_safe is True
    assert error is None

    # Inject canary into parameter
    canary_token = "7F8A9E1D2C3B4A5E"
    leaked_value = WatermarkEncoder.inject_watermark("Secret leaked parameter", canary_token)
    unsafe_params = {"message": leaked_value}

    is_safe, error = gate.inspect_step_parameters("send_slack_message", unsafe_params)
    assert is_safe is False
    assert "Tripwire triggered" in error


def test_fastmcp_gate_decorator():
    breaker = CircuitBreaker("secret")

    @canary_gate(circuit_breaker=breaker)
    def my_mcp_tool(query: str) -> dict[str, str]:
        return {"result": f"Executed: {query}"}

    # Clean call works
    res = my_mcp_tool(query="Hello safe world")
    assert res == {"result": "Executed: Hello safe world"}

    # Leaked canary in input raises PermissionError
    canary_token = "DEADBEEFCAFE1234"
    watermarked_query = WatermarkEncoder.inject_watermark("Leaked input query", canary_token)

    with pytest.raises(PermissionError) as exc_info:
        my_mcp_tool(query=watermarked_query)
    assert "CanaryFabric security tripwire triggered" in str(exc_info.value)
