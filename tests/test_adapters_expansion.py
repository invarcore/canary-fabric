"""Edge case tests for adapters (FastMCP, OpenAI, LangChain, LlamaIndex, IntentFabric, KnowledgeFabric) and Core."""

import base64

import pytest

from canary_fabric.adapters.fastmcp import canary_gate
from canary_fabric.adapters.intent_fabric import IntentFabricCanaryGate
from canary_fabric.adapters.knowledge_fabric import KnowledgeFabricCanaryAdapter
from canary_fabric.adapters.langchain import (
    CanaryCallbackHandler,
    CanaryRetriever,
)
from canary_fabric.adapters.llamaindex import CanaryNodePostprocessor
from canary_fabric.adapters.openai import CanaryStreamWrapper
from canary_fabric.breaker.circuit import CircuitBreaker
from canary_fabric.core.crypto import derive_canary_token, generate_session_nonce
from canary_fabric.core.honeytoken import HoneytokenGenerator, HoneytokenRegistry, HoneytokenType
from canary_fabric.core.synonyms import SemanticWatermarker
from canary_fabric.core.watermark import WatermarkDecoder, WatermarkEncoder
from canary_fabric.eval.redteam import RedTeamEvaluator


# =========================================================================
# FastMCP async and output tripwire tests
# =========================================================================
@pytest.mark.asyncio
async def test_fastmcp_async_canary_gate_clean_and_tripped():
    breaker = CircuitBreaker(secret_key="secret")
    token = derive_canary_token("secret", "tenant_mcp", "tool_doc", "c0")
    wm_text = WatermarkEncoder.inject_watermark("secret param data", token)

    @canary_gate(circuit_breaker=breaker, active_canary_tokens={token})
    async def async_safe_tool(x: int, y: str) -> dict:
        return {"result": f"{x}_{y}"}

    # Clean call
    res = await async_safe_tool(42, "hello")
    assert res == {"result": "42_hello"}

    # Input canary trip
    with pytest.raises(PermissionError, match="CanaryFabric security tripwire triggered"):
        await async_safe_tool(1, wm_text)


@pytest.mark.asyncio
async def test_fastmcp_async_honeytoken_and_output_trip():
    registry = HoneytokenRegistry()
    gen = HoneytokenGenerator(registry=registry)
    ht = gen.generate(HoneytokenType.API_KEY, tenant_id="t1", doc_id="d1")
    breaker = CircuitBreaker(secret_key="secret")

    # Input honeytoken trip
    @canary_gate(circuit_breaker=breaker, honeytoken_registry=registry)
    async def tool_ht_in(key: str) -> str:
        return "ok"

    with pytest.raises(PermissionError, match="CanaryFabric security tripwire triggered"):
        await tool_ht_in(ht.value)

    # Output canary trip
    token = derive_canary_token("secret", "t1", "d1", "c1")
    wm_text = WatermarkEncoder.inject_watermark("leaked result", token)

    @canary_gate(circuit_breaker=breaker, active_canary_tokens={token})
    async def tool_leak_out() -> dict:
        return {"data": wm_text}

    res_out = await tool_leak_out()
    assert res_out["error"] == "TRIPWIRE_TRIGGERED"

    # Sync output trip
    @canary_gate(circuit_breaker=breaker, active_canary_tokens={token})
    def sync_tool_leak_out() -> dict:
        return {"data": wm_text}

    sync_res = sync_tool_leak_out()
    assert sync_res["error"] == "TRIPWIRE_TRIGGERED"


# =========================================================================
# OpenAI Async Streaming Wrapper
# =========================================================================
@pytest.mark.asyncio
async def test_openai_async_stream_wrapper():
    breaker = CircuitBreaker(secret_key="secret")
    token = derive_canary_token("secret", "tenant_oai", "doc_oai", "c0")
    wm_text = WatermarkEncoder.inject_watermark("leaked OpenAI stream token", token)

    class MockDelta:
        def __init__(self, content):
            self.content = content

    class MockChoice:
        def __init__(self, content):
            self.delta = MockDelta(content)

    class MockChunk:
        def __init__(self, content):
            self.choices = [MockChoice(content)]

    async def async_chunks():
        yield MockChunk("Safe intro ")
        yield MockChunk(wm_text)
        yield MockChunk("Should be blocked")

    wrapper = CanaryStreamWrapper(
        stream_iterator=async_chunks(),
        circuit_breaker=breaker,
        active_canary_tokens={token},
    )

    collected = []
    async for chunk in wrapper:
        collected.append(chunk.choices[0].delta.content)

    joined = "".join(collected)
    assert "Safe intro" in joined
    assert "SECURITY ALERT: CanaryFabric Circuit Breaker Tripped" in joined
    assert "Should be blocked" not in joined


# =========================================================================
# LangChain Fallback & Buffer Truncation
# =========================================================================
def test_langchain_retriever_fallbacks():
    class SimpleDoc:
        def __init__(self, text):
            self.page_content = text
            self.metadata = {}

    class FallbackRetriever:
        def get_relevant_documents(self, query: str, **kwargs):
            return [SimpleDoc("Retrieved doc content")]

    retriever = CanaryRetriever(base_retriever=FallbackRetriever(), secret_key="secret", tenant_id="t1")

    # Test invoke fallback to get_relevant_documents
    docs = retriever.invoke("search query")
    assert len(docs) == 1
    assert "doc content" in docs[0].page_content
    assert WatermarkDecoder.contains_watermark(docs[0].page_content)


@pytest.mark.asyncio
async def test_langchain_retriever_async_fallbacks():
    class SimpleDoc:
        def __init__(self, text):
            self.page_content = text
            self.metadata = {}

    # Retriever with native aget_relevant_documents and ainvoke
    class AsyncNativeRetriever:
        async def aget_relevant_documents(self, query: str, **kwargs):
            return [SimpleDoc("Async native docs")]

        async def ainvoke(self, input: str, **kwargs):
            return [SimpleDoc("Async native invoke docs")]

    r_native = CanaryRetriever(base_retriever=AsyncNativeRetriever(), secret_key="secret", tenant_id="t1")
    docs_aget = await r_native.aget_relevant_documents("query")
    assert len(docs_aget) == 1
    docs_ainvoke = await r_native.ainvoke("query")
    assert len(docs_ainvoke) == 1

    # Retriever with only synchronous methods
    class SyncOnlyRetriever:
        def get_relevant_documents(self, query: str, **kwargs):
            return [SimpleDoc("Sync fallback docs")]

    r_sync = CanaryRetriever(base_retriever=SyncOnlyRetriever(), secret_key="secret", tenant_id="t1")
    docs_fallback_aget = await r_sync.aget_relevant_documents("query")
    assert len(docs_fallback_aget) == 1
    docs_fallback_ainvoke = await r_sync.ainvoke("query")
    assert len(docs_fallback_ainvoke) == 1


def test_langchain_callback_buffer_overflow():
    breaker = CircuitBreaker(secret_key="secret")
    handler = CanaryCallbackHandler(circuit_breaker=breaker)

    # Feed tokens exceeding 256 characters
    for _ in range(30):
        handler.on_llm_new_token("ten_chars_")
    assert len(handler._buffer) <= 256


# =========================================================================
# LlamaIndex get_content() fallback
# =========================================================================
def test_llamaindex_node_get_content_fallback():
    postprocessor = CanaryNodePostprocessor(secret_key="secret", tenant_id="t_llama")

    class NodeWithGetContent:
        def __init__(self, content):
            self._text = ""
            self._content = content
            self.metadata = {}
            self.node_id = "node_gc_1"

        def get_content(self):
            return self._content

        @property
        def text(self):
            return self._text

        @text.setter
        def text(self, val):
            self._text = val

    node = NodeWithGetContent("Content via getter")
    processed = postprocessor.postprocess_nodes([node])
    assert len(processed) == 1
    assert "_canary_token" in processed[0].metadata


# =========================================================================
# Knowledge Fabric provenance_hash & Intent Fabric Honeytoken
# =========================================================================
def test_knowledge_fabric_provenance_hash():
    adapter = KnowledgeFabricCanaryAdapter(secret_key="secret")
    items = [{"content": "Evidence text", "provenance_hash": "original_hash", "id": "ev_1"}]
    watermarked, tokens = adapter.watermark_evidence_package(items, tenant_id="t1")
    assert len(watermarked) == 1
    assert "chunk_hash" in watermarked[0]
    assert watermarked[0]["_canary_token"] == tokens[0]


def test_intent_fabric_honeytoken_gate():
    breaker = CircuitBreaker(secret_key="secret")
    registry = HoneytokenRegistry()
    gen = HoneytokenGenerator(registry=registry)
    ht = gen.generate(HoneytokenType.API_KEY, tenant_id="t1", doc_id="d1")

    gate = IntentFabricCanaryGate(circuit_breaker=breaker, honeytoken_registry=registry)
    valid, err = gate.inspect_step_parameters("deploy_infra", {"api_key": ht.value})
    assert valid is False
    assert "Tripwire triggered" in err


# =========================================================================
# Core: Watermark Strategies, Base64, Synonyms, Honeytokens, Crypto
# =========================================================================
def test_watermark_strategies_and_edge_cases():
    token = "A1B2C3D4E5F67890"

    # Prefix strategy
    prefix_wm = WatermarkEncoder.inject_watermark("Sentence text.", token, strategy="prefix")
    assert WatermarkDecoder.contains_watermark(prefix_wm, token)

    # Suffix strategy
    suffix_wm = WatermarkEncoder.inject_watermark("Sentence text.", token, strategy="suffix")
    assert WatermarkDecoder.contains_watermark(suffix_wm, token)

    # Unknown strategy fallback
    unknown_wm = WatermarkEncoder.inject_watermark("Sentence text.", token, strategy="unsupported_strat")
    assert WatermarkDecoder.contains_watermark(unknown_wm, token)

    # Empty text
    empty_wm = WatermarkEncoder.inject_watermark("", token)
    assert WatermarkDecoder.contains_watermark(empty_wm, token)

    # Single word without spaces
    single_word_wm = WatermarkEncoder.inject_watermark("SingleWord", token, strategy="organic")
    assert WatermarkDecoder.contains_watermark(single_word_wm, token)

    # contains_watermark without target token
    assert WatermarkDecoder.contains_watermark(prefix_wm) is True
    assert WatermarkDecoder.contains_watermark("Clean text") is False

    # strip_watermarks
    stripped = WatermarkDecoder.strip_watermarks(prefix_wm)
    assert not WatermarkDecoder.contains_watermark(stripped)
    assert WatermarkDecoder.strip_watermarks("") == ""

    # Base64 encoded zero-width inspection
    encoded_b64 = base64.b64encode(prefix_wm.encode("utf-8")).decode("ascii")
    b64_wrapper_text = f"Here is base64 payload: {encoded_b64} end."
    extracted_b64_tokens = WatermarkDecoder.extract_tokens(b64_wrapper_text)
    assert token in extracted_b64_tokens


def test_synonyms_casing_and_min_slots():
    watermarker = SemanticWatermarker(min_slots_threshold=3)

    # Case preservation: UPPERCASE and Capitalized
    text_with_casing = "We will COMMENCE the project and BEGIN operations swiftly."
    wm_text, modified = watermarker.inject(text_with_casing, secret_key="k", tenant_id="t", doc_id="d")
    assert modified >= 0

    # No synonym slots in text
    no_slot_text = "XYZ 123 456 nothing matches here."
    unmodified, count = watermarker.inject(no_slot_text, secret_key="k", tenant_id="t", doc_id="d")
    assert count == 0
    assert unmodified == no_slot_text

    # Total slots < min_slots in detect
    result = watermarker.detect(no_slot_text, secret_key="k", tenant_id="t", doc_id="d")
    assert result.is_detected is False
    assert result.confidence == 0.0


def test_honeytoken_generator_types_and_registry():
    registry = HoneytokenRegistry()
    gen = HoneytokenGenerator(registry=registry)

    ht_emp = gen.generate(HoneytokenType.EMPLOYEE_ID, tenant_id="t1", doc_id="d1")
    assert "EMP-CANARY-" in ht_emp.value

    ht_jwt = gen.generate(HoneytokenType.JWT_SECRET, tenant_id="t1", doc_id="d1")
    assert "canary_jwt_secret_" in ht_jwt.value

    # Test registry methods
    assert len(registry.find_matches(ht_emp.value)) == 1
    assert len(registry.find_matches("")) == 0

    registry.unregister(ht_emp.value)
    assert len(registry.find_matches(ht_emp.value)) == 0

    registry.clear()
    assert len(registry.find_matches(ht_jwt.value)) == 0


def test_crypto_generate_session_nonce():
    nonce = generate_session_nonce()
    assert isinstance(nonce, str)
    assert len(nonce) == 16


def test_eval_redteam_unknown_vector():
    evaluator = RedTeamEvaluator()
    res = evaluator.simulate_attack_output("dummy_attack", "confidential text", "dummy_token")
    assert res == "confidential text"
