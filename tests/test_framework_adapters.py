"""Tests for framework adapters: LangChain, LlamaIndex, and OpenAI/LiteLLM."""

import pytest

from canary_fabric.adapters.langchain import (
    CanaryCallbackHandler,
    CanaryDocumentTransformer,
    CanaryRetriever,
    CanaryTripwireException,
)
from canary_fabric.adapters.llamaindex import CanaryNodePostprocessor
from canary_fabric.adapters.openai import wrap_streaming_response
from canary_fabric.breaker.circuit import BreakerAction, CircuitBreaker
from canary_fabric.core.crypto import derive_canary_token
from canary_fabric.core.watermark import WatermarkDecoder, WatermarkEncoder


class MockDocument:
    def __init__(self, page_content: str, metadata: dict | None = None):
        self.page_content = page_content
        self.metadata = metadata or {}


class MockRetriever:
    def __init__(self, docs):
        self.docs = docs

    def get_relevant_documents(self, query: str):
        return self.docs

    def invoke(self, input_str: str):
        return self.docs


class MockNode:
    def __init__(self, text: str, node_id: str = "node_1", metadata: dict | None = None):
        self.text = text
        self.node_id = node_id
        self.metadata = metadata or {}


class MockNodeWithScore:
    def __init__(self, node: MockNode, score: float = 0.95):
        self.node = node
        self.score = score


class MockDelta:
    def __init__(self, content: str = ""):
        self.content = content


class MockChoice:
    def __init__(self, delta: MockDelta):
        self.delta = delta


class MockChunk:
    def __init__(self, content: str = ""):
        self.choices = [MockChoice(MockDelta(content))]


def test_langchain_document_transformer():
    transformer = CanaryDocumentTransformer(
        secret_key="test_secret",
        tenant_id="tenant_alpha",
    )
    docs = [
        MockDocument("Confidential Q3 revenue is $45M.", {"id": "rev_q3"}),
        {"page_content": "Project Apollo will launch in November.", "metadata": {"id": "apollo"}},
    ]

    transformed = transformer.transform_documents(docs)
    assert len(transformed) == 2

    # Check first doc (object)
    doc1 = transformed[0]
    extracted1 = WatermarkDecoder.extract_tokens(doc1.page_content)
    assert len(extracted1) == 1
    assert doc1.metadata["_canary_token"] == extracted1[0]
    assert doc1.metadata["_canary_active"] is True

    # Check second doc (dict)
    doc2 = transformed[1]
    extracted2 = WatermarkDecoder.extract_tokens(doc2["page_content"])
    assert len(extracted2) == 1
    assert doc2["metadata"]["_canary_token"] == extracted2[0]


def test_langchain_retriever():
    mock_retriever = MockRetriever([
        MockDocument("Acquisition details for Beta Corp.", {"id": "acq_beta"}),
    ])
    canary_retriever = CanaryRetriever(
        base_retriever=mock_retriever,
        secret_key="test_secret",
        tenant_id="tenant_beta",
    )

    docs = canary_retriever.get_relevant_documents("acquisition")
    assert len(docs) == 1
    assert "_canary_token" in docs[0].metadata
    assert len(WatermarkDecoder.extract_tokens(docs[0].page_content)) == 1

    # Test invoke protocol
    invoked_docs = canary_retriever.invoke("acquisition")
    assert len(invoked_docs) == 1
    assert "_canary_token" in invoked_docs[0].metadata


def test_langchain_callback_handler():
    breaker = CircuitBreaker(secret_key="test_secret", default_action=BreakerAction.BLOCK_AND_SEVER)
    handler = CanaryCallbackHandler(circuit_breaker=breaker, tenant_id="tenant_alpha")

    # Safe token does not raise
    handler.on_llm_new_token("Hello, this is safe.")

    # Generate watermarked text
    canary = derive_canary_token("test_secret", "tenant_alpha", "doc1", "chunk1")
    leaked_text = WatermarkEncoder.inject_watermark("Secret revenue", canary)

    with pytest.raises(CanaryTripwireException) as excinfo:
        handler.on_llm_new_token(leaked_text)
    assert "security tripwire triggered" in str(excinfo.value)

    # Test tool start gate
    with pytest.raises(CanaryTripwireException) as excinfo_tool:
        handler.on_tool_start({"name": "web_search"}, f"Search query: {leaked_text}")
    assert "tool gate tripped" in str(excinfo_tool.value)


def test_llamaindex_node_postprocessor():
    postprocessor = CanaryNodePostprocessor(
        secret_key="test_secret",
        tenant_id="tenant_llamaindex",
    )
    nodes = [
        MockNodeWithScore(MockNode("Sensitive customer retention data.", "node_retention")),
    ]

    processed = postprocessor.postprocess_nodes(nodes)
    assert len(processed) == 1
    node = processed[0].node
    extracted = WatermarkDecoder.extract_tokens(node.text)
    assert len(extracted) == 1
    assert node.metadata["_canary_token"] == extracted[0]


def test_openai_stream_wrapper():
    breaker = CircuitBreaker(secret_key="test_secret", default_action=BreakerAction.BLOCK_AND_SEVER)

    canary = derive_canary_token("test_secret", "tenant_stream", "doc1", "chunk1")
    leaked_chunk = WatermarkEncoder.inject_watermark("Leaked confidential memo", canary)

    mock_chunks = [
        MockChunk("Hello, "),
        MockChunk("here is "),
        MockChunk(leaked_chunk),
        MockChunk(" extra text that should not appear."),
    ]

    wrapped = wrap_streaming_response(mock_chunks, circuit_breaker=breaker, tenant_id="tenant_stream")
    yielded = list(wrapped)

    # The 3rd chunk should be redacted and the 4th should never be yielded
    assert len(yielded) == 3
    assert yielded[0].choices[0].delta.content == "Hello, "
    assert "SECURITY ALERT" in yielded[2].choices[0].delta.content