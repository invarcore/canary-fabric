"""Ecosystem adapters for Knowledge Fabric, Intent Fabric, FastMCP, LangChain, LlamaIndex, and OpenAI."""

from canary_fabric.adapters.fastmcp import canary_gate
from canary_fabric.adapters.intent_fabric import IntentFabricCanaryGate
from canary_fabric.adapters.knowledge_fabric import KnowledgeFabricCanaryAdapter
from canary_fabric.adapters.langchain import (
    CanaryCallbackHandler,
    CanaryDocumentTransformer,
    CanaryRetriever,
    CanaryTripwireException,
)
from canary_fabric.adapters.llamaindex import CanaryNodePostprocessor
from canary_fabric.adapters.openai import CanaryStreamWrapper, wrap_streaming_response

__all__ = [
    "CanaryCallbackHandler",
    "CanaryDocumentTransformer",
    "CanaryNodePostprocessor",
    "CanaryRetriever",
    "CanaryStreamWrapper",
    "CanaryTripwireException",
    "IntentFabricCanaryGate",
    "KnowledgeFabricCanaryAdapter",
    "canary_gate",
    "wrap_streaming_response",
]