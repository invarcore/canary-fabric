"""Ecosystem adapters for Knowledge Fabric, Intent Fabric, FastMCP, and LangChain."""

from canary_fabric.adapters.fastmcp import canary_gate
from canary_fabric.adapters.intent_fabric import IntentFabricCanaryGate
from canary_fabric.adapters.knowledge_fabric import KnowledgeFabricCanaryAdapter

__all__ = [
    "IntentFabricCanaryGate",
    "KnowledgeFabricCanaryAdapter",
    "canary_gate",
]
