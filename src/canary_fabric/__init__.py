"""Canary Fabric: Invisible Cryptographic Tripwires and Sub-Millisecond Egress Circuit Breakers for AI."""

import sys

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
from canary_fabric.breaker.alerter import IncidentAlerter
from canary_fabric.breaker.circuit import (
    BreakerAction,
    BreakerState,
    CircuitBreaker,
    TripwireEvent,
)
from canary_fabric.core.crypto import (
    derive_canary_token,
    generate_session_nonce,
    sign_payload,
    verify_signature,
)
from canary_fabric.core.honeytoken import (
    Honeytoken,
    HoneytokenGenerator,
    HoneytokenRegistry,
    HoneytokenType,
)
from canary_fabric.core.synonyms import SemanticWatermarker
from canary_fabric.core.watermark import (
    WatermarkDecoder,
    WatermarkEncoder,
)
from canary_fabric.eval.redteam import RedTeamEvaluator
from canary_fabric.forensics.certificate import LeakCertificate
from canary_fabric.forensics.exporters import (
    BaseIncidentExporter,
    CEFExporter,
    OpenTelemetryExporter,
    WebhookExporter,
)
from canary_fabric.forensics.vault import IncidentVault
from canary_fabric.proxy.server import create_proxy_app
from canary_fabric.proxy.streamer import SlidingWindowStreamBuffer, StreamWatcher

__version__ = "0.2.0"

# Register promptcanary alias in sys.modules for backward compatibility
sys.modules["promptcanary"] = sys.modules[__name__]

__all__ = [
    "__version__",
    # Core
    "derive_canary_token",
    "generate_session_nonce",
    "sign_payload",
    "verify_signature",
    "WatermarkEncoder",
    "WatermarkDecoder",
    "SemanticWatermarker",
    "Honeytoken",
    "HoneytokenType",
    "HoneytokenGenerator",
    "HoneytokenRegistry",
    # Breaker
    "BreakerAction",
    "BreakerState",
    "CircuitBreaker",
    "TripwireEvent",
    "IncidentAlerter",
    # Forensics & Exporters
    "LeakCertificate",
    "IncidentVault",
    "BaseIncidentExporter",
    "WebhookExporter",
    "CEFExporter",
    "OpenTelemetryExporter",
    # Proxy
    "SlidingWindowStreamBuffer",
    "StreamWatcher",
    "create_proxy_app",
    # Adapters
    "KnowledgeFabricCanaryAdapter",
    "IntentFabricCanaryGate",
    "canary_gate",
    "CanaryDocumentTransformer",
    "CanaryRetriever",
    "CanaryCallbackHandler",
    "CanaryTripwireException",
    "CanaryNodePostprocessor",
    "CanaryStreamWrapper",
    "wrap_streaming_response",
    # Eval
    "RedTeamEvaluator",
]