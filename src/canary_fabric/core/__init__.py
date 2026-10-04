# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""Core cryptographic, steganographic, and honeytoken primitives for Canary Fabric."""

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
from canary_fabric.core.synonyms import (
    DEFAULT_SYNONYM_PAIRS,
    DetectionResult,
    SemanticWatermarker,
)
from canary_fabric.core.watermark import WatermarkDecoder, WatermarkEncoder

__all__ = [
    "DEFAULT_SYNONYM_PAIRS",
    "DetectionResult",
    "Honeytoken",
    "HoneytokenGenerator",
    "HoneytokenRegistry",
    "HoneytokenType",
    "SemanticWatermarker",
    "WatermarkDecoder",
    "WatermarkEncoder",
    "derive_canary_token",
    "generate_session_nonce",
    "sign_payload",
    "verify_signature",
]