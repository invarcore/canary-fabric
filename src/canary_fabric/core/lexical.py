# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""Configurable Non-Steganographic Lexical Fallback & Multi-Mode Canary Engine."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from canary_fabric.core.honeytoken import (
    Honeytoken,
    HoneytokenRegistry,
    HoneytokenType,
)
from canary_fabric.core.synonyms import SemanticWatermarker
from canary_fabric.core.watermark import WatermarkEncoder


class CanaryMode(str, Enum):
    """Canary injection and detection operational modes."""

    STEGO = "stego"  # 4-ary Zero-width Unicode invisible steganography only
    LEXICAL = "lexical"  # Non-steganographic high-entropy honeytokens & lexical sentinels
    HYBRID = "hybrid"  # Defense-in-depth: Both zero-width steganography and lexical tripwires


@dataclass
class LexicalCanaryToken:
    """Represents a non-steganographic lexical canary token."""

    token_id: str
    token_value: str
    token_type: str  # "decoy_credential" | "semantic_anchor" | "synonym_stream"
    tenant_id: str
    doc_id: str
    chunk_id: str
    created_at: str
    metadata: dict[str, Any] = field(default_factory=dict)


class LexicalCanaryInjector:
    """Injects non-steganographic, sanitizer-resilient lexical tripwires into RAG context.

    Provides high-entropy decoy credentials and deterministic semantic anchor tokens
    that survive aggressive Unicode stripping, HTML entity escaping, and plain-text
    normalization pipelines.
    """

    def __init__(
        self,
        secret_key: str,
        honeytoken_registry: HoneytokenRegistry | None = None,
        synonym_watermarker: SemanticWatermarker | None = None,
    ) -> None:
        if not secret_key or not secret_key.strip():
            raise ValueError("secret_key must be a non-empty, non-whitespace string")
        self.secret_key = secret_key
        self.registry = honeytoken_registry or HoneytokenRegistry()
        self.synonym_watermarker = synonym_watermarker or SemanticWatermarker()

    def generate_lexical_token(
        self,
        tenant_id: str,
        doc_id: str,
        chunk_id: str,
        token_type: str = "decoy_credential",
        session_nonce: str | None = None,
        auto_register: bool = True,
    ) -> LexicalCanaryToken:
        """Derive an authenticated, high-entropy lexical canary token bound to chunk metadata."""
        nonce = session_nonce or secrets.token_hex(4).lower()
        seed_data = f"{tenant_id}:{doc_id}:{chunk_id}:{nonce}".encode("utf-8")
        mac = (
            hmac.new(self.secret_key.encode("utf-8"), seed_data, hashlib.sha256)
            .hexdigest()[:16]
            .upper()
        )

        if token_type == "decoy_credential":
            value = f"sk_live_canary_{mac.lower()}_{secrets.token_hex(4)}"
        elif token_type == "semantic_anchor":
            value = f"CANARY-REF-{mac[:12]}"
        elif token_type == "audit_header":
            value = f"audit_tracing_id: CANARY-{mac[:8]}-{secrets.token_hex(3)}"
        else:
            value = f"canary_token_{mac}"

        token_id = f"lex_{mac[:8]}_{secrets.token_hex(3)}"
        lex_token = LexicalCanaryToken(
            token_id=token_id,
            token_value=value,
            token_type=token_type,
            tenant_id=tenant_id,
            doc_id=doc_id,
            chunk_id=chunk_id,
            created_at=nonce,
            metadata={"mac": mac},
        )

        if auto_register:
            # Register with underlying HoneytokenRegistry for unified streaming inspection
            ht = Honeytoken(
                token_id=token_id,
                token_type=HoneytokenType.API_KEY
                if "sk_live" in value
                else HoneytokenType.EMPLOYEE_ID,
                value=value,
                tenant_id=tenant_id,
                doc_id=doc_id,
                description=f"Lexical canary token ({token_type})",
            )
            self.registry.register(ht)

        return lex_token

    def inject(
        self,
        text: str,
        tenant_id: str,
        doc_id: str,
        chunk_id: str,
        mode: CanaryMode | str = CanaryMode.HYBRID,
        token_type: str = "decoy_credential",
        session_nonce: str | None = None,
    ) -> tuple[str, list[str]]:
        """Inject canaries into chunk text according to the selected operational mode.

        Returns:
            (watermarked_text, list_of_active_canary_identifiers)
        """
        active_tokens: list[str] = []
        result_text = text
        op_mode = CanaryMode(mode) if isinstance(mode, str) else mode

        # 1. Steganographic Zero-Width Injection (if STEGO or HYBRID)
        if op_mode in (CanaryMode.STEGO, CanaryMode.HYBRID):
            nonce = session_nonce or secrets.token_hex(4).lower()
            seed_data = f"{tenant_id}:{doc_id}:{chunk_id}:{nonce}".encode("utf-8")
            stego_token = (
                hmac.new(self.secret_key.encode("utf-8"), seed_data, hashlib.sha256)
                .hexdigest()[:16]
                .upper()
            )
            result_text = WatermarkEncoder.inject_watermark(result_text, stego_token)
            active_tokens.append(stego_token)

        # 2. Non-Steganographic Lexical Decoy Injection (if LEXICAL or HYBRID)
        if op_mode in (CanaryMode.LEXICAL, CanaryMode.HYBRID):
            lex_token = self.generate_lexical_token(
                tenant_id=tenant_id,
                doc_id=doc_id,
                chunk_id=chunk_id,
                token_type=token_type,
                session_nonce=session_nonce,
                auto_register=True,
            )
            # Organically append or insert lexical sentinel
            if token_type == "decoy_credential":
                result_text = f'{result_text}\n[Security Notice: Internal credentials for {doc_id} reference: key="{lex_token.token_value}"]'
            elif token_type == "semantic_anchor":
                result_text = f"{result_text} (Reference ID: {lex_token.token_value})"
            else:
                result_text = f"{result_text}\n<!-- {lex_token.token_value} -->"
            active_tokens.append(lex_token.token_value)

        return result_text, active_tokens


class LexicalCanaryMatcher:
    """High-throughput regex and substring scanner for lexical canary sentinels."""

    _CANARY_REF_RE = re.compile(r"\bCANARY-REF-[A-F0-9]{8,16}\b", re.IGNORECASE)
    _SK_CANARY_RE = re.compile(r"\bsk_live_canary_[a-f0-9_\-]{16,40}\b", re.IGNORECASE)

    @classmethod
    def find_lexical_matches(cls, text: str, known_tokens: set[str] | None = None) -> list[str]:
        """Scan text buffer for high-entropy lexical canary patterns or specific token sets."""
        if not text:
            return []
        matches: list[str] = []

        # Exact token matching against known active tokens
        if known_tokens:
            for tok in known_tokens:
                if tok in text:
                    matches.append(tok)

        # Pattern-based matching for un-registered high-entropy canary patterns
        for m in cls._CANARY_REF_RE.finditer(text):
            val = m.group(0)
            if val not in matches:
                matches.append(val)

        for m in cls._SK_CANARY_RE.finditer(text):
            val = m.group(0)
            if val not in matches:
                matches.append(val)

        return matches
