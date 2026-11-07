# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""Unit & Integration tests for Configurable Non-Steganographic Lexical Fallback Mode."""

import re

from canary_fabric.adapters.knowledge_fabric import KnowledgeFabricCanaryAdapter
from canary_fabric.breaker.circuit import BreakerAction, CircuitBreaker
from canary_fabric.core.honeytoken import HoneytokenRegistry
from canary_fabric.core.lexical import (
    CanaryMode,
    LexicalCanaryInjector,
    LexicalCanaryMatcher,
)
from canary_fabric.proxy.streamer import SlidingWindowStreamBuffer, StreamWatcher


def test_lexical_injector_modes():
    """Verify injector behavior across STEGO, LEXICAL, and HYBRID modes."""
    registry = HoneytokenRegistry()
    injector = LexicalCanaryInjector(secret_key="test_secret_key", honeytoken_registry=registry)

    base_text = "The quarterly financial projections show 18% growth in cloud services."

    # 1. STEGO mode: Only zero-width Unicode characters, no visible lexical sentinels
    stego_text, stego_tokens = injector.inject(
        text=base_text,
        tenant_id="acme",
        doc_id="finance_q4",
        chunk_id="chunk_1",
        mode=CanaryMode.STEGO,
    )
    assert len(stego_tokens) == 1
    assert "sk_live" not in stego_text
    assert "CANARY-REF" not in stego_text
    assert len(stego_text) > len(base_text)  # Contains zero-width chars

    # 2. LEXICAL mode: No zero-width characters, contains high-entropy credential or anchor
    lex_text, lex_tokens = injector.inject(
        text=base_text,
        tenant_id="acme",
        doc_id="finance_q4",
        chunk_id="chunk_2",
        mode=CanaryMode.LEXICAL,
        token_type="decoy_credential",
    )
    assert len(lex_tokens) == 1
    assert "sk_live_canary_" in lex_text
    # Verify zero-width stripped version matches original length + decoy length
    clean_lex = re.sub(r"[\u200b-\u200d\ufeff\u200e\u200f]", "", lex_text)
    assert len(clean_lex) == len(lex_text)  # Zero zero-width characters injected

    # 3. HYBRID mode: Injects both steganographic and lexical sentinels
    hybrid_text, hybrid_tokens = injector.inject(
        text=base_text,
        tenant_id="acme",
        doc_id="finance_q4",
        chunk_id="chunk_3",
        mode=CanaryMode.HYBRID,
        token_type="semantic_anchor",
    )
    assert len(hybrid_tokens) == 2  # (stego_token, lexical_token)
    assert "CANARY-REF-" in hybrid_text
    assert len(hybrid_text) > len(re.sub(r"[\u200b-\u200d\ufeff\u200e\u200f]", "", hybrid_text))


def test_sanitizer_unicode_stripping_attack_mitigated():
    """Prove that lexical fallback catches leaks even when upstream sanitizers strip Unicode.

    Simulates an adversary or proxy stripping [\\u200B-\\u200D\\uFEFF\\u200E\\u200F].
    """
    secret = "k8s_super_secret_audit_key"
    registry = HoneytokenRegistry()
    injector = LexicalCanaryInjector(secret_key=secret, honeytoken_registry=registry)

    confidential_doc = "Confidential merge target: CyberDyne Systems valuation is $4.5B."

    # Generate HYBRID protected text
    hybrid_text, active_tokens = injector.inject(
        text=confidential_doc,
        tenant_id="defense_dept",
        doc_id="doc_merger",
        chunk_id="c_01",
        mode=CanaryMode.HYBRID,
        token_type="decoy_credential",
    )

    # Adversary strips all Unicode zero-width characters
    sanitized_text = re.sub(r"[\u200b-\u200d\ufeff\u200e\u200f]", "", hybrid_text)

    # Case A: Watcher in STEGO-only mode fails to detect stripped stream (demonstrating the vulnerability)
    breaker_stego = CircuitBreaker(secret, default_action=BreakerAction.BLOCK_AND_SEVER)
    watcher_stego = StreamWatcher(
        circuit_breaker=breaker_stego,
        honeytoken_registry=registry,
        active_canary_tokens=set(active_tokens),
        canary_mode=CanaryMode.STEGO,
    )
    chunks = [sanitized_text[i : i + 8] for i in range(0, len(sanitized_text), 8)]
    out_stego = list(watcher_stego.wrap_sync_stream(iter(chunks)))
    assert "".join(out_stego) == sanitized_text
    assert breaker_stego.state.value == "closed"  # Bypassed!

    # Case B: Watcher in HYBRID or LEXICAL mode catches the stripped stream via the lexical fallback!
    breaker_hybrid = CircuitBreaker(secret, default_action=BreakerAction.BLOCK_AND_SEVER)
    watcher_hybrid = StreamWatcher(
        circuit_breaker=breaker_hybrid,
        honeytoken_registry=registry,
        active_canary_tokens=set(active_tokens),
        canary_mode=CanaryMode.HYBRID,
    )
    out_hybrid = list(watcher_hybrid.wrap_sync_stream(iter(chunks)))
    combined_hybrid = "".join(out_hybrid)
    assert "SECURITY ALERT: CanaryFabric Circuit Breaker Tripped" in combined_hybrid
    assert breaker_hybrid.state.value == "tripped"  # Mitigated!


def test_lexical_sliding_lookahead_zero_leakage():
    """Verify that SlidingWindowStreamBuffer holdback prevents partial credential leakage."""
    breaker = CircuitBreaker("secret_key", default_action=BreakerAction.BLOCK_AND_SEVER)
    registry = HoneytokenRegistry()
    injector = LexicalCanaryInjector("secret_key", honeytoken_registry=registry)

    raw_doc = "Customer SSN data is stored in AWS S3."
    _, tokens = injector.inject(
        text=raw_doc,
        tenant_id="finance",
        doc_id="ssn_records",
        chunk_id="chunk_0",
        mode=CanaryMode.LEXICAL,
        token_type="decoy_credential",
    )
    target_token = tokens[0]  # e.g. sk_live_canary_...

    buffer = SlidingWindowStreamBuffer(
        circuit_breaker=breaker,
        honeytoken_registry=registry,
        active_canary_tokens=set(tokens),
        lookahead_window=32,
        canary_mode=CanaryMode.LEXICAL,
    )

    # Stream the token letter by letter
    leaked_so_far = []
    for char in f"Prefix text: {target_token} suffix data.":
        safe_chunk, tripped, _ = buffer.scan_chunk(char)
        if safe_chunk:
            leaked_so_far.append(safe_chunk)
        if tripped:
            break

    emitted_stream = "".join(leaked_so_far)
    # The actual canary secret MUST NOT appear in the emitted stream prior to circuit sever
    assert target_token not in emitted_stream
    assert breaker.state.value == "tripped"


def test_knowledge_fabric_multi_mode_adaptation():
    """Verify KnowledgeFabricCanaryAdapter handles STEGO and HYBRID modes with hash sync."""
    adapter = KnowledgeFabricCanaryAdapter(secret_key="kf_key")

    items = [
        {
            "document_uri": "s3://internal/reports/payroll.txt",
            "chunk_id": "chunk_0",
            "snippet": "Executive payroll figures for Q4.",
            "provenance_hash": "placeholder_hash",
        }
    ]

    # Watermark in HYBRID mode
    wm_items, tokens = adapter.watermark_evidence_package(
        items, tenant_id="t_hr", mode=CanaryMode.HYBRID
    )
    assert len(wm_items) == 1
    assert len(tokens) == 2  # (stego, lexical)
    assert "canary" in wm_items[0]["snippet"].lower()
    # Provenance hash should be updated symmetrically to the new snippet text
    import hashlib

    expected_hash = hashlib.sha256(wm_items[0]["snippet"].encode("utf-8")).hexdigest()
    assert wm_items[0]["provenance_hash"] == expected_hash
    assert wm_items[0]["chunk_hash"] == expected_hash


def test_lexical_matcher_standalone():
    """Test pattern-based matching for unregistered high-entropy canaries."""
    text = "Here is the reference code: CANARY-REF-7F8A9B0C1D2E and nothing else."
    matches = LexicalCanaryMatcher.find_lexical_matches(text)
    assert len(matches) == 1
    assert matches[0] == "CANARY-REF-7F8A9B0C1D2E"
