"""Tests for keyed semantic micro-synonym steganography."""

from canary_fabric.core.synonyms import SemanticWatermarker


def test_semantic_watermarker_injection_and_detection():
    watermarker = SemanticWatermarker(min_slots_threshold=4, confidence_threshold=0.90)

    original_text = (
        "We plan to acquire Beta Corp and quickly conclude the merger. "
        "It is crucial to use adequate resources and verify all financial records. "
        "Engineers will strive to build the new platform promptly."
    )

    secret = "production_canary_secret_key"
    tenant = "enterprise_corp"
    doc_id = "doc_merger_confidential"

    watermarked_text, modified_count = watermarker.inject(
        text=original_text,
        secret_key=secret,
        tenant_id=tenant,
        doc_id=doc_id,
    )

    # Text should remain natural and readable
    assert len(watermarked_text) > 0

    # Detection against correct credentials
    result = watermarker.detect(
        text=watermarked_text,
        secret_key=secret,
        tenant_id=tenant,
        doc_id=doc_id,
    )

    assert result.is_detected is True
    assert result.confidence >= 0.90
    assert result.matching_slots == result.total_slots
    assert result.total_slots >= 4


def test_semantic_watermarker_resilience_to_unicode_stripping():
    """Verify that even if an attacker strips all zero-width unicode, semantic watermarks survive."""
    watermarker = SemanticWatermarker(min_slots_threshold=4)

    text = (
        "Please provide the initial report and confirm the budget. "
        "We must select a team to construct the system and notify the board."
    )
    secret = "secret_key"
    tenant = "tenant_test"
    doc = "doc_1"

    watermarked, _ = watermarker.inject(text, secret, tenant, doc)

    # Simulate zero-width character stripping (it contains none anyway, but test survival)
    stripped = "".join(c for c in watermarked if ord(c) < 128)

    res = watermarker.detect(stripped, secret, tenant, doc)
    assert res.is_detected is True
    assert res.matching_slots == res.total_slots


def test_semantic_watermarker_unwatermarked_no_false_positive():
    watermarker = SemanticWatermarker(min_slots_threshold=4)

    # Random natural text with arbitrary words
    random_text = (
        "We might buy a car and soon finish the trip. "
        "It is important to need sufficient help and show the way."
    )

    res = watermarker.detect(
        text=random_text,
        secret_key="some_key",
        tenant_id="tenant",
        doc_id="doc",
    )
    assert res.is_detected is False