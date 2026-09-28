"""Tests for synthetic honeytokens and decoy registry."""

from canary_fabric.core.honeytoken import (
    HoneytokenGenerator,
    HoneytokenRegistry,
    HoneytokenType,
)


def test_generate_and_match_honeytoken():
    reg = HoneytokenRegistry()
    gen = HoneytokenGenerator(registry=reg)

    ht_key = gen.generate(HoneytokenType.API_KEY, "tenant_1", "doc_secrets", "Admin API Key")
    ht_db = gen.generate(HoneytokenType.DB_URI, "tenant_1", "doc_db", "Postgres URI")

    assert ht_key.value.startswith("sk_live_canary_")
    assert "canary_sec_app" in ht_db.value

    # Test detection in text
    leak_prompt = f"Here is the database URL: {ht_db.value} and key {ht_key.value}"
    matches = reg.find_matches(leak_prompt)
    assert len(matches) == 2
    matched_ids = [m.token_id for m in matches]
    assert ht_key.token_id in matched_ids
    assert ht_db.token_id in matched_ids


def test_no_false_positives():
    reg = HoneytokenRegistry()
    gen = HoneytokenGenerator(registry=reg)
    gen.generate(HoneytokenType.EMAIL, "tenant_1", "doc_email")

    normal_text = "Standard internal communication between employees."
    assert reg.find_matches(normal_text) == []
