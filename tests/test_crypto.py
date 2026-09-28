"""Tests for cryptographic HMAC derivation and payload signing."""

from canary_fabric.core.crypto import (
    derive_canary_token,
    sign_payload,
    verify_signature,
)


def test_derive_canary_token_deterministic():
    secret = "test_secret_key"
    token1 = derive_canary_token(secret, "tenant_a", "doc_1", "chunk_0", "nonce_123")
    token2 = derive_canary_token(secret, "tenant_a", "doc_1", "chunk_0", "nonce_123")
    assert token1 == token2
    assert len(token1) == 16  # 8 bytes hex


def test_derive_canary_token_divergence():
    secret = "test_secret_key"
    t1 = derive_canary_token(secret, "tenant_a", "doc_1", "chunk_0", "nonce_1")
    t2 = derive_canary_token(secret, "tenant_b", "doc_1", "chunk_0", "nonce_1")
    t3 = derive_canary_token(secret, "tenant_a", "doc_2", "chunk_0", "nonce_1")
    assert t1 != t2
    assert t1 != t3


def test_sign_and_verify_payload():
    secret = "super_secret"
    payload = {"incident_id": "inc_123", "tenant_id": "tenant_x", "amount": 500}
    sig = sign_payload(secret, payload)
    assert isinstance(sig, str)
    assert len(sig) == 64  # SHA256 hex length
    assert verify_signature(secret, payload, sig) is True

    # Tampered payload fails
    tampered = dict(payload)
    tampered["amount"] = 999
    assert verify_signature(secret, tampered, sig) is False
