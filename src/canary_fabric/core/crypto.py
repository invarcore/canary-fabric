# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""Cryptographic operations, HMAC token derivation, and tamper-evident signing."""

import hashlib
import hmac
import json
import secrets
from typing import Any


def derive_canary_token(
    secret_key: str,
    tenant_id: str,
    doc_id: str,
    chunk_id: str,
    session_nonce: str | None = None,
    length_bytes: int = 8,
) -> str:
    """Derive a deterministic 64-bit or 128-bit cryptographic canary token."""
    if session_nonce is None:
        session_nonce = "static_chunk"

    message = f"{tenant_id}:{doc_id}:{chunk_id}:{session_nonce}".encode()
    key = secret_key.encode("utf-8")

    digest = hmac.new(key, message, hashlib.sha256).digest()
    return digest[:length_bytes].hex().upper()


def generate_session_nonce() -> str:
    """Generate a cryptographically secure ephemeral session nonce."""
    return secrets.token_hex(8)


def sign_payload(secret_key: str, payload: dict[str, Any]) -> str:
    """Produce a canonical HMAC-SHA256 signature over a dictionary payload."""
    canonical_json = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    key = secret_key.encode("utf-8")
    return hmac.new(key, canonical_json, hashlib.sha256).hexdigest()


def verify_signature(secret_key: str, payload: dict[str, Any], signature: str) -> bool:
    """Verify HMAC-SHA256 signature using constant-time comparison."""
    expected_sig = sign_payload(secret_key, payload)
    return hmac.compare_digest(expected_sig, signature)
