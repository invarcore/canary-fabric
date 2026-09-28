"""Cryptographic Leak Certificates for tamper-evident data leak forensic attribution."""

from datetime import UTC, datetime

from pydantic import BaseModel, Field

from canary_fabric.core.crypto import sign_payload, verify_signature


class LeakCertificate(BaseModel):
    """Cryptographically signed forensic certificate representing an exfiltration tripwire event."""

    certificate_id: str = Field(
        description="Unique identifier for the forensic leak incident"
    )
    timestamp: str = Field(default_factory=lambda: datetime.now(UTC).isoformat())
    tenant_id: str = Field(description="Tenant or organization identifier")
    source_doc_id: str = Field(
        description="Identifier of the compromised source document"
    )
    source_chunk_id: str = Field(
        description="Identifier of the specific retrieved chunk"
    )
    canary_token: str = Field(
        description="Hex canary signature or honeytoken value detected"
    )
    leak_channel: str = Field(
        default="llm_sse_stream",
        description="Egress channel (e.g. llm_sse_stream, tool_parameter)",
    )
    action_taken: str = Field(
        default="SOCKET_TERMINATED",
        description="Breaker action (e.g. SOCKET_TERMINATED, REDACTED)",
    )
    user_session_id: str | None = Field(
        default=None, description="Optional user session nonce"
    )
    prompt_hash: str | None = Field(
        default=None, description="SHA-256 hash of the triggering user prompt"
    )
    signature: str = Field(
        default="",
        description="HMAC-SHA256 signature guaranteeing certificate non-repudiation",
    )

    def sign(self, secret_key: str) -> "LeakCertificate":
        """Compute and set the HMAC-SHA256 signature for this certificate."""
        payload = self.model_dump(exclude={"signature"})
        self.signature = sign_payload(secret_key, payload)
        return self

    def verify(self, secret_key: str) -> bool:
        """Verify the authenticity and integrity of this certificate."""
        if not self.signature:
            return False
        payload = self.model_dump(exclude={"signature"})
        return verify_signature(secret_key, payload, self.signature)

    def to_canonical_json(self) -> str:
        """Export certificate as formatted JSON for SIEM or auditor review."""
        return self.model_dump_json(indent=2)
