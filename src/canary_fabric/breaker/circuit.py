"""Circuit breaker and active egress gate for canary tripwire detection."""

import secrets
from dataclasses import dataclass
from enum import Enum

from canary_fabric.forensics.certificate import LeakCertificate
from canary_fabric.forensics.vault import IncidentVault


class BreakerAction(str, Enum):
    BLOCK_AND_SEVER = "block_and_sever"
    REDACT_AND_CONTINUE = "redact_and_continue"
    LOG_ONLY = "log_only"


class BreakerState(str, Enum):
    CLOSED = "closed"  # Normal operation, monitoring
    TRIPPED = "tripped"  # Active tripwire event occurred


@dataclass
class TripwireEvent:
    canary_token: str
    tenant_id: str
    source_doc_id: str
    source_chunk_id: str
    matched_text_snippet: str
    user_session_id: str | None = None
    prompt_text: str | None = None


class CircuitBreaker:
    """Active egress gate that intercepts leaked canaries and trips the circuit."""

    def __init__(
        self,
        secret_key: str,
        default_action: BreakerAction = BreakerAction.BLOCK_AND_SEVER,
        vault: IncidentVault | None = None,
    ) -> None:
        self.secret_key = secret_key
        self.default_action = default_action
        self.vault = vault or IncidentVault(":memory:")
        self.state = BreakerState.CLOSED

    def handle_tripwire(
        self,
        event: TripwireEvent,
        action: BreakerAction | None = None,
    ) -> tuple[LeakCertificate, str]:
        """Trigger circuit breaker, generate forensic certificate, and return safe replacement message."""
        self.state = BreakerState.TRIPPED
        effective_action = action or self.default_action

        incident_id = f"cf_inc_{secrets.token_hex(6)}"

        prompt_hash = None
        if event.prompt_text:
            import hashlib

            prompt_hash = hashlib.sha256(event.prompt_text.encode("utf-8")).hexdigest()

        cert = LeakCertificate(
            certificate_id=incident_id,
            tenant_id=event.tenant_id,
            source_doc_id=event.source_doc_id,
            source_chunk_id=event.source_chunk_id,
            canary_token=event.canary_token,
            action_taken=effective_action.value.upper(),
            user_session_id=event.user_session_id,
            prompt_hash=prompt_hash,
        )
        cert.sign(self.secret_key)
        self.vault.record_certificate(cert)

        if effective_action == BreakerAction.BLOCK_AND_SEVER:
            replacement_msg = (
                f"\n[SECURITY ALERT: CanaryFabric Circuit Breaker Tripped - "
                f"Confidential data exfiltration prevented. Incident ID: {incident_id}]"
            )
        elif effective_action == BreakerAction.REDACT_AND_CONTINUE:
            replacement_msg = f"[REDACTED_CONFIDENTIAL_CONTENT_{incident_id}]"
        else:
            replacement_msg = event.matched_text_snippet

        return cert, replacement_msg
