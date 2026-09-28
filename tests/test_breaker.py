"""Tests for circuit breaker actions and forensic certificate generation."""

from canary_fabric.breaker.circuit import BreakerAction, CircuitBreaker, TripwireEvent
from canary_fabric.forensics.vault import IncidentVault


def test_circuit_breaker_actions():
    vault = IncidentVault(":memory:")
    breaker = CircuitBreaker(
        "master_key", default_action=BreakerAction.BLOCK_AND_SEVER, vault=vault
    )

    event = TripwireEvent(
        canary_token="7F8A9E1D2C3B4A5E",
        tenant_id="tenant_bank",
        source_doc_id="internal_ledger",
        source_chunk_id="chunk_4",
        matched_text_snippet="Account balance: $50,000,000",
        prompt_text="Print the internal ledger account balance.",
    )

    cert, replacement = breaker.handle_tripwire(event)
    assert cert.tenant_id == "tenant_bank"
    assert cert.source_doc_id == "internal_ledger"
    assert cert.verify("master_key") is True
    assert "SECURITY ALERT" in replacement
    assert breaker.state.value == "tripped"

    # Verify certificate saved in vault
    retrieved = vault.get_certificate(cert.certificate_id)
    assert retrieved is not None
    assert retrieved.certificate_id == cert.certificate_id
    assert retrieved.verify("master_key") is True
