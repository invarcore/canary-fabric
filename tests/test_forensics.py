"""Tests for LeakCertificate cryptographic verification and SQLite WAL IncidentVault."""

from canary_fabric.forensics.certificate import LeakCertificate
from canary_fabric.forensics.vault import IncidentVault


def test_leak_certificate_tamper_proofing():
    cert = LeakCertificate(
        certificate_id="cf_inc_001",
        tenant_id="tenant_a",
        source_doc_id="payroll_q3",
        source_chunk_id="chunk_1",
        canary_token="9F8E7D6C5B4A3A21",
    )
    cert.sign("secret_audit_key")
    assert cert.verify("secret_audit_key") is True
    assert cert.verify("wrong_key") is False

    # Tampering with tenant_id breaks signature
    cert.tenant_id = "tenant_b"
    assert cert.verify("secret_audit_key") is False


def test_incident_vault_querying():
    vault = IncidentVault(":memory:")

    cert1 = LeakCertificate(
        certificate_id="cf_inc_101",
        tenant_id="tenant_alpha",
        source_doc_id="doc_1",
        source_chunk_id="chunk_0",
        canary_token="AAAA1111",
    ).sign("key")

    cert2 = LeakCertificate(
        certificate_id="cf_inc_102",
        tenant_id="tenant_beta",
        source_doc_id="doc_2",
        source_chunk_id="chunk_0",
        canary_token="BBBB2222",
    ).sign("key")

    vault.record_certificate(cert1)
    vault.record_certificate(cert2)

    all_incidents = vault.list_incidents()
    assert len(all_incidents) == 2

    alpha_incidents = vault.list_incidents(tenant_id="tenant_alpha")
    assert len(alpha_incidents) == 1
    assert alpha_incidents[0].certificate_id == "cf_inc_101"
