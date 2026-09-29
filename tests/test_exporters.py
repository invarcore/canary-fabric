"""Tests for enterprise SIEM and telemetry exporters."""

from canary_fabric.forensics.certificate import LeakCertificate
from canary_fabric.forensics.exporters import BaseIncidentExporter, CEFExporter, WebhookExporter
from canary_fabric.forensics.vault import IncidentVault


class MockCollectorExporter(BaseIncidentExporter):
    def __init__(self):
        self.collected = []

    def export(self, certificate: LeakCertificate) -> None:
        self.collected.append(certificate)


def test_cef_exporter_formatting():
    exporter = CEFExporter()
    cert = LeakCertificate(
        certificate_id="cert_123",
        tenant_id="tenant_acme",
        source_doc_id="financial_forecast",
        source_chunk_id="chunk_4",
        canary_token="A1B2C3D4E5F67890",
        leak_channel="STREAMING_SSE",
        action_taken="BLOCK_AND_SEVER",
        signature="dummy_signature",
    )

    cef = exporter.format_cef(cert)
    assert cef.startswith("CEF:0|CanaryFabric|CanaryFabric|0.1.0|TRIPWIRE_TRIGGERED|")
    assert "srcDoc=financial_forecast" in cef
    assert "chunkId=chunk_4" in cef
    assert "canaryToken=A1B2C3D4E5F67890" in cef
    assert "tenant=tenant_acme" in cef
    assert "act=BLOCK_AND_SEVER" in cef


def test_webhook_exporter_hmac_signature():
    exporter = WebhookExporter(
        endpoint_url="https://siem.corp.internal/hooks/canary",
        signing_secret="webhook_super_secret_key",
    )

    payload = b'{"test": "data"}'
    sig = exporter._generate_signature(payload)
    assert len(sig) == 64  # SHA-256 hex length
    assert sig == exporter._generate_signature(payload)


def test_vault_dispatches_to_exporters():
    collector = MockCollectorExporter()
    vault = IncidentVault(exporters=[collector])

    cert = LeakCertificate(
        certificate_id="cert_vault_test",
        tenant_id="tenant_alpha",
        source_doc_id="doc_x",
        source_chunk_id="chunk_y",
        canary_token="9999AAAA8888BBBB",
        leak_channel="TOOL_CALL",
        action_taken="BLOCK_AND_SEVER",
        signature="test_sig",
    )

    vault.record_certificate(cert)

    assert len(collector.collected) == 1
    assert collector.collected[0].certificate_id == "cert_vault_test"
