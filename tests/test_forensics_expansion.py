"""Forensics, Exporters, and Vault edge case tests."""

import logging
from unittest.mock import MagicMock, patch

import pytest

from canary_fabric.forensics.certificate import LeakCertificate
from canary_fabric.forensics.exporters import (
    BaseIncidentExporter,
    CEFExporter,
    OpenTelemetryExporter,
    WebhookExporter,
)
from canary_fabric.forensics.vault import IncidentVault


def test_vault_with_disk_file(tmp_path):
    db_file = tmp_path / "test_incidents.db"
    vault = IncidentVault(db_path=str(db_file))

    cert = LeakCertificate(
        certificate_id="cert_disk_1",
        tenant_id="tenant_disk",
        source_doc_id="doc_disk_100",
        source_chunk_id="chunk_disk_0",
        canary_token="TOKEN_DISK_123",
        leak_channel="chat_stream",
        action_taken="BLOCK_AND_SEVER",
    )
    cert.sign("secret_disk")
    vault.record_certificate(cert)

    # Re-open vault from disk
    vault2 = IncidentVault(db_path=str(db_file))
    fetched = vault2.get_certificate("cert_disk_1")
    assert fetched is not None
    assert fetched.certificate_id == "cert_disk_1"
    assert fetched.source_doc_id == "doc_disk_100"

    # Non-existent certificate
    assert vault2.get_certificate("non_existent") is None

    # List incidents with tenant filter and without
    all_records = vault2.list_incidents()
    assert len(all_records) == 1

    tenant_records = vault2.list_incidents(tenant_id="tenant_disk")
    assert len(tenant_records) == 1

    empty_records = vault2.list_incidents(tenant_id="other_tenant")
    assert len(empty_records) == 0


def test_vault_exporter_exception_resilience():
    failing_exporter = MagicMock()
    failing_exporter.export.side_effect = RuntimeError("Exporter failed!")
    vault = IncidentVault(db_path=":memory:", exporters=[failing_exporter])

    cert = LeakCertificate(
        certificate_id="cert_fail_test",
        tenant_id="tenant_x",
        source_doc_id="doc_x",
        source_chunk_id="chunk_0",
        canary_token="TOKEN_X",
        leak_channel="test",
        action_taken="BLOCK_AND_SEVER",
    )
    # Should not raise exception even if exporter raises
    vault.record_certificate(cert)
    assert failing_exporter.export.called


def test_webhook_exporter_sync_and_async():
    # Sync export with exception handling
    exporter = WebhookExporter("http://invalid-nonexistent-domain.test:9999/webhook", signing_secret="key123")
    cert = LeakCertificate(
        certificate_id="cert_wh",
        tenant_id="t1",
        source_doc_id="d1",
        source_chunk_id="c0",
        canary_token="TOK1",
        leak_channel="stream",
        action_taken="BLOCK_AND_SEVER",
    )
    # Shouldn't raise when connection fails
    exporter.export(cert)

    # Sync export with mocked post
    with patch("httpx.Client") as mock_client_cls:
        mock_instance = MagicMock()
        mock_client_cls.return_value.__enter__.return_value = mock_instance
        exporter.export(cert)
        assert mock_instance.post.called


@pytest.mark.asyncio
async def test_webhook_exporter_async():
    exporter = WebhookExporter("http://invalid-nonexistent-domain.test:9999/webhook", signing_secret="key123")
    cert = LeakCertificate(
        certificate_id="cert_wh_async",
        tenant_id="t1",
        source_doc_id="d1",
        source_chunk_id="c0",
        canary_token="TOK1",
        leak_channel="stream",
        action_taken="BLOCK_AND_SEVER",
    )
    # Shouldn't raise when connection fails
    await exporter.aexport(cert)

    # Mocked async post
    with patch("httpx.AsyncClient") as mock_aclient_cls:
        mock_instance = MagicMock()
        mock_instance.post = MagicMock()
        mock_aclient_cls.return_value.__aenter__.return_value = mock_instance
        await exporter.aexport(cert)


def test_cef_exporter_formatting():
    logger = logging.getLogger("test_cef")
    cef = CEFExporter(log_handler=logger)

    cert_severe = LeakCertificate(
        certificate_id="cert_cef_1",
        tenant_id="tenant_sec",
        source_doc_id="doc_pci",
        source_chunk_id="c1",
        canary_token="CANARY_CEF_1",
        leak_channel="proxy",
        action_taken="BLOCK_AND_SEVER",
        prompt_hash="hash_abc_123",
    )
    formatted = cef.format_cef(cert_severe)
    assert "|8|" in formatted
    assert "promptHash=hash_abc_123" in formatted
    assert "canaryToken=CANARY_CEF_1" in formatted

    cert_log_only = LeakCertificate(
        certificate_id="cert_cef_2",
        tenant_id="tenant_sec",
        source_doc_id="doc_pci",
        source_chunk_id="c1",
        canary_token="CANARY_CEF_2",
        leak_channel="proxy",
        action_taken="LOG_ONLY",
        prompt_hash=None,
    )
    formatted_log = cef.format_cef(cert_log_only)
    assert "|5|" in formatted_log
    assert "promptHash" not in formatted_log


def test_opentelemetry_exporter():
    mock_tracer = MagicMock()
    mock_span = MagicMock()
    mock_tracer.start_as_current_span.return_value.__enter__.return_value = mock_span

    otel = OpenTelemetryExporter(tracer=mock_tracer)
    cert = LeakCertificate(
        certificate_id="cert_otel",
        tenant_id="t_otel",
        source_doc_id="d_otel",
        source_chunk_id="c_otel",
        canary_token="TOKEN_OTEL",
        leak_channel="test",
        action_taken="BLOCK_AND_SEVER",
    )
    otel.export(cert)
    assert mock_span.set_attribute.called
    assert mock_span.add_event.called

    # Test ImportError fallback when tracer is None and opentelemetry is absent
    with patch.dict("sys.modules", {"opentelemetry": None}):
        otel_none = OpenTelemetryExporter(tracer=None)
        otel_none.export(cert)  # Should not raise


@pytest.mark.asyncio
async def test_base_incident_exporter_aexport():
    class DummyExporter(BaseIncidentExporter):
        def __init__(self):
            self.exported = False

        def export(self, certificate: LeakCertificate) -> None:
            self.exported = True

    dummy = DummyExporter()
    cert = LeakCertificate(
        certificate_id="c_base",
        tenant_id="t",
        source_doc_id="d",
        source_chunk_id="c",
        canary_token="TOK",
        leak_channel="ch",
        action_taken="ACT",
    )
    await dummy.aexport(cert)
    assert dummy.exported is True


def test_leak_certificate_verify_unsigned():
    cert = LeakCertificate(
        certificate_id="c_unsign",
        tenant_id="t",
        source_doc_id="d",
        source_chunk_id="c",
        canary_token="TOK",
        leak_channel="ch",
        action_taken="ACT",
    )
    assert cert.verify("secret") is False
