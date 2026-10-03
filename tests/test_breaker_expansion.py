"""Alerter and CircuitBreaker action tests."""

from unittest.mock import MagicMock, patch

import pytest

from canary_fabric.breaker.alerter import IncidentAlerter
from canary_fabric.breaker.circuit import BreakerAction, CircuitBreaker, TripwireEvent
from canary_fabric.forensics.certificate import LeakCertificate


@pytest.mark.asyncio
async def test_incident_alerter_handlers_and_webhooks():
    alerter = IncidentAlerter(
        webhook_urls=["http://test-webhook.invalid/alert"],
        enable_console=True,
    )

    sync_called = False
    async_called = False

    def sync_handler(cert: LeakCertificate):
        nonlocal sync_called
        sync_called = True

    async def async_handler(cert: LeakCertificate):
        nonlocal async_called
        async_called = True

    def error_handler(cert: LeakCertificate):
        raise ValueError("Simulated handler crash")

    alerter.add_handler(sync_handler)
    alerter.add_handler(async_handler)
    alerter.add_handler(error_handler)

    cert = LeakCertificate(
        certificate_id="cert_alert_test",
        tenant_id="tenant_alert",
        source_doc_id="doc_alert",
        source_chunk_id="chunk_0",
        canary_token="TOKEN_ALERT",
        leak_channel="proxy",
        action_taken="BLOCK_AND_SEVER",
    )

    # Dispatch alerts with exception on webhook call (should not throw)
    await alerter.alert(cert)

    assert sync_called is True
    assert async_called is True


@pytest.mark.asyncio
async def test_incident_alerter_successful_webhook():
    alerter = IncidentAlerter(
        webhook_urls=["http://valid-webhook.internal/alert"],
        enable_console=False,
    )

    cert = LeakCertificate(
        certificate_id="cert_alert_2",
        tenant_id="tenant_alert",
        source_doc_id="doc_alert",
        source_chunk_id="chunk_0",
        canary_token="TOKEN_ALERT_2",
        leak_channel="proxy",
        action_taken="BLOCK_AND_SEVER",
    )

    with patch("httpx.AsyncClient") as mock_client_cls:
        mock_instance = MagicMock()
        mock_instance.post = MagicMock()
        mock_client_cls.return_value.__aenter__.return_value = mock_instance
        await alerter.alert(cert)


def test_circuit_breaker_actions():
    # Test REDACT_AND_CONTINUE
    breaker_redact = CircuitBreaker(
        secret_key="secret",
        default_action=BreakerAction.REDACT_AND_CONTINUE,
    )
    event_redact = TripwireEvent(
        canary_token="TOKEN_R",
        tenant_id="tenant_r",
        source_doc_id="doc_r",
        source_chunk_id="chunk_r",
        matched_text_snippet="confidential text segment",
    )
    cert_r, replacement_r = breaker_redact.handle_tripwire(event_redact)
    assert cert_r.action_taken == "REDACT_AND_CONTINUE"
    assert "[REDACTED_CONFIDENTIAL_CONTENT_" in replacement_r

    # Test LOG_ONLY
    breaker_log = CircuitBreaker(
        secret_key="secret",
        default_action=BreakerAction.LOG_ONLY,
    )
    event_log = TripwireEvent(
        canary_token="TOKEN_L",
        tenant_id="tenant_l",
        source_doc_id="doc_l",
        source_chunk_id="chunk_l",
        matched_text_snippet="unaltered text snippet",
    )
    cert_l, replacement_l = breaker_log.handle_tripwire(event_log)
    assert cert_l.action_taken == "LOG_ONLY"
    assert replacement_l == "unaltered text snippet"
