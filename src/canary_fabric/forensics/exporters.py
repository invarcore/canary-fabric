"""Enterprise SIEM, Webhook, and Observability Exporters for Canary Fabric."""

import hashlib
import hmac
import logging
from abc import ABC, abstractmethod
from typing import Any

import httpx

from canary_fabric.forensics.certificate import LeakCertificate

logger = logging.getLogger("canary_fabric.forensics.exporters")


class BaseIncidentExporter(ABC):
    """Abstract base class for incident telemetric dispatchers."""

    @abstractmethod
    def export(self, certificate: LeakCertificate) -> None:
        """Synchronously dispatch the leak certificate."""
        pass

    async def aexport(self, certificate: LeakCertificate) -> None:
        """Asynchronously dispatch the leak certificate."""
        self.export(certificate)


class WebhookExporter(BaseIncidentExporter):
    """Dispatches cryptographic leak certificates to HTTPS endpoints (Slack, PagerDuty, SIEM)."""

    def __init__(
        self,
        endpoint_url: str,
        signing_secret: str | None = None,
        timeout: float = 5.0,
    ) -> None:
        self.endpoint_url = endpoint_url
        self.signing_secret = signing_secret
        self.timeout = timeout

    def _generate_signature(self, payload_bytes: bytes) -> str:
        if not self.signing_secret:
            return ""
        return hmac.new(self.signing_secret.encode(), payload_bytes, hashlib.sha256).hexdigest()

    def export(self, certificate: LeakCertificate) -> None:
        """Synchronously POST certificate payload to webhook endpoint."""
        payload_bytes = certificate.model_dump_json().encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.signing_secret:
            headers["X-Canary-Signature"] = f"sha256={self._generate_signature(payload_bytes)}"

        try:
            with httpx.Client(timeout=self.timeout) as client:
                client.post(self.endpoint_url, content=payload_bytes, headers=headers)
        except Exception as e:
            logger.warning("Failed to dispatch webhook incident alert to %s: %s", self.endpoint_url, e)

    async def aexport(self, certificate: LeakCertificate) -> None:
        """Asynchronously POST certificate payload to webhook endpoint."""
        payload_bytes = certificate.model_dump_json().encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.signing_secret:
            headers["X-Canary-Signature"] = f"sha256={self._generate_signature(payload_bytes)}"

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                await client.post(self.endpoint_url, content=payload_bytes, headers=headers)
        except Exception as e:
            logger.warning("Failed to async dispatch webhook alert to %s: %s", self.endpoint_url, e)


class CEFExporter(BaseIncidentExporter):
    """Formats and exports incidents in Common Event Format (CEF) for Splunk, Sentinel, and QRadar."""

    def __init__(self, log_handler: logging.Logger | None = None) -> None:
        self.log = log_handler or logging.getLogger("canary_fabric.cef")

    def format_cef(self, certificate: LeakCertificate) -> str:
        """Generate a valid ArcSight CEF string for the incident."""
        severity = 8 if certificate.action_taken in ("SEVER_SOCKET", "BLOCK_AND_SEVER") else 5
        ext_fields = [
            f"srcDoc={certificate.source_doc_id}",
            f"chunkId={certificate.source_chunk_id}",
            f"canaryToken={certificate.canary_token}",
            f"tenant={certificate.tenant_id}",
            f"channel={certificate.leak_channel}",
            f"act={certificate.action_taken}",
            f"certId={certificate.certificate_id}",
        ]
        if certificate.prompt_hash:
            ext_fields.append(f"promptHash={certificate.prompt_hash}")

        return (
            f"CEF:0|CanaryFabric|CanaryFabric|0.1.0|TRIPWIRE_TRIGGERED|"
            f"RAG Data Exfiltration Attempt Intercepted|{severity}|" + " ".join(ext_fields)
        )

    def export(self, certificate: LeakCertificate) -> None:
        cef_string = self.format_cef(certificate)
        self.log.warning(cef_string)


class OpenTelemetryExporter(BaseIncidentExporter):
    """Produces OpenTelemetry distributed tracing Spans and security metrics if available."""

    def __init__(self, tracer: Any = None) -> None:
        self.tracer = tracer

    def export(self, certificate: LeakCertificate) -> None:
        # Gracefully handle environments with or without opentelemetry installed
        try:
            from opentelemetry import trace

            active_tracer = self.tracer or trace.get_tracer("canary_fabric")
            with active_tracer.start_as_current_span("canary_tripwire_incident") as span:
                span.set_attribute("security.incident_id", certificate.incident_id)
                span.set_attribute("security.canary_token", certificate.canary_token)
                span.set_attribute("security.tenant_id", certificate.tenant_id)
                span.set_attribute("security.action_taken", certificate.action_taken)
                span.add_event(
                    "tripwire_triggered",
                    {
                        "source_doc_id": certificate.source_doc_id,
                        "leak_channel": certificate.leak_channel,
                    },
                )
        except ImportError:
            # OpenTelemetry not installed in runtime; no-op
            pass