# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""Multi-channel incident alerting and SIEM dispatcher."""

import asyncio
from collections.abc import Callable
from typing import Any

import httpx
from rich.console import Console

from canary_fabric.forensics.certificate import LeakCertificate

console = Console()


class IncidentAlerter:
    """Dispatches tripwire alerts to consoles, webhooks, Slack, and SIEMs."""

    def __init__(
        self,
        webhook_urls: list[str] | None = None,
        enable_console: bool = True,
    ) -> None:
        self.webhook_urls = webhook_urls or []
        self.enable_console = enable_console
        self._custom_handlers: list[Callable[[LeakCertificate], Any]] = []

    def add_handler(self, handler: Callable[[LeakCertificate], Any]) -> None:
        self._custom_handlers.append(handler)

    async def alert(self, cert: LeakCertificate) -> None:
        """Dispatch incident alerts asynchronously."""
        if self.enable_console:
            self._log_console(cert)

        # Call custom handlers
        for handler in self._custom_handlers:
            try:
                res = handler(cert)
                if asyncio.iscoroutine(res):
                    await res
            except Exception as e:
                console.print(f"[bold red]Alerter handler error: {e}[/bold red]")

        # Send HTTP webhooks
        if self.webhook_urls:
            async with httpx.AsyncClient(timeout=3.0) as client:
                payload = cert.model_dump()
                for url in self.webhook_urls:
                    try:
                        await client.post(url, json=payload)
                    except Exception as e:
                        console.print(
                            f"[bold red]Failed to dispatch webhook to {url}: {e}[/bold red]"
                        )

    def _log_console(self, cert: LeakCertificate) -> None:
        console.print(
            f"[bold red]🚨 [CANARYFABRIC TRIPWIRE ALERT] 🚨[/bold red]\n"
            f"  • Incident ID: [yellow]{cert.certificate_id}[/yellow]\n"
            f"  • Tenant: [cyan]{cert.tenant_id}[/cyan]\n"
            f"  • Document ID: [green]{cert.source_doc_id}[/green] (Chunk: {cert.source_chunk_id})\n"
            f"  • Canary Signature: [magenta]{cert.canary_token}[/magenta]\n"
            f"  • Action Taken: [bold]{cert.action_taken}[/bold]\n"
            f"  • Timestamp: {cert.timestamp}"
        )
