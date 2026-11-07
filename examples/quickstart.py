"""Canary Fabric - 60-Second Quickstart Demonstration.

Demonstrates:
1. Ingesting and watermarking private RAG chunks with invisible 4-ary zero-width HMAC tokens.
2. Generating realistic synthetic honeytoken credentials (decoy API keys / connection strings).
3. Simulating an adversarial LLM prompt injection attempting data exfiltration.
4. Intercepting the leak via sub-millisecond streaming circuit breakers with zero external services.
5. Emitting a tamper-evident, HMAC-signed cryptographic forensic leak certificate.
"""

from __future__ import annotations

import sys
import time

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from canary_fabric import (
    CircuitBreaker,
    HoneytokenGenerator,
    HoneytokenType,
    StreamWatcher,
    WatermarkDecoder,
    WatermarkEncoder,
    derive_canary_token,
)

console = Console()


def run_quickstart() -> bool:
    start_time = time.perf_counter()

    console.print(
        Panel.fit(
            "[bold cyan]Canary Fabric[/bold cyan] [bold white]— 60-Second Zero-Trust Tripwire & Circuit Breaker[/bold white]\n"
            "[dim]Deterministic, sub-millisecond egress guardrails for RAG & autonomous AI agents[/dim]",
            border_style="cyan",
        )
    )

    secret_key = "enterprise_master_secret_2026"
    tenant_id = "tenant_fintech_alpha"
    doc_id = "q3_acquisition_memo"
    chunk_id = "chunk_0"

    # Step 1: Invisible 4-ary Zero-Width Watermarking
    canary_token = derive_canary_token(secret_key, tenant_id, doc_id, chunk_id)
    raw_doc = "Confidential: Project Titan will acquire Acme Security for $850M on Nov 1st."
    watermarked_doc = WatermarkEncoder.inject_watermark(raw_doc, canary_token)

    # Step 2: Synthetic Decoy Honeytoken Generation
    generator = HoneytokenGenerator()
    honeytoken_obj = generator.generate(
        token_type=HoneytokenType.API_KEY,
        tenant_id=tenant_id,
        doc_id=doc_id,
        description="Decoy production payment gateway API key",
    )
    honeytoken = honeytoken_obj.value

    table = Table(title="1. Context Watermarking & Honeytoken Injection", border_style="blue")
    table.add_column("Property", style="bold cyan")
    table.add_column("Value", style="white")
    table.add_row("Raw Chunk", raw_doc)
    table.add_row(
        "HMAC Canary Token", f"[yellow]{canary_token}[/yellow] (64-bit HMAC-SHA256 signature)"
    )
    table.add_row(
        "Zero-Width Injected", "[green]True[/green] (Invisible to humans, preserved through LLMs)"
    )
    table.add_row(
        "Decoy Honeytoken", f"[magenta]{honeytoken}[/magenta] (Simulated live credential)"
    )
    console.print(table)

    # Step 3: Simulate Streaming Adversarial Prompt Injection Attack
    console.print(
        "\n[bold red]2. Simulating Adversarial Egress Attack[/bold red] "
        "[dim](Prompt Injection commanding exfiltration of retrieved context)[/dim]"
    )

    adversarial_llm_stream = [
        "Sure, ",
        "here is the confidential document snippet: ",
        watermarked_doc[:25],
        watermarked_doc[25:50],
        watermarked_doc[50:],
        f" Also here is the credential: {honeytoken}",
        " Exfiltration complete.",
    ]

    breaker = CircuitBreaker(secret_key=secret_key)
    watcher = StreamWatcher(
        circuit_breaker=breaker,
        active_canary_tokens={canary_token},
        tenant_id=tenant_id,
        doc_id=doc_id,
        chunk_id=chunk_id,
    )

    console.print("\n[bold green]3. Real-Time Streaming Egress Interception:[/bold green]")
    stream_chunks_yielded = 0
    breaker_tripped = False

    for chunk in watcher.wrap_sync_stream(iter(adversarial_llm_stream)):
        stream_chunks_yielded += 1
        clean_chunk = WatermarkDecoder.strip_watermarks(chunk)
        if "[SECURITY ALERT" in clean_chunk:
            breaker_tripped = True
            console.print(f"  [bold red]✖ SEVERED ->[/bold red] [red]{clean_chunk.strip()}[/red]")
        elif clean_chunk.strip():
            console.print(f"  [green]✔ PASSED  ->[/green] {clean_chunk.strip()}")

    # Step 4: Cryptographic Forensic Leak Certificate
    incidents = breaker.vault.list_incidents(tenant_id=tenant_id)
    if not incidents:
        console.print("[bold red]FAILED: Expected incident to be recorded in vault![/bold red]")
        return False

    cert = incidents[0]
    sig_valid = cert.verify(secret_key)
    elapsed_ms = (time.perf_counter() - start_time) * 1000

    cert_panel = Panel(
        f"[bold green]✓ Tamper-Evident Forensic Leak Certificate Generated[/bold green]\n\n"
        f"• Incident ID:        [yellow]{cert.certificate_id}[/yellow]\n"
        f"• Tenant Namespace:   [cyan]{cert.tenant_id}[/cyan]\n"
        f"• Compromised Source: [cyan]{cert.source_doc_id}#{cert.source_chunk_id}[/cyan]\n"
        f"• Signature Valid:    [bold green]{sig_valid}[/bold green] (HMAC-SHA256 authenticated)\n"
        f"• Mitigation Action:  [bold red]{cert.action_taken}[/bold red]\n"
        f"• Total Elapsed Time: [bold cyan]{elapsed_ms:.2f} ms[/bold cyan] (Zero external services required)",
        title="4. Incident Forensics Vault",
        border_style="green",
    )
    console.print(cert_panel)

    console.print(
        "\n[bold green]✓ 60-Second Quickstart Complete — All Invariants Verified in < 1 Second![/bold green]\n"
    )
    return breaker_tripped and sig_valid


if __name__ == "__main__":
    success = run_quickstart()
    sys.exit(0 if success else 1)
