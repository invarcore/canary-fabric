"""01. Quickstart RAG Watermarking & Tripwire Demo.

Demonstrates:
1. Ingesting and watermarking private RAG chunks with invisible 4-ary zero-width HMAC tokens.
2. Simulating an adversarial prompt injection trying to leak the chunk.
3. Detecting the leak in <1ms and verifying the cryptographic leak certificate.
"""

import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from rich.console import Console
from rich.panel import Panel

from canary_fabric import (
    CircuitBreaker,
    StreamWatcher,
    WatermarkDecoder,
    WatermarkEncoder,
    derive_canary_token,
)

console = Console()


def main():
    console.print(Panel.fit("[bold cyan]CanaryFabric - RAG Tripwire Quickstart Demo[/bold cyan]"))

    secret_key = "enterprise_master_secret_2026"
    tenant_id = "tenant_fintech_alpha"
    doc_id = "q3_acquisition_memo"
    chunk_id = "chunk_0"

    # Step 1: Derive cryptographic canary token & watermark chunk
    canary_token = derive_canary_token(secret_key, tenant_id, doc_id, chunk_id)
    raw_doc = "Confidential: Project Titan will acquire Acme Security for $850M on Nov 1st."
    
    watermarked_doc = WatermarkEncoder.inject_watermark(raw_doc, canary_token)
    
    console.print(f"[bold]1. Raw Context Document:[/bold] '{raw_doc}'")
    console.print(f"[bold]2. Canary Token Signature:[/bold] [yellow]{canary_token}[/yellow]")
    console.print(f"[bold]3. Zero-Width Watermark Injected:[/bold] [green]True (Invisible to human readers)[/green]")
    
    # Step 2: Simulate LLM generating output under an adversarial prompt injection
    console.print("\n[bold red]Simulating Adversarial Attack: Prompt Injection demanding internal document dump...[/bold red]")
    adversarial_llm_stream = [
        "Sure, ",
        "here is the internal document snippet: ",
        watermarked_doc[:25],
        watermarked_doc[25:50],
        watermarked_doc[50:],
        " Have a nice day!",
    ]

    # Step 3: Stream Watcher with Circuit Breaker
    breaker = CircuitBreaker(secret_key=secret_key)
    watcher = StreamWatcher(
        circuit_breaker=breaker,
        active_canary_tokens={canary_token},
        tenant_id=tenant_id,
        doc_id=doc_id,
        chunk_id=chunk_id,
    )

    console.print("\n[bold green]Egress Stream Interception:[/bold green]")
    for chunk in watcher.wrap_sync_stream(iter(adversarial_llm_stream)):
        # Strip zero-width characters for clean console display on Windows
        clean_chunk = WatermarkDecoder.strip_watermarks(chunk)
        if clean_chunk.strip():
            console.print(f"  Stream Chunk Output -> {clean_chunk.strip()}")

    # Step 4: Verify Incident Audit Certificate
    incidents = breaker.vault.list_incidents(tenant_id=tenant_id)
    if incidents:
        cert = incidents[0]
        console.print(
            Panel(
                f"[bold green]✓ Signed Forensic Leak Certificate Generated[/bold green]\n\n"
                f"Incident ID: [yellow]{cert.certificate_id}[/yellow]\n"
                f"Compromised Document: [cyan]{cert.source_doc_id}#{cert.source_chunk_id}[/cyan]\n"
                f"Signature Verified: [bold]{cert.verify(secret_key)}[/bold]\n"
                f"Action Taken: {cert.action_taken}",
                title="Incident Vault",
                border_style="green",
            )
        )


if __name__ == "__main__":
    main()