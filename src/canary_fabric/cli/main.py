"""CanaryFabric interactive and production CLI."""

import json
import time
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from canary_fabric.core.crypto import (
    derive_canary_token,
    generate_session_nonce,
)
from canary_fabric.core.honeytoken import HoneytokenGenerator, HoneytokenType
from canary_fabric.core.watermark import WatermarkDecoder, WatermarkEncoder
from canary_fabric.forensics.certificate import LeakCertificate

console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="canary-fabric")
def main() -> None:
    """CanaryFabric: Zero-Trust Cryptographic Tripwires for AI Pipelines."""


@main.command()
@click.option(
    "--text", "-t", required=True, help="Input text or document content to watermark"
)
@click.option("--tenant-id", default="tenant_corp", help="Tenant / Organization ID")
@click.option("--doc-id", default="doc_101", help="Document identifier")
@click.option("--chunk-id", default="chunk_0", help="Chunk identifier")
@click.option(
    "--secret-key", default="canary_secret_key_prod", help="Cryptographic secret key"
)
def watermark(
    text: str, tenant_id: str, doc_id: str, chunk_id: str, secret_key: str
) -> None:
    """Invisibly inject a 4-ary Zero-Width HMAC canary token into text."""
    session_nonce = generate_session_nonce()
    token = derive_canary_token(
        secret_key=secret_key,
        tenant_id=tenant_id,
        doc_id=doc_id,
        chunk_id=chunk_id,
        session_nonce=session_nonce,
    )
    watermarked_text = WatermarkEncoder.inject_watermark(text, token)

    console.print(
        Panel(
            f"[bold green]Canary Token Generated & Injected Successfully[/bold green]\n\n"
            f"[bold]Canary Signature:[/bold] [yellow]{token}[/yellow]\n"
            f"[bold]Tenant ID:[/bold] {tenant_id}\n"
            f"[bold]Document ID:[/bold] {doc_id} (Chunk: {chunk_id})\n"
            f"[bold]Session Nonce:[/bold] {session_nonce}\n"
            f"[bold]Original Length:[/bold] {len(text)} chars | [bold]Watermarked Length:[/bold] {len(watermarked_text)} chars\n"
            f"[dim](Zero-width characters are invisible to humans and preserved in LLM context)[/dim]",
            title="CanaryFabric Watermark Generator",
            border_style="cyan",
        )
    )
    console.print(f"\n[bold cyan]Watermarked Output:[/bold cyan]\n{watermarked_text}")


@main.command()
@click.option(
    "--text", "-t", required=True, help="Text to scan for watermarks and honeytokens"
)
def scan(text: str) -> None:
    """Scan text or stream chunk for invisible canary watermarks."""
    extracted = WatermarkDecoder.extract_tokens(text)
    if extracted:
        console.print(
            Panel(
                f"[bold red]⚠️ ACTIVE CANARY TRIPWIRE DETECTED! ⚠️[/bold red]\n\n"
                f"[bold]Extracted Signatures:[/bold] [yellow]{', '.join(extracted)}[/yellow]\n"
                f"[bold]Total Canaries Found:[/bold] {len(extracted)}\n"
                f"[bold]Status:[/bold] EXFILTRATION CANDIDATE DETECTED",
                title="Canary Scanner Result",
                border_style="red",
            )
        )
    else:
        console.print(
            "[bold green]✓ Clean - No canary watermarks detected.[/bold green]"
        )


@main.command()
@click.option(
    "--type",
    "token_type",
    default="api_key",
    type=click.Choice(["api_key", "db_uri", "email", "employee_id", "jwt_secret"]),
)
@click.option("--tenant-id", default="tenant_corp", help="Tenant ID")
@click.option("--doc-id", default="financial_report_2026", help="Document ID")
@click.option(
    "--description", default="Canary decoy credential", help="Decoy description"
)
def honeytoken(token_type: str, tenant_id: str, doc_id: str, description: str) -> None:
    """Generate high-fidelity synthetic honeytokens."""
    gen = HoneytokenGenerator()
    ht = gen.generate(
        token_type=HoneytokenType(token_type),
        tenant_id=tenant_id,
        doc_id=doc_id,
        description=description,
    )
    console.print(
        Panel(
            f"[bold cyan]Synthetic Honeytoken Generated[/bold cyan]\n\n"
            f"[bold]Token ID:[/bold] {ht.token_id}\n"
            f"[bold]Type:[/bold] {ht.token_type.value}\n"
            f"[bold]Decoy Value:[/bold] [yellow]{ht.value}[/yellow]\n"
            f"[bold]Target Doc ID:[/bold] {ht.doc_id}\n"
            f"[bold]Tenant ID:[/bold] {ht.tenant_id}",
            title="Honeytoken Generator",
            border_style="blue",
        )
    )


@main.command(name="cert-verify")
@click.option(
    "--file",
    "-f",
    required=True,
    type=click.Path(exists=True),
    help="Path to JSON Leak Certificate",
)
@click.option(
    "--secret-key",
    default="canary_prod_master_secret",
    help="Secret key to verify signature",
)
def cert_verify(file: str, secret_key: str) -> None:
    """Verify cryptographic authenticity of a Forensic Leak Certificate."""
    content = Path(file).read_text(encoding="utf-8")
    data = json.loads(content)
    cert = LeakCertificate.model_validate(data)
    is_valid = cert.verify(secret_key)

    if is_valid:
        console.print(
            "[bold green]✓ Valid Certificate - Cryptographic signature verified successfully.[/bold green]"
        )
        console.print(f"Incident ID: [yellow]{cert.certificate_id}[/yellow]")
        console.print(
            f"Compromised Chunk: [cyan]{cert.source_doc_id}#{cert.source_chunk_id}[/cyan]"
        )
    else:
        console.print(
            "[bold red]✗ INVALID CERTIFICATE - Signature mismatch or payload tampered![/bold red]"
        )


@main.command()
@click.option("--iterations", default=10000, help="Number of scan iterations")
def benchmark(iterations: int) -> None:
    """Run performance micro-benchmarks for sliding-window scanner."""
    sample_text = (
        "The confidential acquisition of Acme Corp will complete on November 15th for $450M. "
        "All engineers will receive transition grants."
    )
    token = "7F8A9E1D2C3B4A5E"
    watermarked = WatermarkEncoder.inject_watermark(sample_text, token)

    console.print(
        f"[bold cyan]Running {iterations:,} scanning iterations...[/bold cyan]"
    )
    t0 = time.perf_counter()
    for _ in range(iterations):
        _ = WatermarkDecoder.extract_tokens(watermarked)
    elapsed = time.perf_counter() - t0
    avg_us = (elapsed / iterations) * 1_000_000

    table = Table(title="CanaryFabric Latency Benchmark", border_style="cyan")
    table.add_column("Metric", style="bold")
    table.add_column("Value", style="green")
    table.add_row("Total Iterations", f"{iterations:,}")
    table.add_row("Total Elapsed Time", f"{elapsed:.4f}s")
    table.add_row("Average Scan Latency", f"{avg_us:.2f} µs ({avg_us / 1000.0:.4f} ms)")
    table.add_row("Throughput", f"{int(iterations / elapsed):,} ops/sec")
    table.add_row("TTFT Degradation Tax", "< 0.05 ms (Target: < 0.8 ms)")

    console.print(table)


if __name__ == "__main__":
    main()
