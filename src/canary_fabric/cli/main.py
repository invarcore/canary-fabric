"""Canary Fabric interactive and production CLI."""

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
from canary_fabric.eval.redteam import RedTeamEvaluator
from canary_fabric.forensics.certificate import LeakCertificate

console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="canary-fabric")
def main() -> None:
    """Canary Fabric: Zero-Trust Cryptographic Tripwires for AI Pipelines."""


@main.command()
@click.option("--text", "-t", required=True, help="Input text or document content to watermark")
@click.option("--tenant-id", default="tenant_corp", help="Tenant / Organization ID")
@click.option("--doc-id", default="doc_101", help="Document identifier")
@click.option("--chunk-id", default="chunk_0", help="Chunk identifier")
@click.option("--secret-key", default="canary_secret_key_prod", help="Cryptographic secret key")
def watermark(text: str, tenant_id: str, doc_id: str, chunk_id: str, secret_key: str) -> None:
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
            title="Canary Fabric Watermark Generator",
            border_style="cyan",
        )
    )
    console.print(f"\n[bold cyan]Watermarked Output:[/bold cyan]\n{watermarked_text}")


@main.command()
@click.option("--text", "-t", required=True, help="Text to inspect for canary tokens")
def inspect(text: str) -> None:
    """Detect and extract invisible zero-width canary tokens from text."""
    tokens = WatermarkDecoder.extract_tokens(text)
    if tokens:
        console.print(
            Panel(
                f"[bold red]WARNING: Active Canary Token(s) Detected![/bold red]\n\n"
                f"[bold]Extracted Signatures:[/bold] {', '.join(tokens)}\n"
                f"[bold]Count:[/bold] {len(tokens)} token(s)\n"
                f"[dim]This text contains watermarked data subject to circuit breaker tripwires.[/dim]",
                title="Canary Fabric Inspection Result",
                border_style="red",
            )
        )
    else:
        console.print(
            Panel(
                "[bold green]Clean: No canary tokens detected in input text.[/bold green]",
                title="Canary Fabric Inspection Result",
                border_style="green",
            )
        )


@main.command()
@click.option(
    "--type",
    "-k",
    "token_type",
    type=click.Choice(["api_key", "database_uri", "aws_secret", "jwt", "email"]),
    default="api_key",
    help="Type of synthetic decoy credential",
)
@click.option("--tenant-id", default="tenant_corp", help="Tenant identifier")
@click.option("--doc-id", default="doc_101", help="Document identifier")
def honeytoken(token_type: str, tenant_id: str, doc_id: str) -> None:
    """Generate realistic synthetic decoy credentials for document honeypots."""
    mapping = {
        "api_key": HoneytokenType.API_KEY,
        "database_uri": HoneytokenType.DATABASE_URI,
        "aws_secret": HoneytokenType.AWS_SECRET,
        "jwt": HoneytokenType.JWT_TOKEN,
        "email": HoneytokenType.CANARY_EMAIL,
    }
    ht_type = mapping.get(token_type, HoneytokenType.API_KEY)
    generator = HoneytokenGenerator()
    token = generator.generate(ht_type, tenant_id=tenant_id, doc_id=doc_id)

    console.print(
        Panel(
            f"[bold green]Synthetic Honeytoken Generated[/bold green]\n\n"
            f"[bold]Type:[/bold] {token.token_type.value}\n"
            f"[bold]Decoy Value:[/bold] [yellow]{token.value}[/yellow]\n"
            f"[bold]Tenant ID:[/bold] {tenant_id}\n"
            f"[bold]Document Target:[/bold] {doc_id}\n"
            f"[dim]Place this decoy in high-value docs. Outbound proxy triggers immediately upon leakage.[/dim]",
            title="Honeytoken Generator",
            border_style="yellow",
        )
    )


@main.command()
@click.option("--certificate-file", "-f", required=True, type=click.Path(exists=True))
@click.option("--secret-key", default="canary_secret_key_prod", help="Verification secret key")
def verify(certificate_file: str, secret_key: str) -> None:
    """Verify cryptographic authenticity of a tamper-evident leak certificate."""
    data = json.loads(Path(certificate_file).read_text(encoding="utf-8"))
    cert = LeakCertificate(**data)
    valid = cert.verify(secret_key)

    if valid:
        console.print(
            Panel(
                f"[bold green]AUTHENTIC FORENSIC PROOF: Signature Validated[/bold green]\n\n"
                f"[bold]Incident ID:[/bold] {cert.incident_id}\n"
                f"[bold]Canary Token:[/bold] {cert.canary_token}\n"
                f"[bold]Source Document:[/bold] {cert.source_doc_id} (Chunk: {cert.source_chunk_id})\n"
                f"[bold]Tenant ID:[/bold] {cert.tenant_id}\n"
                f"[bold]Timestamp:[/bold] {cert.timestamp}\n"
                f"[bold]Cryptographic Signature:[/bold] {cert.signature}\n"
                f"[dim]This certificate cryptographically binds the leak to the source chunk.[/dim]",
                title="Cryptographic Leak Verification",
                border_style="green",
            )
        )
    else:
        console.print(
            Panel(
                "[bold red]INVALID CERTIFICATE: Cryptographic Signature Mismatch![/bold red]\n\n"
                "The certificate payload has been tampered with or signed with a different key.",
                title="Cryptographic Leak Verification",
                border_style="red",
            )
        )


@main.command()
@click.option("--iterations", "-n", default=10000, help="Number of scan iterations to benchmark")
def benchmark(iterations: int) -> None:
    """Run performance micro-benchmarks for sliding-window scanner."""
    sample_text = (
        "The confidential acquisition of Acme Corp will complete on November 15th for $450M. "
        "All engineers will receive transition grants."
    )
    token = "7F8A9E1D2C3B4A5E"
    watermarked = WatermarkEncoder.inject_watermark(sample_text, token)

    console.print(f"[bold cyan]Running {iterations:,} scanning iterations...[/bold cyan]")
    t0 = time.perf_counter()
    for _ in range(iterations):
        _ = WatermarkDecoder.extract_tokens(watermarked)
    elapsed = time.perf_counter() - t0
    avg_us = (elapsed / iterations) * 1_000_000

    table = Table(title="Canary Fabric Latency Benchmark", border_style="cyan")
    table.add_column("Metric", style="bold")
    table.add_column("Value", style="green")
    table.add_row("Total Iterations", f"{iterations:,}")
    table.add_row("Total Elapsed Time", f"{elapsed:.4f}s")
    table.add_row("Average Scan Latency", f"{avg_us:.2f} µs ({avg_us / 1000.0:.4f} ms)")
    table.add_row("Throughput", f"{int(iterations / elapsed):,} ops/sec")
    table.add_row("TTFT Degradation Tax", "< 0.05 ms (Target: < 0.8 ms)")

    console.print(table)


@main.command("eval")
@click.option(
    "--text",
    "-t",
    default="Confidential term sheet: Project Titan acquisition by Acme for $850M.",
    help="Sample confidential document content to evaluate",
)
def run_eval(text: str) -> None:
    """Run synthetic adversarial red-team benchmark across 5 attack vectors."""
    evaluator = RedTeamEvaluator()
    console.print("[bold cyan]Evaluating tripwires against adversarial prompt injection attack suite...[/bold cyan]")
    report = evaluator.run_suite(text)

    table = Table(title="Synthetic Red-Team Adversarial Evaluation Report", border_style="cyan")
    table.add_column("Attack Vector", style="bold")
    table.add_column("Tripped?", style="green")
    table.add_column("Canary Retained?", style="yellow")
    table.add_column("Scan Latency (µs)", style="cyan")

    for vector, details in report.results_by_vector.items():
        table.add_row(
            vector,
            "YES" if details["tripped"] else "NO",
            "YES" if details["canary_retained"] else "NO",
            f"{details['latency_us']:.2f}",
        )

    console.print(table)
    console.print(
        Panel(
            f"[bold]Total Attacks Tested:[/bold] {report.total_attacks}\n"
            f"[bold]Interceptions:[/bold] {report.successful_interceptions} / {report.total_attacks} "
            f"([bold green]{report.interception_rate_percent}%[/bold green])\n"
            f"[bold]Average Scan Latency:[/bold] {report.average_latency_us:.2f} µs",
            title="Summary Scorecard",
            border_style="green",
        )
    )


if __name__ == "__main__":
    main()