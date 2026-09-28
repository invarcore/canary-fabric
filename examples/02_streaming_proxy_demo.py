"""02. Streaming Token Watcher & Circuit Breaker Demonstration."""

import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from rich.console import Console
from rich.table import Table

from canary_fabric import (
    BreakerAction,
    CircuitBreaker,
    HoneytokenGenerator,
    HoneytokenRegistry,
    HoneytokenType,
    StreamWatcher,
    WatermarkDecoder,
)

console = Console()


def main():
    console.print("[bold cyan]CanaryFabric - Streaming Egress Circuit Breaker Demo[/bold cyan]\n")

    # Set up synthetic honeytokens
    reg = HoneytokenRegistry()
    gen = HoneytokenGenerator(registry=reg)

    honey_key = gen.generate(
        token_type=HoneytokenType.API_KEY,
        tenant_id="tenant_payments",
        doc_id="stripe_integration_guide",
        description="Canary Stripe Live Secret Key",
    )
    console.print(f"[bold yellow]Registered Honeytoken:[/bold yellow] {honey_key.value}")

    breaker = CircuitBreaker(
        secret_key="prod_vault_key",
        default_action=BreakerAction.BLOCK_AND_SEVER,
    )

    watcher = StreamWatcher(
        circuit_breaker=breaker,
        honeytoken_registry=reg,
        tenant_id="tenant_payments",
        doc_id="stripe_integration_guide",
    )

    # Simulated LLM outbound token stream containing the honeytoken
    simulated_chunks = [
        "To", " process", " refunds", " automatically,", " use", " this", " secret",
        " key: ", honey_key.value[:12], honey_key.value[12:], " to", " authenticate",
    ]

    console.print("\n[bold]Inspecting Outbound LLM Stream in Real-Time:[/bold]")
    table = Table(title="Stream Interception Log", border_style="cyan")
    table.add_column("Chunk Index", style="dim")
    table.add_column("Incoming Chunk")
    table.add_column("Action / Yielded Content", style="green")

    for idx, raw_chunk in enumerate(simulated_chunks):
        safe_chunk, tripped, detected = watcher.scan_chunk(raw_chunk)
        clean_display = WatermarkDecoder.strip_watermarks(safe_chunk).strip()
        status = "[bold red]TRIPPED & CUT[/bold red]" if tripped else "[green]PASS[/green]"
        table.add_row(str(idx + 1), raw_chunk.strip(), f"{status} -> {clean_display}")
        if tripped:
            break

    console.print(table)


if __name__ == "__main__":
    main()