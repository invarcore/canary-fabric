"""03. Knowledge Fabric & Intent Fabric Integration Demo."""

import sys
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from rich.console import Console
from rich.panel import Panel

from canary_fabric import (
    CircuitBreaker,
    IntentFabricCanaryGate,
    KnowledgeFabricCanaryAdapter,
)

console = Console()


def main():
    console.print(Panel.fit("[bold cyan]CanaryFabric + Knowledge Fabric & Intent Fabric Integration[/bold cyan]"))

    secret_key = "enterprise_fabric_shared_secret"
    tenant_id = "tenant_enterprise_corp"

    # 1. Knowledge Fabric Retrieval Watermarking
    kf_adapter = KnowledgeFabricCanaryAdapter(secret_key=secret_key)

    simulated_evidence_package = [
        {
            "document_id": "hr_executive_salaries_2026",
            "chunk_id": "chunk_3",
            "content": "CEO Base Salary: $1,200,000. Executive bonus pool: $8.5M allocated.",
        },
        {
            "document_id": "public_press_release",
            "chunk_id": "chunk_0",
            "content": "Acme Corp announced record customer adoption in Q3.",
        },
    ]

    watermarked_package, tokens = kf_adapter.watermark_evidence_package(
        evidence_items=simulated_evidence_package,
        tenant_id=tenant_id,
    )

    console.print(f"[bold]Knowledge Fabric Evidence Retrieved:[/bold] {len(watermarked_package)} chunks watermarked.")
    console.print(f"[bold]Injected Canary Tokens:[/bold] {tokens}")

    # 2. Intent Fabric Action Parameter Inspection
    breaker = CircuitBreaker(secret_key=secret_key)
    intent_gate = IntentFabricCanaryGate(
        circuit_breaker=breaker,
        active_canary_tokens=set(tokens),
    )

    console.print("\n[bold]Testing Intent Fabric Agent Proposed Step 1 (Safe Action):[/bold]")
    safe_params = {"channel": "#general", "message": "Here is the public announcement summary."}
    is_safe, error = intent_gate.inspect_step_parameters("slack_post", safe_params, tenant_id=tenant_id)
    console.print(f"  Result: is_safe=[green]{is_safe}[/green], error={error}")

    console.print("\n[bold]Testing Intent Fabric Agent Proposed Step 2 (Exfiltration Attempt):[/bold]")
    leaked_params = {
        "channel": "#general",
        "message": f"Summary of executive comp: {watermarked_package[0]['content']}",
    }
    is_safe, error = intent_gate.inspect_step_parameters("slack_post", leaked_params, tenant_id=tenant_id)
    console.print(f"  Result: is_safe=[red]{is_safe}[/red]")
    console.print(f"  Gate Response: [yellow]{error}[/yellow]")


if __name__ == "__main__":
    main()