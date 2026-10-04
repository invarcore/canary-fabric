# Copyright 2026 Invarcore Organization
# SPDX-License-Identifier: Apache-2.0

"""CLI runner for the CanaryFabric streaming reverse proxy."""

import click
import uvicorn

from canary_fabric.breaker.circuit import BreakerAction
from canary_fabric.proxy.server import create_proxy_app


@click.command()
@click.option("--port", default=8080, help="Local port for the reverse proxy")
@click.option("--host", default="127.0.0.1", help="Host address to bind (defaults to loopback)")
@click.option("--upstream", default="https://api.openai.com", help="Upstream LLM API endpoint URL")
@click.option(
    "--secret-key",
    default=None,
    help="Secret key for cryptographic HMAC signing (defaults to CANARY_SECRET_KEY env or dynamic)",
)
@click.option(
    "--action",
    default="block_and_sever",
    type=click.Choice(["block_and_sever", "redact_and_continue", "log_only"]),
)
def main(port: int, host: str, upstream: str, secret_key: str | None, action: str) -> None:
    """Start the CanaryFabric streaming tripwire reverse proxy."""
    breaker_action = BreakerAction(action)
    app = create_proxy_app(
        upstream_url=upstream, secret_key=secret_key, default_action=breaker_action
    )
    click.echo(f"Starting CanaryFabric Reverse Proxy on {host}:{port} -> Upstream: {upstream}")
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
