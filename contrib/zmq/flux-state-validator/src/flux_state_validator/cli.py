#!/usr/bin/env python3
"""CLI entry point for FluxNode State Validator."""

import asyncio
import typer
from pathlib import Path
from .validator import FluxNodeStateValidator

app = typer.Typer(help="Validate FluxNode state consistency via ZMQ events")


@app.command()
def validate(
    zmq: str = typer.Option(
        "tcp://127.0.0.1:16123",
        "--zmq", "-z",
        help="ZMQ endpoint to connect to"
    ),
    rpc_conf: Path = typer.Option(
        "/dat/var/lib/fluxd/flux.conf",
        "--rpc-conf", "-c",
        help="Path to flux.conf"
    ),
    log: Path = typer.Option(
        "/var/log/flux-state-validator/validation.log",
        "--log", "-l",
        help="Log file path"
    ),
    interval: int = typer.Option(
        100,
        "--interval", "-i",
        help="Validation interval in blocks"
    ),
):
    """Validate FluxNode state by comparing ZMQ deltas against RPC snapshots."""
    validator = FluxNodeStateValidator(
        zmq_endpoint=zmq,
        rpc_conf=str(rpc_conf),
        log_file=str(log),
        validation_interval=interval
    )

    asyncio.run(validator.run())


def main():
    """Entry point for the CLI."""
    app()


if __name__ == '__main__':
    main()
