#!/usr/bin/env python3
"""FluxD ZMQ Event Monitor CLI - Monitor hashblockheight, chainreorg, and fluxnodelistdelta events."""

import sys
import struct
from datetime import datetime
from pathlib import Path
from typing import Optional
from importlib.metadata import version

import zmq
import typer
from rich.console import Console

from .decoders import decode_hashblockheight, decode_chainreorg, decode_fluxnodelistdelta, decode_fluxnodestatus

app = typer.Typer(help="Monitor FluxD ZMQ events in real-time")
console = Console()


def version_callback(value: bool):
    """Print version and exit."""
    if value:
        pkg_version = version("flux-zmq-monitor")
        typer.echo(f"flux-zmq-monitor version {pkg_version}")
        raise typer.Exit()


@app.command()
def monitor(
    endpoint: str = typer.Option(
        "tcp://127.0.0.1:16123",
        "--endpoint", "-e",
        help="ZMQ endpoint to connect to"
    ),
    log_file: Optional[Path] = typer.Option(
        None,
        "--log-file", "-l",
        help="Path to log file (default: stdout)"
    ),
    version_flag: Optional[bool] = typer.Option(
        None,
        "--version", "-v",
        callback=version_callback,
        is_eager=True,
        help="Show version and exit"
    ),
):
    """Monitor FluxD ZMQ events in real-time."""

    # Set up logging
    log_handle = None
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        log_handle = open(log_file, 'a', buffering=1)
        sys.stdout = log_handle
        sys.stderr = log_handle

    context = zmq.Context()

    subscribers = {
        'hashblockheight': decode_hashblockheight,
        'chainreorg': decode_chainreorg,
        'fluxnodelistdelta': decode_fluxnodelistdelta,
        'fluxnodestatus': decode_fluxnodestatus,
    }

    sockets = []
    poller = zmq.Poller()

    print("🚀 FluxD ZMQ Event Monitor")
    print("=" * 60)

    for topic, decoder in subscribers.items():
        try:
            socket = context.socket(zmq.SUB)
            socket.connect(endpoint)
            socket.setsockopt_string(zmq.SUBSCRIBE, topic)
            sockets.append((socket, topic, decoder))
            poller.register(socket, zmq.POLLIN)
            print(f"✓ Subscribed to {topic} on {endpoint}")
        except Exception as e:
            print(f"✗ Failed to subscribe to {topic}: {e}")

    if not sockets:
        print("\n❌ No subscriptions active. Check fluxd is running with ZMQ enabled.")
        raise typer.Exit(code=1)

    print("\n👂 Listening for events... (Ctrl+C to stop)\n")
    print(f"📝 Logging to: {log_file if log_file else 'stdout'}\n")

    try:
        while True:
            events = dict(poller.poll(timeout=1000))

            for socket, topic, decoder in sockets:
                if socket in events:
                    parts = socket.recv_multipart()

                    if len(parts) >= 3:
                        msg_topic = parts[0].decode('utf-8')
                        msg_data = parts[1]
                        msg_seq = struct.unpack('<I', parts[2])[0]

                        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        decoded = decoder(msg_data)

                        print(f"[{timestamp}] {msg_topic} (seq #{msg_seq})")
                        print(f"  {decoded}")
                        print()

    except KeyboardInterrupt:
        print("\n\n👋 Shutting down...")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        raise typer.Exit(code=1)
    finally:
        for socket, _, _ in sockets:
            socket.close()
        context.term()
        if log_handle:
            log_handle.close()


def main():
    """Entry point for the CLI."""
    app()


if __name__ == '__main__':
    main()
