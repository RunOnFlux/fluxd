"""Capture fluxd ``-alertnotify`` output to a file and poll it for a needle.

fluxd runs the ``-alertnotify`` command (``%s`` replaced by the sanitized,
single-quoted alert text) when it sees a really long fork. Wiring it to append
to a file lets a test confirm the alert fired and inspect the message.
"""

import asyncio
from pathlib import Path


def notify_arg(alert_file: Path) -> str:
    """A ``-alertnotify`` arg that appends the alert message to ``alert_file``."""
    alert_file.write_text("")  # start empty so a stale file can't pass the poll
    return f'-alertnotify=echo %s >> "{alert_file}"'


async def wait_for_alert(alert_file: Path, needle: str, timeout: float = 30) -> str:
    """Poll ``alert_file`` until it contains ``needle``; return its contents.

    fluxd sanitizes the alert text (drops ``~`` and newlines) before passing it
    to the command, so callers should match a sanitization-safe substring.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        try:
            text = alert_file.read_text()
        except OSError:
            text = ""
        if needle in text:
            return text
        if loop.time() > deadline:
            raise AssertionError(
                f"-alertnotify did not write {needle!r} within {timeout}s; got {text!r}"
            )
        await asyncio.sleep(0.2)
