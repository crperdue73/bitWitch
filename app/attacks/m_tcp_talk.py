"""Attack modules: interaction — raw TCP conversation.

Netcat with a script. Sometimes you do not want a scanner, you want to type at
a service and see what it says back. This is that, bounded: a fixed list of
lines, a fixed pause, a fixed ceiling on what comes back.

This is the module that makes a telnet decoy interesting. A telnet service
that opens with a banner naming its own product is doing part of the
attacker's work for them — that is Trapdoor defect #1, and it is visible here
in one line of output.

`complete`: reading a banner asserts nothing by itself. What the banner *means*
is the lesson, and it is printed rather than judged.
"""

from __future__ import annotations

import socket
import time

from ..jobs import Blocked

NAME = "tcp_talk"
LABEL = "TCP conversation"
DESC = "Connect, read the greeting, send a few lines, and record everything that came back."
CATEGORY = "interaction"
NEEDS_PORT = True

# What a person actually types at an unfamiliar service. Nothing destructive,
# nothing that assumes it is a shell.
LINES = [
    "help",
    "version",
    "id",
    "whoami",
    "exit",
]

READ_WINDOW = 3.0     # seconds to wait for each reply
TOTAL_CEILING = 120.0  # hard wall for the whole conversation
MAX_BYTES = 20000


def _drain(sock, emit, label: str, window: float) -> int:
    """Read whatever arrives within `window`. Returns bytes read."""
    sock.settimeout(window)
    total = 0
    while total < MAX_BYTES:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        except OSError as exc:
            emit(f"    {label} connection dropped: {exc}")
            break
        if not chunk:
            emit(f"    {label} (remote closed)")
            break
        total += len(chunk)
        text = chunk.decode("utf-8", "replace")
        for line in text.splitlines():
            emit(f"    {label} {line}")
    return total


def run(target: str, port: int | None, emit) -> dict:
    if not port:
        raise Blocked("this attack needs a port")

    emit(f"[*] connecting to {target}:{port}")
    emit("")

    try:
        sock = socket.create_connection((target, port), timeout=8)
    except OSError as exc:
        raise Blocked(f"cannot connect to {target}:{port}: {exc}") from exc

    started = time.monotonic()
    greeting_bytes = 0
    try:
        emit("  greeting")
        greeting_bytes = _drain(sock, emit, "<<", READ_WINDOW)
        if greeting_bytes == 0:
            emit("    (silent — service waits for the client to speak first)")
        emit("")

        for line in LINES:
            if time.monotonic() - started > TOTAL_CEILING:
                emit("    (hit the conversation ceiling, stopping)")
                break
            emit(f"  >> {line}")
            try:
                sock.sendall((line + "\r\n").encode())
            except OSError as exc:
                emit(f"    send failed: {exc}")
                break
            _drain(sock, emit, "<<", READ_WINDOW)
            emit("")
    finally:
        try:
            sock.close()
        except OSError:
            pass

    if greeting_bytes == 0:
        emit("[-] the service never said anything unsolicited.")
        emit("    That is a fact about the service, not a failure — plenty of")
        emit("    real daemons wait for the client to talk first.")
        return {"status": "complete", "summary": "connected, no greeting"}

    emit("[+] conversation complete. Read the greeting carefully: a service")
    emit("    that names its own product and version is doing part of the")
    emit("    attacker's work for them.")
    return {"status": "complete", "summary": f"{greeting_bytes} bytes of greeting"}
