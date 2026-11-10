"""Attack modules: recon — banner grab."""

from __future__ import annotations

import socket

from ..jobs import Blocked

NAME = "banner_grab"
LABEL = "Banner grab"
DESC = "Connect to one port and read whatever it says before you say anything."
CATEGORY = "recon"
NEEDS_PORT = True


def run(target: str, port: int | None, emit) -> dict:
    if not port:
        raise Blocked("this attack needs a port")
    emit(f"[*] connecting to {target}:{port} (5s timeout)")
    try:
        with socket.create_connection((target, port), timeout=5) as sock:
            sock.settimeout(3)
            try:
                data = sock.recv(1024)
            except socket.timeout:
                emit("    connected, no banner sent within 3s (silent service)")
                return {"status": "complete", "summary": "connected, silent"}
    except OSError as exc:
        raise Blocked(f"cannot connect to {target}:{port}: {exc}") from exc

    text = data.decode("utf-8", "replace").strip()
    emit(f"[+] banner: {text!r}")
    return {"status": "complete", "summary": text[:120]}
