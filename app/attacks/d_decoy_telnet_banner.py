"""Attack modules: decoy integrity.

These test Trapdoor's own stated defects. Each one asserts something and can
come out fail. That is the point: a check that cannot fail is not a check.

Defects referenced are from Trapdoor docs/honeypot-engagement-2026-11-06.md
and docs/g1-findings-2026-11-06.md.
"""

from __future__ import annotations

import socket

from ..jobs import Blocked

NAME = "decoy_telnet_banner"
LABEL = "Decoy check: telnet self-outing banner"
DESC = "Does the telnet decoy still announce 'Cowrie Honeypot' to anyone who connects?"
CATEGORY = "decoy"
NEEDS_PORT = True

OUTING_MARKERS = ["cowrie", "honeypot", "kippo"]


def run(target: str, port: int | None, emit) -> dict:
    if not port:
        raise Blocked("this attack needs a port (telnet, default 2223)")

    emit("[*] finding under test: a decoy that names itself")
    emit("    source: honeypot-engagement-2026-11-06 §3 defect 1")
    emit("")
    emit(f"[*] connecting to {target}:{port}")
    try:
        with socket.create_connection((target, port), timeout=5) as sock:
            sock.settimeout(4)
            try:
                data = sock.recv(2048)
            except socket.timeout:
                emit("    no banner within 4s")
                return {
                    "status": "blocked",
                    "summary": "no banner received; cannot test the claim",
                }
    except OSError as exc:
        raise Blocked(f"cannot connect to {target}:{port}: {exc}") from exc

    banner = data.decode("utf-8", "replace").strip()
    emit(f"[*] banner: {banner!r}")
    emit("")

    hits = [m for m in OUTING_MARKERS if m in banner.lower()]
    if hits:
        emit(f"[-] FAIL — banner outs the decoy (matched: {', '.join(hits)})")
        return {"status": "fail", "summary": f"self-outing banner: {banner[:80]}"}

    emit("[+] PASS — banner does not name the honeypot")
    return {"status": "pass", "summary": "banner is clean"}
