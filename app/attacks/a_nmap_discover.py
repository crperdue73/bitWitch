"""Attack modules: recon.

No target restrictions. These run the tool and report what it said.
"""

from __future__ import annotations

import re
import socket
import subprocess

from ..jobs import Blocked
from ._common import require_tool

NAME = "nmap_discover"
LABEL = "Port discovery (nmap)"
DESC = "TCP connect scan of the target. No exploitation, just what is listening."
CATEGORY = "recon"
NEEDS_PORT = False


def run(target: str, port: int | None, emit) -> dict:
    if not re.match(r"^[A-Za-z0-9_.:\-\[\]]+$", target):
        raise Blocked(f"target {target!r} is not a hostname or IP")

    emit("[*] precondition: target resolves")
    try:
        resolved = socket.gethostbyname(target)
    except OSError as exc:
        raise Blocked(f"cannot resolve {target}: {exc}") from exc
    emit(f"    {target} -> {resolved}")

    emit("[*] precondition: nmap present")
    require_tool("nmap")
    emit("    found")

    argv = ["nmap", "-sT", "-Pn", "-T4", "--top-ports", "200", target]
    emit("")
    emit(f"[$] {' '.join(argv)}")
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=300)
    for line in (proc.stdout + proc.stderr).splitlines():
        emit(line)

    if proc.returncode != 0:
        return {"status": "fail", "summary": f"nmap exited {proc.returncode}"}

    open_ports = re.findall(r"^(\d+)/tcp\s+open\s+(\S+)", proc.stdout, re.M)
    if not open_ports:
        return {"status": "complete", "summary": "no open ports in top 200"}

    listing = ", ".join(f"{p}/{s}" for p, s in open_ports)
    emit("")
    emit(f"[+] {len(open_ports)} open: {listing}")
    return {"status": "complete", "summary": f"{len(open_ports)} open: {listing}"}
