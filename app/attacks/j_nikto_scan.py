"""Attack modules: recon — nikto web server scan.

Nikto is the loud one. It sends thousands of requests, checks for known
misconfigurations and outdated software, and reports what it found. On a
honeypot that is exactly what you want: it generates a long, obvious
transcript in the decoy's log.

`complete`, not `pass`: nikto's findings are data, not a claim this module can
adjudicate. It does not know whether a reported item is a real vulnerability
or a decoy being interesting on purpose.

Slow by design. The scan is time-boxed with -maxtime so a run cannot wedge a
class, and the timeout means a slow target reports what it got rather than
hanging.
"""

from __future__ import annotations

import subprocess

from ..jobs import Blocked
from ._common import require_tool

NAME = "nikto_scan"
LABEL = "Nikto web scan"
DESC = "Known-misconfiguration and outdated-software scan. Loud, slow, and generates a lot of log."
CATEGORY = "recon"
NEEDS_PORT = True

MAXTIME = "180s"
HARD_TIMEOUT = 240


def run(target: str, port: int | None, emit) -> dict:
    if not port:
        raise Blocked("this attack needs a port")

    require_tool("nikto")

    emit(f"[*] target {target}:{port}")
    emit(f"[*] time-boxed to {MAXTIME}; nikto is loud and will fill a log")
    emit("")

    try:
        proc = subprocess.run(
            [
                "nikto",
                "-h", f"http://{target}:{port}",
                "-maxtime", MAXTIME,
                "-nointeractive",
                "-ask", "no",
                "-Display", "V",
            ],
            capture_output=True,
            text=True,
            timeout=HARD_TIMEOUT,
        )
    except subprocess.TimeoutExpired as exc:
        # Partial output is still evidence. Report it rather than binning it.
        partial = (exc.stdout or "")
        if isinstance(partial, bytes):
            partial = partial.decode("utf-8", "replace")
        for line in partial.splitlines()[-30:]:
            emit(f"    {line}")
        raise Blocked(
            f"nikto hit the {HARD_TIMEOUT}s wall — partial output above is "
            f"everything it got"
        ) from exc

    out = (proc.stdout or "") + (proc.stderr or "")
    if not out.strip():
        raise Blocked(f"nikto produced no output (exit {proc.returncode})")

    findings = 0
    for line in out.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        # Nikto prefixes findings with "+ ". Pass those through; drop the
        # banner noise and progress dots so the output stays readable.
        if stripped.startswith("+ "):
            findings += 1
            emit(f"    {stripped}")
        elif stripped.startswith("- ") or "Target IP" in stripped or "Start Time" in stripped:
            emit(f"    {stripped}")

    emit("")
    if findings == 0:
        emit("[-] no findings reported.")
        emit("    On a decoy this usually means the bait answered everything")
        emit("    with a flat 403 and nikto had nothing to latch onto — which")
        emit("    is the decoy working, not the scan failing.")
        return {"status": "complete", "summary": "no findings"}

    emit(f"[+] {findings} findings. Read them as leads, not verdicts: this")
    emit("    module cannot tell a real misconfiguration from a decoy that is")
    emit("    pretending to be interesting.")
    return {"status": "complete", "summary": f"{findings} findings"}
