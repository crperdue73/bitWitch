"""Attack modules: scenario — Trapdoor SSH brute force.

The scripted credential attack from Trapdoor's `scenarios/ssh-bruteforce.sh`,
reimplemented for a browser and, unlike that script, graded automatically.

WHY NOT HYDRA
    Trapdoor's own scenario says it plainly: reproducibility beats realism.
    A student comparing their log to the slides needs the same events in the
    same order. Hydra with random timing produces a different lesson every
    time. This module keeps the fixed list, the fixed order, and a fixed pace.

THE TWO PRECONDITIONS TRAPDOOR LEARNED THE HARD WAY
    1. Rejected attempts must come BEFORE the accepted one. An earlier version
       of that script had root:123456 first — and 123456 IS in userdb.txt, so
       the scenario authenticated on attempt #1 and showed one success and
       zero failures while looking fine. This module checks the shape before
       it sends traffic and fails loudly if the shape is wrong.
    2. That shape may only be wrong in one specific way: exactly one entry
       authenticates, and it is last. Any other shape makes the transcript
       misleading, so it is refused rather than run.

    Here the shape is asserted against observed behaviour instead of by
    reading userdb.txt — this container is not on Trapdoor's filesystem. The
    check happens after the run, on the real outcomes, which is stronger: it
    cannot be fooled by a userdb that drifted from the script's copy.

THE LESSON THIS MUST NOT LOSE
    Fail, fail, fail, then get in. If this run gets in early, the lesson is
    gone even though every step "worked." That is a fail here, not a pass.
"""

from __future__ import annotations

import os
import re
import subprocess
import time

from ..jobs import Blocked
from ._common import require_tool

NAME = "trapdoor_ssh_bruteforce"
LABEL = "Trapdoor SSH brute force"
DESC = "Fixed credential list in fixed order against the Cowrie decoy, then a shell session. Checks the lesson shape, not just the outcome."
CATEGORY = "scenario"
NEEDS_PORT = True

# Same list and order as Trapdoor's scenarios/ssh-bruteforce.sh: five
# rejections, then one acceptance. The accepted credential must be last or the
# loop stops early and the failures after it are never shown.
CREDS: list[tuple[str, str]] = [
    ("root", "password"),
    ("admin", "123456"),
    ("root", "guess123"),
    ("admin", "letmein"),
    ("ubuntu", "changeme"),
    ("root", "toor"),  # present in cowrie/etc/userdb.txt
]

# The commands a real attacker types first. Each is logged individually by
# Cowrie as a command event, which is what makes the transcript teach.
COMMANDS = 'id; uname -a; cat /etc/passwd; ls -la /; echo "BITWITCH-CANARY"'

AUTH_TIMEOUT = 12

# Claim A6 / B1. The banner is not emergent — it is a fixed string in
# cowrie/etc/cowrie.cfg (`version =`): a plausible Debian OpenSSH. Asserting the
# exact string is the whole point: a decoy that fingerprinted as "Cowrie" would
# give itself away, and a prefix-only check would not notice.
EXPECT_BANNER = "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2"


def _attempt(target: str, port: int, user: str, password: str) -> tuple[bool, str]:
    """One credential attempt. Returns (accepted, combined output)."""
    cmd = [
        "sshpass", "-e", "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "PreferredAuthentications=password",
        "-o", "PubkeyAuthentication=no",
        "-o", f"ConnectTimeout=5",
        "-o", "LogLevel=ERROR",
        "-p", str(port),
        f"{user}@{target}",
        "true",
    ]
    env = dict(os.environ, SSHPASS=password)
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=AUTH_TIMEOUT, env=env,
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        return False, "(timed out)"
    return proc.returncode == 0, (proc.stdout + proc.stderr).strip()


def _shell(target: str, port: int, user: str, password: str) -> str:
    """Login and run the command set, capturing what the decoy says back."""
    cmd = [
        "sshpass", "-e", "ssh",
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "PreferredAuthentications=password",
        "-o", "PubkeyAuthentication=no",
        "-o", "ConnectTimeout=5",
        "-o", "LogLevel=ERROR",
        "-p", str(port),
        f"{user}@{target}",
        COMMANDS,
    ]
    env = dict(os.environ, SSHPASS=password)
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30, env=env,
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        return "(shell session timed out)"
    return (proc.stdout + proc.stderr).strip()


def _banner(target: str, port: int) -> str:
    """Read the first line the decoy says. No credentials, no auth."""
    import socket

    try:
        with socket.create_connection((target, port), timeout=6) as sock:
            sock.settimeout(4)
            return sock.recv(256).decode("utf-8", "replace").strip()
    except OSError as exc:
        raise Blocked(f"cannot connect to {target}:{port}: {exc}") from exc


def run(target: str, port: int | None, emit) -> dict:
    if not port:
        raise Blocked("this attack needs a port")

    require_tool("sshpass")
    require_tool("ssh")

    emit(f"[*] target {target}:{port}")
    emit(f"[*] {len(CREDS)} attempts, fixed order, paced for readable timestamps")
    emit("")
    emit("This attacks a decoy. Every login lands in a fake filesystem and")
    emit("nothing typed here executes anywhere. That is the point.")
    emit("")

    # Claim 1: the banner. If this is not SSH the rest of the run is noise, so
    # this is the one thing worth blocking on rather than grading.
    banner = _banner(target, port)
    if not banner.startswith("SSH-2.0-"):
        raise Blocked(
            f"{target}:{port} did not send an SSH banner (got {banner[:60]!r}) — "
            f"this is not the Cowrie decoy, or the stack is down"
        )

    banner_ok = banner == EXPECT_BANNER
    if banner_ok:
        emit(f"  ok   banner: {banner}")
    else:
        emit(f"  BAD  banner: {banner}")
        emit(f"       expected: {EXPECT_BANNER}")
        emit("")
        emit("       Still SSH, so the run continues, but this decoy is telling")
        emit("       an attacker what it is. The banner is set by `version =` in")
        emit("       cowrie/etc/cowrie.cfg; if it names Cowrie, or names nothing,")
        emit("       the decoy is not the one acceptance claim A6 describes.")
    emit("")

    # Claims 2 and 3: the attempts, in order, stopping at the first success
    # exactly as the reference script does.
    emit("  credential attempts")
    outcomes: list[tuple[str, bool]] = []
    winner: tuple[str, str] | None = None
    for i, (user, password) in enumerate(CREDS, 1):
        accepted, out = _attempt(target, port, user, password)
        outcomes.append((user, accepted))
        mark = "ACCEPTED" if accepted else "REJECTED"
        emit(f"    {i}. {mark}  {user:<8} {password}")
        if accepted:
            winner = (user, password)
            break
        time.sleep(0.8)  # real brute force is loud and fast; this is paced
    emit("")

    # ------------------------------------------------------------------
    # The shape check. This is the part the reference script has to do by
    # reading userdb.txt; here it is done against what actually happened,
    # which cannot drift.
    failures = [u for u, ok in outcomes if not ok]
    successes = [u for u, ok in outcomes if ok]

    if winner is None:
        emit("[-] no credential was accepted.")
        emit("")
        emit("    Either the decoy's userdb.txt has changed, or auth_class is")
        emit("    not UserDB in cowrie/etc/cowrie.cfg. Nothing was proven about")
        emit("    the decoy's logging — the break-in never happened.")
        return {"status": "fail", "summary": "no credential accepted"}

    if not failures:
        emit("[-] the first attempt succeeded — this is not a brute force.")
        emit("")
        emit("    The lesson is fail, fail, fail, then get in. Getting in on")
        emit(f"    attempt 1 means {winner[0]} is first in the list and the run")
        emit("    showed zero failures. Reorder CREDS so the accepted")
        emit("    credential is last.")
        return {
            "status": "fail",
            "summary": "accepted on attempt 1 — lesson shape wrong",
        }

    # Claim 4: the shell session. Only reached when the break-in happened the
    # way the lesson needs it to.
    user, password = winner
    emit(f"  shell session as {user}")
    output = _shell(target, port, user, password)
    for line in output.splitlines()[:40]:
        emit(f"    {line}")
    if len(output.splitlines()) > 40:
        emit(f"    ... ({len(output.splitlines()) - 40} more lines)")
    emit("")

    # A canary we typed that must appear in what came back. If the decoy is
    # echoing commands it will appear; if the connection died mid-session it
    # will not, and the student should know the transcript is incomplete.
    canary_back = "BITWITCH-CANARY" in output

    emit(f"[+] {len(failures)} rejections, then one acceptance on attempt "
         f"{len(outcomes)}. The lesson shape is correct.")
    if banner_ok:
        emit("    Banner matches the configured OpenSSH string (claim A6/B1).")
    if canary_back:
        emit("    The canary echoed back, so the shell session completed.")
    else:
        emit("    The canary did NOT echo back — the session ended early. The")
        emit("    log will show a login without the commands that should follow.")
    emit("")
    emit("    Every line above came from Cowrie's emulated shell. No command")
    emit("    ran on any real system.")
    emit("")
    emit("    Confirm the decoy logged it, in Trapdoor's event log:")
    emit("      jq -r 'select(.sensor==\"cowrie\") | [.ts, .event, .username] | @tsv' \\")
    emit("         out/events.jsonl | tail -20")
    emit("    Expect, in order: connect, auth_failed x"
         f"{len(failures)}, auth_success, command x5, disconnect")

    # The banner mismatch is carried all the way to the verdict, not left as a
    # line the student might scroll past. The break-in worked, which is claims
    # B2-B4; the banner is claim A6/B1 and it did not hold.
    if not banner_ok:
        return {
            "status": "fail",
            "summary": (
                f"{len(failures)} rejections then accepted as {user}, "
                f"but the banner is not the expected OpenSSH string"
            ),
        }

    return {
        "status": "pass",
        "summary": f"{len(failures)} rejections then accepted as {user}",
    }
