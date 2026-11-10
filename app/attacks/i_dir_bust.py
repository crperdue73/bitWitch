"""Attack modules: recon — directory and file brute force.

gobuster with a short list. Full wordlists are gigabytes and most of them are
noise for a classroom; this ships a curated set aimed at the paths that
actually appear on a lab target, plus the generic noise a scanner would send.

`complete` rather than `pass`: finding directories is gathering data, not
asserting a claim. The verdict is in the output.
"""

from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path

from ..jobs import Blocked
from ._common import require_tool

# gobuster colours its output; those bytes are not part of the path.
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

NAME = "dir_bust"
LABEL = "Directory brute force"
DESC = "gobuster against a web root with a curated list of common paths and bait files."
CATEGORY = "recon"
NEEDS_PORT = True

# Curated, not the 4-million-line classic. These are the paths that show up on
# real lab boxes and in Trapdoor's own bait list, so a hit means something.
WORDS = [
    "admin", "admin.php", "administrator", "api", "assets", "backup", "backups",
    "backup.zip", "backup.sql", "cgi-bin", "config", "config.php", "console",
    "dashboard", "db", "db.sql", "debug", "dev", "docs", "download",
    "files", "hidden", "images", "include", "includes", "index.php", "js",
    "login", "login.php", "logs", "old", "phpinfo.php", "phpmyadmin", "private",
    "robots.txt", "server-status", "setup", "shell.php", "src", "static",
    "status", "test", "tmp", "uploads", "user", "users", "web.config", "wp-admin",
    "wp-config.php", "wp-content", "wp-login.php", "xmlrpc.php",
    ".env", ".git/config", ".aws/credentials", ".ssh/id_rsa", ".htaccess",
]

TIMEOUT = 180


def run(target: str, port: int | None, emit) -> dict:
    if not port:
        raise Blocked("this attack needs a port")

    require_tool("gobuster")

    url = f"http://{target}:{port}"
    emit(f"[*] target {url}")
    emit(f"[*] {len(WORDS)} paths, {TIMEOUT}s cap")
    emit("")

    # Feed the list on stdin rather than writing a temp file, so nothing has to
    # be stored or cleaned up inside the container.
    # gobuster seeks its wordlist more than once, and a pipe cannot seek.
    # Feeding it /dev/stdin made it exit with "failed to rewind wordlist: seek
    # /dev/stdin: illegal seek", which the parser below then read as "no paths
    # found" — a tool crash reported as a clean scan. It gets a real file.
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        fh.write("\n".join(WORDS) + "\n")
        wordlist = fh.name

    try:
        proc = subprocess.run(
            [
                "gobuster", "dir",
                "-u", url,
                "-w", wordlist,
                "--quiet",
                "--no-error",
                "--timeout", "5s",
                "-t", "8",
                "-k",
            ],
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
        )
    finally:
        Path(wordlist).unlink(missing_ok=True)

    out = (proc.stdout or "") + (proc.stderr or "")

    # A crashed tool must never read as a clean result. Fail closed: the scan
    # did not happen, so this is `blocked`, not `complete`.
    errors = [
        line.strip() for line in out.splitlines()
        if line.strip().lower().startswith("error")
    ]
    if errors:
        emit("")
        for line in errors:
            emit(f"    {line}")
        raise Blocked(f"gobuster failed before scanning: {errors[0]}")

    if not out.strip():
        raise Blocked(
            f"gobuster produced no output (exit {proc.returncode}) — nothing "
            f"was proven about {url}"
        )

    # gobuster emits ANSI colour codes even with --quiet, so a raw line looks
    # like "\x1b[2K/.env   (Status: 403)". Strip them before matching, or every
    # hit is missed and a working scan reports nothing found.
    clean = ANSI.sub("", out)

    found: list[tuple[str, str]] = []
    for line in clean.splitlines():
        if not line.strip():
            continue
        # Path first, then status: ".env  (Status: 403) [Size: 146]"
        m = re.match(r"^\s*(\S+)\s+\(Status:\s*(\d+)\)", line)
        if not m:
            # Some gobuster builds put the status first.
            m2 = re.match(r"^\s*Status:\s*(\d+)\s*:?\s*(\S+)", line)
            if m2:
                found.append((m2.group(1), m2.group(2)))
            continue
        found.append((m.group(2), m.group(1)))

    emit("")
    if not found:
        emit("[-] no path returned any status at all. That is different from")
        emit("    'nothing interesting' — a working scan should at least see")
        emit("    403s or 404s. Check the port with the banner grab.")
        return {"status": "complete", "summary": "no responses at all"}

    emit(f"[+] {len(found)} paths returned a status:")
    for status, path in sorted(found):
        emit(f"    {status}  {path}")

    interesting = [p for s, p in found if s in ("200", "301", "302", "401", "403")]
    if interesting:
        emit("")
        emit(f"    {len(interesting)} are worth a second look (200/301/302/401/403).")
        emit("    A 403 is not a dead end — it means the path exists and is")
        emit("    refusing you. That is the most interesting answer on the list.")

    return {"status": "complete", "summary": f"{len(found)} paths found"}
