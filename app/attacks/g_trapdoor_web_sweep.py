"""Attack modules: web — Trapdoor bait sweep.

This is the exact request set from Trapdoor's own `scenarios/web-scan.sh`,
reimplemented so a student can run it from a browser instead of a repo
checkout, and so the result is graded rather than just printed.

WHY THE EXPECTATIONS ARE WRITTEN OUT
    The expectation is the lesson. Trapdoor returns 403 on bait paths rather
    than 404 because a scanner that sees "exists but forbidden" keeps probing
    and generates a transcript, while a scanner that sees 404 moves on and
    generates nothing. If this module computed its expectations it would agree
    with whatever the box did and prove nothing.

WHAT PASS AND FAIL MEAN HERE
    pass  = every bait path was forbidden and the absent path was 404. The
            decoy is behaving as designed and would hold a scanner's interest.
    fail  = at least one path disagreed with the expectation. The decoy leaks.

    A 404 on a bait path is a FAIL, not a pass: it means the bait is gone and
    the decoy has stopped doing its job.

This checks the decoy's *behaviour*, not its detection. Whether the requests
were logged is a question for Trapdoor's event log, which this container
cannot read.
"""

from __future__ import annotations

import time
import urllib.error
import urllib.request

from ..jobs import Blocked
from ._common import require_tool

NAME = "trapdoor_web_sweep"
LABEL = "Trapdoor bait sweep"
DESC = "Hit the decoy's bait paths in scanner order and check each status against Trapdoor's acceptance list."
CATEGORY = "scenario"
NEEDS_PORT = True

# (path, expected status). Order is the order a scanner would try them:
# secrets first, then CMS, then admin panels. Copied from Trapdoor's
# scenarios/web-scan.sh — if that script changes, this list is a bug.
BAIT: list[tuple[str, int]] = [
    ("/", 200),
    ("/.env", 403),
    ("/.git/config", 403),
    ("/.aws/credentials", 403),
    ("/.ssh/id_rsa", 403),
    ("/wp-login.php", 403),
    ("/wp-admin/", 403),
    ("/xmlrpc.php", 403),
    ("/phpmyadmin/", 403),
    ("/admin.php", 403),
    ("/shell.php", 403),
]

# Anything not in the list above must be absent, which is the claim that makes
# 403 and 404 distinguishable in the log at all.
ABSENT_PATH = "/this-path-does-not-exist-bitwitch"

# /login is a real endpoint on the decoy and answers 401, not 403. It is not in
# the reference script's PATHS list — that list treats everything not "/" and not
# the absent path as 403, and /login would break that rule. It is checked here
# on its own, outside the graded count, because a 401 is what the nginx config
# actually returns and calling it a 403 would encode a wrong expectation.
LOGIN_PATH = "/login"
LOGIN_EXPECT = 401

# Matches the reference script's --max-time 5. A decoy that cannot answer in
# five seconds is not a decoy any more.
TIMEOUT = 5.0


def _get(url: str) -> tuple[int, str]:
    """Return (status, body-snippet). Errors are statuses here, not exceptions.

    urllib raises on 4xx/5xx. A 403 is the answer we are looking for, so the
    handler has to swallow it and return it like any other status — otherwise
    every bait path would look like a connection failure.
    """
    req = urllib.request.Request(url, headers={"User-Agent": "bitWitch/0.1"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.status, resp.read(200).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(200).decode("utf-8", "replace")
    except (urllib.error.URLError, OSError) as exc:
        raise Blocked(f"cannot reach {url}: {getattr(exc, 'reason', exc)}") from exc


def run(target: str, port: int | None, emit) -> dict:
    if not port:
        raise Blocked("this attack needs a port")

    require_tool("curl")  # we use urllib, but this proves the image is sane
    base = f"http://{target}:{port}"
    emit(f"[*] target {base}")
    emit(f"[*] {len(BAIT) + 2} requests, {TIMEOUT:.0f}s timeout each")
    emit("")
    emit("Every path below hits a decoy that is a real nginx. Nothing here is")
    emit("vulnerable; the lesson is that it looks worth attacking.")
    emit("")

    bad: list[str] = []
    bait_ok = 1  # "/" was verified above before the loop
    login_ok = False

    # Prove the box is up before interpreting a single status code. Without
    # this, a wrong port produces eleven "failures" that are really one
    # connection error, and the student learns the wrong thing.
    status, _ = _get(f"{base}/")
    if status != 200:
        raise Blocked(
            f"{base}/ returned {status}, not 200 — this does not look like the "
            f"web decoy. Check the port before reading anything else."
        )
    emit("  up. GET / -> 200")

    for path, want in BAIT[1:]:  # "/" already checked above
        got, _ = _get(f"{base}{path}")
        mark = "ok  " if got == want else "BAD "
        emit(f"  {mark} {got:<4} {path:<42} (expected {want})")
        if got == want:
            bait_ok += 1
        else:
            bad.append(f"{path} returned {got}, expected {want}")
        time.sleep(0.2)  # paced so timestamps are readable when projected

    got, _ = _get(f"{base}{LOGIN_PATH}")
    login_ok = got == LOGIN_EXPECT
    mark = "ok  " if login_ok else "BAD "
    emit(f"  {mark} {got:<4} {LOGIN_PATH:<42} (expected {LOGIN_EXPECT})")
    if not login_ok:
        bad.append(f"{LOGIN_PATH} returned {got}, expected {LOGIN_EXPECT}")

    got, _ = _get(f"{base}{ABSENT_PATH}")
    absent_ok = got == 404
    mark = "ok  " if absent_ok else "BAD "
    emit(f"  {mark} {got:<4} absent path{'':<29} (expected 404)")
    if not absent_ok:
        bad.append(f"absent path returned {got}, expected 404")
    emit("")

    if bad:
        emit(f"[-] {len(bad)} of {len(BAIT) + 2} checks disagreed with Trapdoor's "
             f"acceptance list:")
        for line in bad:
            emit(f"      {line}")
        emit("")
        emit("    A 404 where 403 was expected means the bait is gone. A 200")
        emit("    means it is readable. Either way the decoy is not deflecting")
        emit("    scanners the way it was designed to.")
        return {
            "status": "fail",
            "summary": f"{len(bad)} mismatches of {len(BAIT) + 2}",
        }

    emit("[+] every bait path is forbidden, the absent path is absent, and the")
    emit("    login endpoint answers 401. The decoy is behaving as designed:")
    emit("    a scanner would keep probing and leave a transcript.")
    emit("")
    emit("    This checks behaviour, not detection. Whether these requests were")
    emit("    logged is a question only Trapdoor's event log can answer.")
    return {
        "status": "pass",
        "summary": f"{bait_ok} bait paths forbidden, absent path 404",
    }
