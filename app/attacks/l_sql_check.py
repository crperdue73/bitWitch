"""Attack modules: web — sqlmap injection check.

sqlmap against a URL. The classroom failure mode here is pointing it at a site
with no parameters, watching it print "no injectable parameters," and
concluding the target is clean. It has not looked at anything. This module
refuses parameterless URLs rather than producing that false negative.

`complete`, not `pass`: "not injectable" and "not tested" look identical in
sqlmap's output and only one of them means anything.
"""

from __future__ import annotations

import re
import subprocess
from urllib.parse import parse_qsl, urlsplit

from ..jobs import Blocked
from ._common import require_tool

NAME = "sql_check"
LABEL = "SQL injection check"
DESC = "sqlmap against one URL. Refuses to run on a URL with no parameters rather than reporting a clean result it did not earn."
CATEGORY = "web"
NEEDS_PORT = True

PATH = "/"
TIMEOUT = 300


def run(target: str, port: int | None, emit, path: str = PATH) -> dict:
    if not port:
        raise Blocked("this attack needs a port")

    require_tool("sqlmap")

    url = f"http://{target}:{port}{path}"
    query = urlsplit(url).query
    params = parse_qsl(query)

    if not params:
        raise Blocked(
            f"{url} has no query parameters, so there is nothing for sqlmap to "
            f"test. A run here would print 'no injectable parameters' and that "
            f"line means 'nothing was looked at', not 'the target is clean'. "
            f"Give a URL with a parameter, e.g. /item.php?id=1"
        )

    emit(f"[*] target {url}")
    emit(f"[*] testing {len(params)} parameter(s): {', '.join(k for k, _ in params)}")
    emit(f"[*] {TIMEOUT}s cap")
    emit("")

    try:
        proc = subprocess.run(
            [
                "sqlmap",
                "-u", url,
                "--batch",
                "--level", "2",
                "--risk", "2",
                "--timeout", "10",
                "--retries", "1",
                "--flush-session",
                "--disable-coloring",
            ],
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
        )
    except subprocess.TimeoutExpired as exc:
        partial = exc.stdout or ""
        if isinstance(partial, bytes):
            partial = partial.decode("utf-8", "replace")
        for line in partial.splitlines()[-25:]:
            emit(f"    {line}")
        raise Blocked(
            f"sqlmap hit the {TIMEOUT}s wall — partial output above is all it got"
        ) from exc

    out = (proc.stdout or "") + (proc.stderr or "")
    if not out.strip():
        raise Blocked(f"sqlmap produced no output (exit {proc.returncode})")

    injectable = False
    for line in out.splitlines():
        s = line.strip()
        if not s:
            continue
        low = s.lower()
        if "is vulnerable" in low or "injectable" in low:
            injectable = True
            emit(f"    [+] {s}")
        elif s.startswith("[INFO]") or s.startswith("[CRITICAL]") or s.startswith("[ERROR]"):
            emit(f"    {s}")
        elif "parameter" in low and "appears to be" in low:
            injectable = True
            emit(f"    [+] {s}")

    emit("")
    if injectable:
        emit("[+] sqlmap reported an injectable parameter. Read the payload it")
        emit("    printed — that line is the finding.")
        return {"status": "complete", "summary": "parameter reported injectable"}

    emit("[-] sqlmap did not find an injectable parameter.")
    emit("    It did look this time: the URL had a parameter and the scan ran.")
    emit("    'Not injectable' is a real result here; it would not have been")
    emit("    if this had been run against a URL with no query string.")
    return {"status": "complete", "summary": "no injectable parameter found"}
