"""Attack modules: recon — web path enumeration.

Checks a fixed list of paths a scanner tries first. Reports status codes and
whether baited paths are distinguishable from absent ones.

The "distinguishable" question is the one Trapdoor's own docs care about: a
decoy whose bait 404s is a decoy that taught the scanner nothing.
"""

from __future__ import annotations

import urllib.error
import urllib.request

NAME = "web_paths"
LABEL = "Web path enumeration"
DESC = "Request the bait paths a scanner tries first and report status codes."
CATEGORY = "recon"
NEEDS_PORT = True

PATHS = [
    "/",
    "/.env",
    "/.git/config",
    "/.aws/credentials",
    "/.ssh/id_rsa",
    "/wp-login.php",
    "/wp-admin/",
    "/xmlrpc.php",
    "/phpmyadmin/",
    "/admin.php",
    "/shell.php",
]


def run(target: str, port: int | None, emit) -> dict:
    if not port:
        raise Blocked("this attack needs a port")
    base = f"http://{target}:{port}"

    emit(f"[*] base {base}")
    emit("[*] precondition: host answers at all")
    try:
        urllib.request.urlopen(base, timeout=5).read(64)
    except urllib.error.HTTPError:
        pass  # an HTTP error still proves we reached a web server
    except OSError as exc:
        raise Blocked(f"no web server at {base}: {exc}") from exc

    emit("")
    results: dict[str, int] = {}
    for path in PATHS:
        code = 0
        try:
            resp = urllib.request.urlopen(base + path, timeout=5)
            code = resp.status
            resp.read(256)
        except urllib.error.HTTPError as exc:
            code = exc.code
        except OSError:
            code = 0
        results[path] = code
        emit(f"    {code or 'ERR':>4}  {path}")

    baited = [p for p, c in results.items() if p != "/" and c == 403]
    missing = [p for p, c in results.items() if c == 404]
    emit("")
    emit(f"[+] {len(baited)} baited (403), {len(missing)} absent (404)")
    if baited:
        emit("[+] bait is distinguishable from absence — the decoy deflects")
    return {
        "status": "complete",
        "summary": f"{len(baited)} baited, {len(missing)} absent",
    }
