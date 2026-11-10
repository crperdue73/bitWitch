"""Attack modules: decoy integrity — WordPress facade completeness."""

from __future__ import annotations

import urllib.error
import urllib.request

from ..jobs import Blocked

NAME = "decoy_wp_facade"
LABEL = "Decoy check: WordPress facade completeness"
DESC = "Is /wp-login.php baited while /wp-content/ 404s? An incomplete facade answers the attacker's question."
CATEGORY = "decoy"
NEEDS_PORT = True


def _status(base: str, path: str) -> int:
    try:
        resp = urllib.request.urlopen(base + path, timeout=5)
        resp.read(128)
        return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except OSError:
        return 0


def run(target: str, port: int | None, emit) -> dict:
    if not port:
        raise Blocked("this attack needs a port (web, default 8080)")
    base = f"http://{target}:{port}"

    emit("[*] finding under test: a WordPress facade that does not hold up")
    emit("    source: honeypot-engagement-2026-11-06 §3 defect 4")
    emit("")

    login = _status(base, "/wp-login.php")
    if login == 0:
        raise Blocked(f"no web server at {base}")

    emit(f"    {login:>4}  /wp-login.php")

    if login == 404:
        emit("")
        emit("[*] /wp-login.php is not baited here — claim not applicable")
        return {
            "status": "blocked",
            "summary": "no WordPress bait present; nothing to test",
        }

    content = _status(base, "/wp-content/")
    emit(f"    {content:>4}  /wp-content/")
    emit("")

    if login in (200, 403) and content == 404:
        emit("[-] FAIL — login baited, content 404s")
        emit("    An attacker who sees this learns the WordPress is fake.")
        return {"status": "fail", "summary": f"facade broken: login {login}, content {content}"}

    if login in (200, 403) and content in (200, 403):
        emit("[+] PASS — facade holds: content is baited too")
        return {"status": "pass", "summary": f"facade holds (login {login}, content {content})"}

    emit("[*] inconclusive — unexpected status combination")
    return {"status": "blocked", "summary": f"inconclusive: login {login}, content {content}"}
