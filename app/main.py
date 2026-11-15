"""bitWitch — web front end for attack runs.

One page, one form, live output. No build step, no framework, no npm.

Two roles, described in scope.py:

  student  name + class password. No target restrictions by default.
  admin    class password + admin password. Sets the target scope.

The tool itself is unconstrained unless an admin bounds it. Nothing in here
stops a student from running nmap, gobuster, or hydra — the scope, when set,
stops them from running it somewhere they should not.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import time
from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from . import attacks, jobs, scope

APP_DIR = Path(__file__).resolve().parent
STATIC = APP_DIR.parent / "static"

CLASS_PASSWORD = os.environ.get("BITWITCH_PASSWORD", "")
ADMIN_PASSWORD = os.environ.get("BITWITCH_ADMIN_PASSWORD", "")
MAX_JOBS_PER_MIN = int(os.environ.get("BITWITCH_MAX_JOBS_PER_MIN", "20"))

# --------------------------------------------------------------------------
# build stamp
#
# The container image runs whatever was COPYed in at build time. `up -d`
# without `--build` reuses the old image, so a "deployed" fix that was never
# rebuilt looks exactly like a deployed fix from the outside. That is the whole
# of D6: two people can compare notes about a live box and both be right about
# different software.
#
# So the build stamps itself and the app says out loud what it is running.
#
# GIT_COMMIT is passed as a build arg. Absent, it is None — the build still
# succeeds (a checkout with no git history is a legitimate way to build), but
# the app REFUSES TO SERVE. An unstamped instance is not a deployment, and a
# service that answers 200 while being unable to say what it is, is a service
# that will be trusted past its provenance.
#
# BITWITCH_ALLOW_UNSTAMPED=1 is the documented escape hatch for local
# development only. It is loud in the log, and the version endpoint reports
# dirty/stamped accordingly so the exception is visible from outside.
GIT_COMMIT = os.environ.get("GIT_COMMIT") or None
GIT_DIRTY = os.environ.get("GIT_DIRTY", "").strip() == "1"
BUILT_AT = os.environ.get("BUILT_AT") or None
ALLOW_UNSTAMPED = os.environ.get("BITWITCH_ALLOW_UNSTAMPED", "") == "1"


def _require_stamp() -> None:
    """Refuse to serve an unstamped build. Startup exception, non-zero exit."""
    if GIT_COMMIT:
        return
    if ALLOW_UNSTAMPED:
        print(
            "[bitwitch] WARNING: serving an UNSTAMPED build because "
            "BITWITCH_ALLOW_UNSTAMPED=1. /api/version will report commit=null. "
            "This is for local development only. Do not deploy this.",
            flush=True,
        )
        return
    raise SystemExit(
        "[bitwitch] REFUSING TO SERVE: no GIT_COMMIT in the image.\n"
        "  The app cannot say what software it is running, so a report from\n"
        "  this instance cannot be trusted or reproduced.\n"
        "  Build with:  docker compose build --build-arg GIT_COMMIT=$(git rev-parse HEAD)\n"
        "  or export BITWITCH_ALLOW_UNSTAMPED=1 for local development only."
    )


_require_stamp()

app = FastAPI(title="bitWitch", docs_url=None, redoc_url=None)


# --------------------------------------------------------------------------
# routes
@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    if not _auth_ok(request):
        return RedirectResponse("/login", status_code=303)
    return HTMLResponse(_render_index(request))


@app.get("/api/version")
def api_version():
    """What software is this? Answers D6 from outside the box.

    Unauthenticated on purpose. It carries no secrets and no run data — only
    provenance. A version endpoint that needs a login cannot be used to check a
    box you suspect is misconfigured, which is the one moment you need it.
    """
    return JSONResponse(
        {
            "commit": GIT_COMMIT,
            "dirty": GIT_DIRTY,
            "built_at": BUILT_AT,
        }
    )


@app.get("/api/health")
def api_health():
    """Liveness. Deliberately thin: it reports that the process answers.

    It does NOT report the commit. A health check that also answers "what
    version" invites people to use it as a version check, and then a restart
    looks like a deploy. Identity lives at /api/version; this only says alive.
    """
    return JSONResponse({"status": "ok"})


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return HTMLResponse(_render_login(request))


@app.post("/login")
def login_submit(
    request: Request,
    operator: str = Form(""),
    password: str = Form(""),
    admin_password: str = Form(""),
):
    operator = operator.strip()
    if not operator:
        return HTMLResponse(_render_login(request, "Enter your name."), status_code=400)

    if CLASS_PASSWORD and not secrets.compare_digest(password, CLASS_PASSWORD):
        return HTMLResponse(_render_login(request, "Wrong password."), status_code=401)

    # Admin is opt-in at the door: leave the field blank and you are a student.
    role = "student"
    if admin_password:
        if not ADMIN_PASSWORD:
            return HTMLResponse(
                _render_login(request, "No admin password is configured on this server."),
                status_code=400,
            )
        if not secrets.compare_digest(admin_password, ADMIN_PASSWORD):
            return HTMLResponse(_render_login(request, "Wrong admin password."), status_code=401)
        role = "admin"

    resp = RedirectResponse("/", status_code=303)
    resp.set_cookie(
        "bw_session",
        _sign(operator, role),
        httponly=True,
        samesite="lax",
        max_age=60 * 60 * 8,
    )
    return resp


@app.get("/logout")
def logout():
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie("bw_session")
    return resp


@app.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request):
    session = _session(request)
    if session is None:
        return RedirectResponse("/login", status_code=303)
    if session["role"] != "admin":
        raise HTTPException(403, "admins only")
    return HTMLResponse(_render_admin(request, session))


@app.post("/admin/scope")
def admin_scope(
    request: Request,
    networks: str = Form(""),
    note: str = Form(""),
):
    session = _session(request)
    if session is None:
        return RedirectResponse("/login", status_code=303)
    if session["role"] != "admin":
        raise HTTPException(403, "admins only")

    entries = [line for line in re.split(r"[\s,]+", networks) if line.strip()]
    try:
        scope.save(entries, note)
    except ValueError as exc:
        return HTMLResponse(
            _render_admin(request, session, error=str(exc)), status_code=400
        )
    return RedirectResponse("/admin", status_code=303)


@app.get("/api/catalog")
def api_catalog(request: Request):
    if not _auth_ok(request):
        raise HTTPException(401, "not signed in")
    return JSONResponse(attacks.catalog())


@app.get("/api/scope")
def api_scope(request: Request):
    if not _auth_ok(request):
        raise HTTPException(401, "not signed in")
    return JSONResponse(scope.current())


@app.post("/api/run")
def api_run(
    request: Request,
    attack: str = Form(...),
    target: str = Form(...),
    port: str = Form(""),
    path: str = Form("/"),
    protocol: str = Form("ssh"),
):
    session = _session(request)
    if session is None:
        raise HTTPException(401, "not signed in")

    operator = session["name"]
    target = target.strip()
    if not target:
        raise HTTPException(400, "target is required")
    if not re.match(r"^[A-Za-z0-9_.:\-\[\]]+$", target):
        raise HTTPException(400, f"target {target!r} is not a hostname or IP")

    allowed, reason = scope.check(target)
    if not allowed:
        # 403 with the reason, not a silent skip: a student should be told the
        # scope exists and what it is, so they learn the rule instead of
        # guessing why the tool "broke".
        #
        # The record is written BEFORE the refusal is returned. A refusal that
        # cannot be recorded is not a refusal, it is an unverified claim — the
        # student is told no and nothing durable says they asked. Writing it
        # first means the only way to get a 403 with no record is a crash
        # between the two, which cannot report success.
        #
        # If the write fails we return 500, not 403. Handing back a clean "no"
        # when the audit trail is broken would turn a logging fault into a
        # silent boundary crossing. The 500 should be unreachable; if it fires,
        # that is its own alarm.
        try:
            jobs.record_refusal(attack, target, operator, reason)
        except Exception as exc:
            print(f"[main] refused run could not be recorded: {exc!r}")
            raise HTTPException(
                500,
                "the attempt was refused and the refusal could not be logged; "
                "this is a bug, not a scope decision",
            ) from exc
        raise HTTPException(403, reason)

    port_val: int | None = None
    if port.strip():
        try:
            port_val = int(port.strip())
        except ValueError as exc:
            raise HTTPException(400, f"port {port!r} is not a number") from exc
        if not 1 <= port_val <= 65535:
            raise HTTPException(400, "port must be 1-65535")

    mod = attacks.get(attack)
    if mod is None:
        raise HTTPException(404, f"no attack named {attack!r}")
    if mod.NEEDS_PORT and port_val is None:
        raise HTTPException(400, f"{mod.LABEL} requires a port")

    if not _within_rate(operator):
        raise HTTPException(429, "too many runs — wait a minute")

    # Optional per-attack parameters. They are passed through and the job
    # runner only hands them to a module whose signature accepts them, so an
    # attack that ignores these is unaffected.
    opts: dict = {}
    if path.strip() and path.strip() != "/":
        opts["path"] = path.strip()
    if protocol.strip():
        opts["protocol"] = protocol.strip()

    job = jobs.start(attack, target, port_val, operator, scope_note=reason, opts=opts)
    return JSONResponse(job.snapshot())


@app.get("/api/job/{job_id}")
def api_job(request: Request, job_id: str, since: int = 0):
    if not _auth_ok(request):
        raise HTTPException(401, "not signed in")
    job = jobs.get_job(job_id)
    if job is None:
        raise HTTPException(404, "no such job")
    return JSONResponse(job.snapshot(since=max(0, since)))


# --------------------------------------------------------------------------
# sessions

SECRET = os.environ.get("BITWITCH_SECRET", "")


def _secret() -> str:
    global SECRET
    if not SECRET:
        # Ephemeral: sessions die with the process. Fine for a class period,
        # and better than shipping a default secret in an image.
        SECRET = secrets.token_hex(32)
    return SECRET


def _sign(operator: str, role: str) -> str:
    payload = f"{operator}\x1f{role}"
    mac = hmac.new(_secret().encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{operator}|{role}|{mac}"


def _session(request: Request) -> dict | None:
    """Return {name, role} from the signed cookie, or None.

    The role travels inside the signed payload, so a student cannot promote
    themselves by editing the cookie — any change breaks the MAC.

    Cookie shape is `name|role|mac`. Split from the left with a limit of 3,
    not rpartition: rpartition from the right gives `name|role` as the name
    and leaves the role empty, which made every valid cookie look forged.
    """
    raw = request.cookies.get("bw_session", "")
    parts = raw.split("|")
    if len(parts) != 3:
        # Legacy single-field cookie from the pre-role build: name|mac.
        if len(parts) == 2:
            name, mac = parts
            role = "student"
        else:
            return None
    else:
        name, role, mac = parts

    payload = f"{name}\x1f{role}"
    want = hmac.new(_secret().encode(), payload.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(mac, want):
        return None
    if role not in ("student", "admin"):
        return None
    return {"name": name, "role": role}


def _auth_ok(request: Request) -> bool:
    return _session(request) is not None


_RATE: dict[str, list[float]] = {}


def _within_rate(operator: str) -> bool:
    now = time.time()
    window = [t for t in _RATE.get(operator, []) if now - t < 60]
    if len(window) >= MAX_JOBS_PER_MIN:
        _RATE[operator] = window
        return False
    window.append(now)
    _RATE[operator] = window
    return True


# --------------------------------------------------------------------------
# pages

def _page(title: str, body: str, body_class: str = "") -> str:
    """Render the shell. Centralised so a page cannot forget body_class."""
    return _PAGE.format(title=title, body=body, body_class=body_class)


def _render_login(request: Request, error: str = "") -> str:
    err = f'<p class="err">{error}</p>' if error else ""
    return _page(
        "sign in",
        body_class="login",
        body=f"""
<img class="login-art" src="/static/img/logo.png"
     alt="bitWitch — hax0rgrrl">
<div class="card narrow">
  <h2>sign in</h2>
  <p class="sub">Sign in so the log knows whose run is whose.</p>
  {err}
  <form method="post" action="/login">
    <label>Your name <input name="operator" autofocus required></label>
    <label>Class password <input name="password" type="password"></label>
    <label>Admin password <span class="opt">(blank unless you run the lab)</span>
      <input name="admin_password" type="password"></label>
    <button type="submit">Enter</button>
  </form>
</div>""",
    )


def _render_index(request: Request) -> str:
    s = _session(request) or {"name": "?", "role": "student"}
    sc = scope.current()

    if sc["restricted"]:
        scope_line = (
            f'<span class="warn">scope limited to {", ".join(sc["networks"])}</span>'
        )
    else:
        scope_line = '<span class="free">no scope set — anything reachable</span>'

    admin_link = (
        ' · <a href="/admin">admin</a>' if s["role"] == "admin" else ""
    )

    return _page(
        "bitWitch",
        body=f"""
<div class="masthead">
  <img class="mark" src="/static/img/mark.png" alt="">
  <div>
    <h1>bit<em>Witch</em> 🪛</h1>
    <p class="tag">hax0rgrrl · attack lab</p>
  </div>
</div>
<div class="card">
  <p class="sub">Signed in as <b>{s["name"]}</b> ({s["role"]}){admin_link} · <a href="/logout">sign out</a></p>
  <p class="sub">{scope_line}</p>
  <form id="run">
    <label>Attack <select name="attack" id="attack"></select></label>
    <p class="hint" id="desc"></p>
    <label>Target <input name="target" placeholder="10.20.30.50" required></label>
    <label>Port <input name="port" id="port" placeholder="blank if unused" inputmode="numeric"></label>
    <button type="submit">Run</button>
  </form>
</div>
<div class="card">
  <h2>Output <span id="status" class="status"></span></h2>
  <pre id="out">—</pre>
</div>
<script src="/static/app.js"></script>""",
    )


def _render_admin(request: Request, session: dict, error: str = "") -> str:
    sc = scope.current()
    err = f'<p class="err">{error}</p>' if error else ""
    listing = "\n".join(sc["networks"]) if sc["networks"] else ""
    state = (
        f'<p class="warn">Students are limited to: {", ".join(sc["networks"])}</p>'
        if sc["restricted"]
        else '<p class="free">No scope set. Students can reach anything this container can.</p>'
    )
    return _page(
        "scope",
        body=f"""
<div class="masthead">
  <img class="mark" src="/static/img/mark.png" alt="">
  <div>
    <h1>bit<em>Witch</em> 🪛</h1>
    <p class="tag">hax0rgrrl · target scope</p>
  </div>
</div>
<div class="card">
  <h2>Target scope</h2>
  <p class="sub">Signed in as <b>{session["name"]}</b> (admin) · <a href="/">back to runs</a> · <a href="/logout">sign out</a></p>
  {state}
  {err}
  <form method="post" action="/admin/scope">
    <label>Allowed networks or addresses, one per line
      <textarea name="networks" rows="6" placeholder="10.20.30.0/24">{listing}</textarea></label>
    <label>Note <span class="opt">(why, for whoever reads this later)</span>
      <input name="note" value="{sc["note"]}"></label>
    <button type="submit">Save scope</button>
  </form>
  <p class="hint">Leave everything blank to remove the limit. Hostnames are refused while a
  scope is set — the scope is compared as addresses, so an IP is required.</p>
</div>""",
    )


_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} · bitWitch</title>
<link rel="stylesheet" href="/static/style.css">
<link rel="icon" type="image/png" href="/static/img/icon.png">
</head>
<body class="{body_class}">
{body}
</body>
</html>"""

app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")
