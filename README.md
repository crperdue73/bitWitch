<div align="center">

![bitWitch — hax0rgrrl](docs/assets/bitwitch-banner.jpg)

**Automated Adversary • Cybersecurity Education • Contained & Controlled**

</div>

# bitWitch 🪛

A web front end for attack runs against the lab. Pick an attack, type a target,
watch the output stream. Built to replace a heavyweight Kali VM with something
students can actually reach from a browser.

## What it is, and what it is not

It is a **runner**, not a wrapper around one tool. Every attack is a small
plugin file that either gathers data or asserts a claim, and says which it did.

It is **not** a scanner with a curated "safe" list bolted on. There are no
target restrictions in the attacks themselves. The boundary is the classroom:
by default a student can reach anything the container can, the same as having a
terminal on a Kali box. An admin can narrow that (see Scope below).

## Roles

Two roles, decided at sign-in.

**Student** — your name and the class password. Leave the admin password blank.
You get the attack menu and a target field.

**Admin** — the class password *plus* the admin password. You get a `/admin`
page where you set the target scope.

The role is carried inside the signed session cookie, so a student cannot
promote themselves by editing it. (Tested: changing `student` to `admin`, or
renaming yourself to an admin, both invalidate the signature and drop you back
to the login page.)

## Scope

By default there is **no scope** and the page says so: *no scope set — anything
reachable*.

An admin can set a list of networks. Once set:

- targets inside the list run normally
- targets outside it are refused with an explicit reason
- hostnames are refused while a scope is set, because the scope is compared as
  addresses — an IP is required

Leaving the field blank removes the limit. The state is written to
`/data/scope.json` and survives restarts.

Why an admin sets this and not a constant in the source: I do not know which
network a given class runs on, and hardcoding a guess means rebuilding an image
every time the room changes.

## Running it

```bash
cp .env.example .env
# edit .env: set BITWITCH_PASSWORD, BITWITCH_ADMIN_PASSWORD, BITWITCH_SECRET
docker compose up -d --build
```

Then open `http://<host>:8099`.

`.env` holds passwords. It is gitignored. Do not commit it.

## Attacks

Each file in `app/attacks/` is one attack, auto-discovered at startup. The
contract is small:

```python
NAME = "unique_id"
LABEL = "Human label shown in the menu"
DESC = "One line about what it does"
CATEGORY = "recon" | "scenario" | "decoy" | "instrumentation"
NEEDS_PORT = True | False

def run(target, port, emit) -> dict:
    emit("a line of output")
    return {"status": "pass" | "fail" | "blocked" | "complete", "summary": "..."}
```

Four statuses, and the difference between them is the point:

| status | means |
|---|---|
| `complete` | gathered data, made no claim (recon) |
| `pass` | asserted a claim, the claim held |
| `fail` | asserted a claim, it did not hold |
| `blocked` | a precondition failed, **nothing was tested** |

`blocked` exists because a check that cannot fail reads exactly like a check
that passed. If a tool is missing, or the port is closed, or the target does not
resolve, the honest answer is that no test happened — not "pass," and not
"fail." A missing binary is `blocked`, never `fail`: the fault is the
container's, and reporting it as a target failure would put a red mark on the
wrong thing.

Raise `Blocked("reason")` for a precondition failure; return a `pass`/`fail`
verdict for an actual test.

### Current modules

- `nmap_discover` — TCP connect scan, top 200 ports
- `banner_grab` — connect and read what the service says first
- `web_paths` — request common bait paths, report status codes, note whether
  bait is distinguishable from absence
- `ssh_cred_sequence` — fixed credential list in fixed order; expects
  rejections then one acceptance, and fails if the shape is wrong
- `decoy_telnet_banner` — does a decoy name itself to anyone who connects
- `decoy_wp_facade` — is `/wp-login.php` baited while `/wp-content/` 404s

## Logs

Every run appends one JSON line to `/data/runs.jsonl`: timestamp, job id,
attack, target, port, operator, **scope reason**, status, summary, elapsed time,
whether output was truncated.

The scope reason is recorded so that three weeks later a line reading
`"scope": "allowed: no scope set"` explains itself, where a bare `"allowed"`
would not.

## Limits, by design

- Output is capped per run (4000 lines / 400KB) so one runaway scan cannot fill
  the disk or wedge a browser tab.
- Jobs run in a thread per run and are held in memory; the durable record is the
  JSONL log.
- `BITWITCH_SECRET` left blank means sessions are signed with a random key
  generated at boot, so restarting the container signs everyone out. Set it to
  keep sessions across restarts.

## Status

Built and tested against live targets: 6 attack modules, auth, roles, scope
enforcement, cookie forgery resistance, and the run log. The Docker image has
**not** been built — no Docker was available on the machine where this was
written, so everything above ran under uvicorn directly. First run on a host
with Docker should be `docker compose build` and a look at the logs.
