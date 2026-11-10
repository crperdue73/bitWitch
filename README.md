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

def run(target, port, emit, path="/", protocol="ssh") -> dict:
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

Optional parameters (`path`, `protocol`) can be added to a module's signature.
They are passed only to modules that declare them, so an attack that ignores
them is unaffected. The job runner inspects the signature rather than catching
`TypeError`, because a `TypeError` raised *inside* an attack would otherwise
look identical to an attack that does not accept the parameter.

`blocked` exists because a check that cannot fail reads exactly like a check
that passed. If a tool is missing, or the port is closed, or the target does not
resolve, the honest answer is that no test happened — not "pass," and not
"fail." A missing binary is `blocked`, never `fail`: the fault is the
container's, and reporting it as a target failure would put a red mark on the
wrong thing.

Raise `Blocked("reason")` for a precondition failure; return a `pass`/`fail`
verdict for an actual test.

### Current modules

**Recon** — gather data, assert nothing.

- `nmap_discover` — TCP connect scan, top 200 ports
- `banner_grab` — connect and read what the service says first
- `dir_bust` — gobuster against a web root, curated path list
- `nikto_scan` — known-misconfiguration scan, time-boxed to 180s

**Web**

- `sql_check` — sqlmap on one URL. **Refuses** a URL with no query parameters:
  sqlmap's "no injectable parameters" against `http://host/` means nothing was
  looked at, not that the target is clean, and that false negative is the usual
  classroom outcome.

**Scenario** — loud, fast, the way an attacker actually behaves.

- `hydra_brute` — ssh/ftp/http-get, 5 usernames × 32 passwords, capped at 60
  attempts, stops on first hit. Deliberately unreproducible so the contrast with
  the scripted run below is visible in the log.
- `ssh_cred_sequence` — fixed credential list in fixed order; expects
  rejections then one acceptance, and fails if the shape is wrong

**Trapdoor checks** — written against the honeypot's own acceptance list.

- `trapdoor_web_sweep` — the exact request set and order from
  `scenarios/web-scan.sh`, including the `/login` → 401 endpoint that the
  reference list does not cover. Checks claims C1–C6.
- `trapdoor_ssh_bruteforce` — the scripted credential attack from
  `scenarios/ssh-bruteforce.sh`, plus an exact-match check on the configured
  banner (`SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u2`, claim A6/B1). Graded, not
  just printed: it fails if the accepted credential arrives before any
  rejection, because then the lesson — fail, fail, fail, then get in — is gone
  even though every step "worked."

**Interaction**

- `tcp_talk` — connect, read the greeting, send a few lines, record everything.
  This is what makes a self-outing telnet banner visible in one line.
- `decoy_telnet_banner` — does a decoy name itself to anyone who connects
- `decoy_wp_facade` — is `/wp-login.php` baited while `/wp-content/` 404s

### A note on nikto

Nikto is **not packaged in Debian**, so the image clones it from source and
installs the Perl modules it needs. One of those, `XML::Writer`, must be named
explicitly — without it nikto exits with "Required module not found" before it
scans anything, which looks exactly like a clean scan if you are only reading
the exit code. The Dockerfile runs `nikto -Version` at build time so this fails
the build instead of the classroom.

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

Built and tested against live targets: 13 attack modules, auth, roles, scope
enforcement, cookie forgery resistance, and the run log. Deployed at
`http://192.168.111.34:8099` on the test box.

**27 regression tests, all passing in the container.** Run them where the
dependencies are:

    docker compose exec -T bitwitch python3 -m unittest discover -s tests

They cover the status vocabulary, the scope gate, cookie forgery, the module
contract, and the hardcoded Trapdoor expectations. They are stdlib `unittest`,
so there is no test framework to install.

**Verified against the live Trapdoor honeypot at `192.168.111.45`:**

- `trapdoor_web_sweep` → pass. 11 bait paths 403, absent path 404, `/login` 401.
- `trapdoor_ssh_bruteforce` → pass. 5 rejections, then accepted as `root`.
  Banner is the exact configured string.
- `tcp_talk` on Cowrie:2222 → complete. The greeting is a bare login prompt.
- `dir_bust` → 12 paths, including all the bait files at 403.
- `nikto_scan` → 17 findings in 9 seconds.
- `hydra_brute` → `root:123456` accepted after 4 loud attempts.
- `sql_check` → correctly refuses a URL with no parameters.
