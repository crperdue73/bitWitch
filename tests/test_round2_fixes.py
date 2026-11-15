"""Round-2 fixes: the five things Jim measured and I fixed.

Run with:  python3 -m unittest tests.d5_round2 -v

One test class per fix. Each test names the number it measures and the number
that would be alarming, so a reader can tell a pass from a silent no-op.

The five:
  1. README names the compose plugin as a prerequisite.      (O1)
  2. README says "docker bridge", never a hard-coded name.   (O2)
  3. _require_stamp is cost-per-use, not cost-at-boot.       (O3)
  4. Login throttle: token bucket, not a per-minute window.  (new)
  5. Blank admin password warns loudly AND still serves.     (new)

Probe convention: tests that need a pristine module import run the probe in a
subprocess, because app.main reads its config at import time and a test process
that has already imported it cannot un-import it.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Every test in this file needs fastapi, because every one of them either
# starts the app or runs a probe that does. Without it they must SKIP with a
# reason, not ERROR - that is the D5 finding, and a suite where the strongest
# tests vanish into red on a box without the dep is the same defect wearing
# different clothes. The skip is module-level and named so the count is honest.
def _have_test_deps() -> bool:
    for mod in ("fastapi", "httpx"):
        try:
            __import__(mod)
        except Exception:
            return False
    return True


HAVE_DEPS = _have_test_deps()
NEEDS_DEPS = unittest.skipUnless(
    HAVE_DEPS,
    "needs fastapi+httpx: pip install -r requirements-test.txt",
)


def _probe(body: str, env_extra: dict | None = None) -> list[str]:
    """Run a probe script in a subprocess with the app importable.

    The body must print; the last line is taken as the machine-readable answer.
    ROOTPATH is substituted rather than using %-formatting, because probe
    scripts contain braces and percent signs of their own.
    """
    script = body.replace("ROOTPATH", repr(str(ROOT)))
    env = {
        **os.environ,
        "BITWITCH_ALLOW_UNSTAMPED": "1",
        "GIT_COMMIT": "",
        "BITWITCH_PASSWORD": "classpw",
        "BITWITCH_ADMIN_PASSWORD": "",
        "BITWITCH_MAX_LOGIN_FAILURES": "5",
        "BITWITCH_LOCKOUT_SECONDS": "0.2",
    }
    if env_extra:
        env.update(env_extra)
    out = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        cwd=str(ROOT),
        env=env,
    )
    if out.returncode != 0:
        raise AssertionError(f"probe failed rc={out.returncode}: {out.stderr[-1200:]}")
    return out.stdout.strip().splitlines()


class ReadmeComposeTests(unittest.TestCase):
    """Fix 1: the README must name the compose plugin, or step 3 exits 125.

    Alarming number: README instructs `docker compose` but never says the
    plugin is a separate package. On a bare Debian box that is exit 125 and
    nothing built.
    """

    def test_readme_mentions_compose_plugin_installation(self):
        text = (ROOT / "README.md").read_text()
        self.assertTrue(
            "docker-compose-v2" in text or "docker-compose-plugin" in text,
            "README does not name a compose plugin package to install",
        )

    def test_readme_tells_you_how_to_check(self):
        text = (ROOT / "README.md").read_text()
        self.assertIn(
            "docker compose version",
            text,
            "README never tells the reader to verify the plugin is present",
        )

    def test_readme_does_not_claim_one_prerequisite(self):
        text = (ROOT / "README.md").read_text()
        self.assertNotIn(
            "One prerequisite and two steps",
            text,
            "README still claims a single prerequisite, which is the O1 fault",
        )


class ReadmeBridgeTests(unittest.TestCase):
    """Fix 2: no hard-coded docker bridge name in the README.

    Measured exactly the way Jim measures it: `grep -c "br-"` must be 0.
    A test cleverer than the check being run is not a better test, it is a
    different claim.
    """

    def test_no_br_prefix_at_all(self):
        text = (ROOT / "README.md").read_text()
        self.assertEqual(
            text.count("br-"),
            0,
            "README contains 'br-'; a named bridge is the O2 finding growing back",
        )

    def test_readme_says_docker_bridge(self):
        text = (ROOT / "README.md").read_text().lower()
        self.assertGreaterEqual(
            text.count("docker bridge"),
            1,
            "README does not use the phrase 'docker bridge' anywhere",
        )

    def test_readme_mentions_ufw(self):
        text = (ROOT / "README.md").read_text().lower()
        self.assertIn(
            "ufw",
            text,
            "README never mentions ufw, so the container-to-host failure is undocumented",
        )


@NEEDS_DEPS
class StampPerRequestTests(unittest.TestCase):
    """Fix 3: the unstamped warning must fire per request, not once at import.

    Alarming number: 1 warning for 20 requests. That is what a module-level
    call site produces, and it is the O3 finding.
    """

    def test_warning_fires_once_per_request(self):
        lines = _probe(
            """
import contextlib, io, sys
sys.path.insert(0, ROOTPATH)
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    from app import main
    from fastapi.testclient import TestClient
    c = TestClient(main.app)
    for _ in range(20):
        c.get("/api/health")
n = buf.getvalue().count("WARNING: serving an UNSTAMPED build")
print("warnings", n)
"""
        )
        n = int(lines[-1].split()[1])
        self.assertEqual(
            n,
            20,
            f"20 requests produced {n} unstamped warnings. "
            "1 would mean the check is still at import time (the O3 fault).",
        )


@NEEDS_DEPS
class LoginThrottleTests(unittest.TestCase):
    """Fix 4: a token bucket, not a per-minute window.

    Alarming numbers:
      * no 429 within MAX_LOGIN_FAILURES+1 consecutive bad logins
      * the count to first 429 does not match the configured capacity
      * rapid retries after exhaustion are not all 429 (the bucket refilling
        as fast as attacks land)
      * a correct login after the lockout window does not work
    """

    def test_count_to_first_429_matches_capacity(self):
        lines = _probe(
            """
import sys
sys.path.insert(0, ROOTPATH)
from app import main
from fastapi.testclient import TestClient
c = TestClient(main.app)
cap = main.MAX_LOGIN_FAILURES
first = None
for i in range(1, cap + 6):
    r = c.post("/login", data={"operator": "x", "password": "wrong"}, follow_redirects=False)
    if r.status_code == 429:
        first = i
        break
print("RESULT", cap, first)
"""
        )
        _, cap, first = lines[-1].split()
        self.assertEqual(
            int(first),
            int(cap) + 1,
            f"capacity is {cap} but the first 429 came at attempt {first}; "
            "they must be one apart (cap bad logins allowed, the next refused)",
        )

    def test_rapid_retries_after_exhaustion_all_refused(self):
        lines = _probe(
            """
import sys
sys.path.insert(0, ROOTPATH)
from app import main
from fastapi.testclient import TestClient
c = TestClient(main.app)
cap = main.MAX_LOGIN_FAILURES
for i in range(cap + 3):
    c.post("/login", data={"operator": "y", "password": "wrong"}, follow_redirects=False)
codes = []
for i in range(5):
    r = c.post("/login", data={"operator": "y", "password": "wrong"}, follow_redirects=False)
    codes.append(r.status_code)
print("RESULT", codes)
"""
        )
        codes = eval(lines[-1].split("RESULT", 1)[1].strip())
        self.assertEqual(
            codes,
            [429] * 5,
            f"after exhausting the bucket, rapid retries returned {codes}; "
            "all must be 429, or the bucket refills as fast as attacks land",
        )

    def test_correct_login_after_lockout_recovers(self):
        lines = _probe(
            """
import sys, time
sys.path.insert(0, ROOTPATH)
from app import main
from fastapi.testclient import TestClient
c = TestClient(main.app)
cap = main.MAX_LOGIN_FAILURES
for i in range(cap + 3):
    c.post("/login", data={"operator": "z", "password": "wrong"}, follow_redirects=False)
blocked = c.post("/login", data={"operator": "z", "password": "classpw"}, follow_redirects=False)
time.sleep(main.LOCKOUT_SECONDS + 0.15)
recovered = c.post("/login", data={"operator": "z", "password": "classpw"}, follow_redirects=False)
print("RESULT", blocked.status_code, recovered.status_code)
"""
        )
        _, blocked, recovered = lines[-1].split()
        self.assertEqual(blocked, "429", "a locked-out client was not refused")
        self.assertEqual(
            recovered,
            "303",
            f"after the lockout window the correct password returned {recovered}, not 303; "
            "the throttle is locking out the legitimate user",
        )

    def test_success_resets_the_bucket(self):
        """A user who mistypes twice and then gets it right must start fresh."""
        lines = _probe(
            """
import sys
sys.path.insert(0, ROOTPATH)
from app import main
from fastapi.testclient import TestClient
c = TestClient(main.app)
cap = main.MAX_LOGIN_FAILURES
# burn all but one token
for i in range(cap - 1):
    c.post("/login", data={"operator": "w", "password": "wrong"}, follow_redirects=False)
ok = c.post("/login", data={"operator": "w", "password": "classpw"}, follow_redirects=False)
# Reset state is represented by the key being ABSENT, not by a full list.
# Absent means "never limited", which is the same thing as full.
present = "testclient" in main._LOGIN_BUCKET
print("RESULT", ok.status_code, present)
"""
        )
        _, status, present = lines[-1].split()
        self.assertEqual(status, "303", "correct login was refused")
        self.assertEqual(
            present,
            "False",
            "the throttle bucket still exists after a successful login; "
            "a success must reset the client to an unthrottled state",
        )


@NEEDS_DEPS
class BlankAdminWarningTests(unittest.TestCase):
    """Fix 5: warn loudly at startup AND still serve. Not one or the other.

    Alarming numbers:
      * no warning line naming the consequence -> silent state
      * the app refuses to start -> a behaviour change nobody asked for
    """

    def test_warns_and_still_serves(self):
        lines = _probe(
            """
import contextlib, io, sys
sys.path.insert(0, ROOTPATH)
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    from app import main
    from fastapi.testclient import TestClient
    code = TestClient(main.app).get("/login").status_code
out = buf.getvalue()
print("RESULT", code,
      "warned=" + str("BITWITCH_ADMIN_PASSWORD is blank" in out),
      "names_consequence=" + str("STUDENT session" in out))
"""
        )
        _, code, warned, names = lines[-1].split()
        self.assertEqual(code, "200", "the app did not keep serving with a blank admin password")
        self.assertEqual(warned, "warned=True", "no startup warning about the blank admin password")
        self.assertEqual(names, "names_consequence=True", "the warning does not name the consequence")


if __name__ == "__main__":
    unittest.main()
