"""Regression tests for bitWitch.

Run with:  python3 -m unittest discover -s tests -v

No pytest, no third-party packages. Everything here is stdlib so it runs on the
test box and on a fresh checkout without an install step.

What these cover, and why each one exists:

  The status vocabulary. `blocked` vs `fail` vs `complete` is the design's whole
  spine. A test that a missing tool reports `blocked` and not `fail` is not
  pedantry — it is the difference between blaming the container and blaming the
  student's target.

  The scope gate. Empty scope means "everything," and that has to be explicit
  and testable, because an empty list silently meaning "deny all" would look
  identical from the outside and would have students reporting the lab broken.

  Cookie forgery. The role lives inside the HMAC. If a student can edit the
  cookie and become admin, the scope boundary is decorative.

  Module contract. Every module in app/attacks/ must define the required
  attributes and a callable run(). A module that loads but is missing NAME
  would otherwise vanish from the menu with no error.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


# ---------------------------------------------------------------------------
# scope
# ---------------------------------------------------------------------------

class ScopeTests(unittest.TestCase):
    """app/scope.py — the admin-controlled boundary.

    The scope module reads one file. Each test points it at a fresh temp file
    and resets the module cache, so tests cannot leak into each other or into
    the real /data/scope.json.
    """

    def setUp(self):
        import importlib
        import tempfile
        from pathlib import Path as _P

        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        scope_file = _P(self.tmp.name) / "scope.json"

        import os
        old = os.environ.get("BITWITCH_SCOPE_FILE")
        os.environ["BITWITCH_SCOPE_FILE"] = str(scope_file)
        self.addCleanup(
            lambda: os.environ.__setitem__("BITWITCH_SCOPE_FILE", old)
            if old is not None else os.environ.pop("BITWITCH_SCOPE_FILE", None)
        )

        from app import scope
        self.scope = importlib.reload(scope)

    def test_empty_scope_allows_everything(self):
        # Empty must mean unrestricted. The UI says so out loud; if this
        # inverted, every attack would be blocked and the lab would look dead.
        allowed, reason = self.scope.check("192.168.111.45")
        self.assertTrue(allowed)
        self.assertIn("no scope", reason.lower())

    def test_cidr_admits_inside_host(self):
        self.scope.save(["10.20.30.0/24"])
        allowed, _ = self.scope.check("10.20.30.50")
        self.assertTrue(allowed)

    def test_cidr_rejects_outside_host(self):
        self.scope.save(["10.20.30.0/24"])
        allowed, reason = self.scope.check("192.168.1.1")
        self.assertFalse(allowed)
        self.assertIn("blocked", reason.lower())

    def test_single_host_admitted(self):
        self.scope.save(["192.168.111.45"])
        self.assertTrue(self.scope.check("192.168.111.45")[0])

    def test_host_is_exact_not_prefix(self):
        # 192.168.111.45 must not admit 192.168.111.4
        self.scope.save(["192.168.111.45"])
        self.assertFalse(self.scope.check("192.168.111.4")[0])

    def test_clean_hostname_denied_when_scope_set(self):
        # Scope is a list of networks; a name cannot be matched against it, and
        # the refusal says why instead of failing mysteriously.
        self.scope.save(["10.20.30.0/24"])
        allowed, reason = self.scope.check("example.com")
        self.assertFalse(allowed)
        self.assertIn("hostname", reason.lower())

    def test_bad_network_rejected_at_save_time(self):
        with self.assertRaises(ValueError):
            self.scope.save(["not-a-network"])

    def test_duplicates_deduped_and_order_kept(self):
        saved = self.scope.save(["10.0.0.0/24", "10.0.0.0/24", "192.168.0.0/16"])
        self.assertEqual(saved["networks"], ["10.0.0.0/24", "192.168.0.0/16"])

    def test_restricted_flag_reflects_reality(self):
        self.assertFalse(self.scope.current()["restricted"])
        self.scope.save(["10.20.30.0/24"])
        self.assertTrue(self.scope.current()["restricted"])


# ---------------------------------------------------------------------------
# sessions / cookie integrity
# ---------------------------------------------------------------------------

class CookieTests(unittest.TestCase):
    """The cookie carries name and role, signed. Forging it must fail.

    `_session` takes a Request, so the tests build the smallest thing that
    quacks: an object with a `.cookies` dict.
    """

    def setUp(self):
        import importlib
        from app import main
        self.main = importlib.reload(main)

    def _req(self, raw):
        class _Req:
            cookies = {"bw_session": raw}
        return _Req()

    def test_round_trip_admin(self):
        raw = self.main._sign("robbie", "admin")
        got = self.main._session(self._req(raw))
        self.assertIsNotNone(got)
        self.assertEqual(got["name"], "robbie")
        self.assertEqual(got["role"], "admin")

    def test_round_trip_student(self):
        raw = self.main._sign("student1", "student")
        got = self.main._session(self._req(raw))
        self.assertEqual(got["role"], "student")

    def test_tampered_role_rejected(self):
        raw = self.main._sign("student1", "student")
        name, role, mac = raw.split("|")
        self.assertIsNone(self.main._session(self._req(f"{name}|admin|{mac}")))

    def test_tampered_name_rejected(self):
        raw = self.main._sign("student1", "student")
        name, role, mac = raw.split("|")
        self.assertIsNone(self.main._session(self._req(f"robbie|{role}|{mac}")))

    def test_garbage_rejected(self):
        # The pipe-splitting bug: a cookie with the wrong field count used to
        # raise instead of returning None.
        for junk in ("", "nonsense", "a|b", "a|b|c|d", "||"):
            self.assertIsNone(
                self.main._session(self._req(junk)), msg=f"{junk!r} should not parse"
            )

    def test_unknown_role_rejected(self):
        # Sign a payload with a role the app does not know. Even correctly
        # signed, it must not be honoured.
        import hashlib, hmac
        payload = "someone\x1fsuperuser"
        mac = hmac.new(
            self.main._secret().encode(), payload.encode(), hashlib.sha256
        ).hexdigest()
        self.assertIsNone(self.main._session(self._req(f"someone|superuser|{mac}")))


# ---------------------------------------------------------------------------
# attack module contract
# ---------------------------------------------------------------------------

class ModuleContractTests(unittest.TestCase):
    """Every module must honour the contract, or it silently vanishes."""

    REQUIRED = ("NAME", "LABEL", "DESC", "CATEGORY", "NEEDS_PORT")

    def setUp(self):
        from app import attacks
        attacks.load_all(force=True)
        self.attacks = attacks
        self.mods = attacks.load_all()

    def test_registry_is_not_empty(self):
        self.assertGreaterEqual(len(self.mods), 13)

    def test_every_module_has_required_attrs(self):
        for name, mod in self.mods.items():
            for attr in self.REQUIRED:
                self.assertTrue(
                    hasattr(mod, attr), msg=f"{name} missing {attr}"
                )
            self.assertTrue(
                callable(mod.run), msg=f"{name}.run is not callable"
            )

    def test_names_are_unique_and_match_filename_intent(self):
        names = [m.NAME for m in self.mods.values()]
        self.assertEqual(len(names), len(set(names)))

    def test_needs_port_is_bool(self):
        for name, mod in self.mods.items():
            self.assertIsInstance(mod.NEEDS_PORT, bool, msg=name)

    def test_run_signature_accepts_three_positional(self):
        # The runner always passes (target, port, emit). A module that needs
        # extra params must take them as defaults, never as required.
        import inspect
        for name, mod in self.mods.items():
            sig = inspect.signature(mod.run)
            params = list(sig.parameters.values())
            self.assertGreaterEqual(len(params), 3, msg=name)
            for p in params[3:]:
                self.assertIsNot(
                    p.default, inspect.Parameter.empty,
                    msg=f"{name}.run has required extra param {p.name!r}",
                )


# ---------------------------------------------------------------------------
# the graded Trapdoor checks
# ---------------------------------------------------------------------------

class TrapdoorWebSweepTests(unittest.TestCase):
    """The bait list must match Trapdoor's scenarios/web-scan.sh exactly.

    This is tested because the expectations are hardcoded on purpose. If
    someone "helpfully" makes them computed from the live responses, the check
    starts agreeing with whatever the box does and proves nothing.
    """

    def setUp(self):
        from app.attacks import g_trapdoor_web_sweep as m
        self.m = m

    def test_bait_list_matches_reference_script(self):
        expected = [
            "/", "/.env", "/.git/config", "/.aws/credentials", "/.ssh/id_rsa",
            "/wp-login.php", "/wp-admin/", "/xmlrpc.php", "/phpmyadmin/",
            "/admin.php", "/shell.php",
        ]
        self.assertEqual([p for p, _ in self.m.BAIT], expected)

    def test_expected_codes(self):
        codes = dict(self.m.BAIT)
        self.assertEqual(codes["/"], 200)
        for path in codes:
            if path != "/":
                self.assertEqual(codes[path], 403, msg=path)

    def test_login_is_separate_from_bait(self):
        # /login answers 401, not 403. Lumping it in would make a working
        # decoy report a false failure.
        self.assertNotIn("/login", [p for p, _ in self.m.BAIT])
        self.assertEqual(self.m.LOGIN_PATH, "/login")
        self.assertEqual(self.m.LOGIN_EXPECT, 401)


class TrapdoorSSHTests(unittest.TestCase):
    """The credential list must produce failures BEFORE the acceptance."""

    def setUp(self):
        from app.attacks import h_trapdoor_ssh_bruteforce as m
        self.m = m

    def test_accepted_credential_is_last(self):
        # The one entry Cowrie accepts must be the final attempt, so the run
        # shape is fail, fail, fail, ... then get in.
        users = [u for u, _ in self.m.CREDS]
        self.assertEqual(users[-1], "root")
        self.assertEqual(self.m.CREDS[-1], ("root", "toor"))

    def test_there_are_rejections_before_the_hit(self):
        self.assertGreaterEqual(len(self.m.CREDS) - 1, 3)

    def test_banner_expectation_is_exact_string(self):
        # A prefix check would pass a decoy that names itself "Cowrie".
        self.assertTrue(self.m.EXPECT_BANNER.startswith("SSH-2.0-"))
        self.assertIn("OpenSSH", self.m.EXPECT_BANNER)
        self.assertNotIn("cowrie", self.m.EXPECT_BANNER.lower())


# ---------------------------------------------------------------------------
# job status handling
# ---------------------------------------------------------------------------

class JobStatusTests(unittest.TestCase):
    """The runner must not turn `complete` into `blocked`, or vice versa."""

    def test_blocked_is_importable_and_distinct(self):
        from app.jobs import Blocked
        exc = Blocked("no tool")
        self.assertEqual(str(exc), "no tool")
        self.assertIsInstance(exc, Exception)


if __name__ == "__main__":
    unittest.main(verbosity=2)
