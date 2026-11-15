"""Error-path tests: every module must refuse, not crash.

Run with:  python3 -m unittest discover -s tests -v
Or against any checkout:  BITWITCH_REPO=/opt/bitwitch python3 tests/d3_error_paths.py

Why this file exists
--------------------

`ModuleContractTests` checks that every module has NAME, LABEL, DESC, CATEGORY,
NEEDS_PORT and a callable run() that accepts three positional args. It never
calls run() on a target that fails.

So a module that raises `Blocked` without importing it passes the contract
check and crashes the moment a student points it at a port with nothing
behind it. That is exactly what happened: `c_web_paths.py` raised `Blocked`
twice and imported it zero times. Twenty-seven tests were green and every
student who mistyped a port got a Python traceback instead of a sentence
telling them their target was wrong.

The check
---------

One test per module. Call `run()` against a closed port, in a subprocess, and
assert the exception is `Blocked`.

Three details that matter, and all three were deliberate:

  * It asserts the exception TYPE is `Blocked`, not that the call merely
    fails. A test asserting "it raised something" goes green against the
    NameError. The type is the whole claim.

  * It runs in a subprocess. A module that raises something uncaught in this
    process could take the suite with it, and a missing import is exactly the
    kind of fault that surfaces only at first call in a fresh interpreter.

  * The port is closed by construction — port 9 on 127.0.0.1 (discard). No
    network, no target, no environment. The module must refuse on its own
    logic, not on a condition the test arranged.

What a failure tells you: the module has an error path that raises something
other than `Blocked`. Usually a missing import. Always a module that has never
been run on its failure path.
"""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# 127.0.0.1:9 is the discard port. Nothing listens; the connection is refused
# immediately and locally. This is the condition every module gets, and it is
# the condition a student reproduces by pointing at a port with nothing on it.
CLOSED = ("127.0.0.1", 9)

# A module may legitimately say "I need a port" before it ever connects. That
# is still Blocked, so it passes. What fails is anything else.
PROBE = r"""
import json, sys
sys.path.insert(0, {root!r})
from app import attacks
attacks.load_all(force=True)
mods = attacks.load_all()
name = {name!r}
mod = mods[name]
lines = []
out = {{"_lines": lines}}
try:
    result = mod.run({target!r}, {port!r}, lines.append)
    out["status"] = "returned"
    out["result"] = result if isinstance(result, dict) else repr(result)
except BaseException as exc:
    out["status"] = "raised"
    out["exc_type"] = type(exc).__name__
    out["exc_module"] = type(exc).__module__
    out["exc_mro"] = [c.__name__ for c in type(exc).__mro__]
    out["exc_str"] = str(exc)[:400]
print(json.dumps(out))
"""


def _probe(name, repo=None):
    import subprocess as _sp
    code = PROBE.format(root=str(repo or ROOT), name=name,
                        target=CLOSED[0], port=CLOSED[1])
    proc = _sp.run([sys.executable, "-c", code], capture_output=True,
                   text=True, timeout=60)
    if proc.returncode != 0:
        return {"status": "crashed", "stderr": proc.stderr[-1200:],
                "_lines": []}
    try:
        return json.loads(proc.stdout.strip().splitlines()[-1])
    except Exception:
        return {"status": "unparsable", "stdout": proc.stdout[-600:],
                "_lines": []}


class ErrorPathTests(unittest.TestCase):
    """Every module must raise Blocked — by type — when it cannot run."""

    @classmethod
    def setUpClass(cls):
        from app import attacks
        attacks.load_all(force=True)
        cls.mods = attacks.load_all()
        cls.names = sorted(cls.mods)

    def test_every_module_refuses_cleanly(self):
        """The whole claim in one test, so a count is printable."""
        failures = []
        for name in self.names:
            out = _probe(name)
            if out.get("status") == "raised" and "Blocked" in out.get("exc_mro", []):
                continue
            if out.get("status") == "raised":
                failures.append(
                    f"{name}: raised {out.get('exc_type')} "
                    f"({out.get('exc_module')}) instead of Blocked: "
                    f"{out.get('exc_str', '')[:160]}"
                )
            else:
                # Returned without raising. Not automatically wrong — a module
                # may complete against a closed port if it is not
                # connection-bound — but it must say so in the vocabulary.
                failures.append(
                    f"{name}: did not raise Blocked, returned "
                    f"{out.get('status')} {str(out.get('result'))[:160]}"
                )
        print(f"\n  error-path probe: {len(self.names)} modules, "
              f"{len(failures)} did not refuse with Blocked")
        if failures:
            self.fail(
                f"{len(failures)} of {len(self.names)} modules have an error "
                "path that raises something other than Blocked. A missing "
                "import is the usual cause:\n  " + "\n  ".join(failures)
            )

    def test_one_named_check_per_module(self):
        """Same check, one test each, so a failure names itself."""
        pass  # replaced below by generated methods


def _make_probe(name):
    def test(self):
        out = _probe(name)
        status = out.get("status")
        if status == "raised":
            self.assertIn(
                "Blocked", out.get("exc_mro", []),
                msg=f"{name}.run on a closed port raised "
                    f"{out.get('exc_type')} ({out.get('exc_module')}), not "
                    f"Blocked. A test asserting only that it fails would have "
                    f"gone green against this. Message: "
                    f"{out.get('exc_str', '')[:300]}",
            )
        else:
            self.fail(
                f"{name}.run on a closed port did not raise; it returned "
                f"{status}: {str(out.get('result') or out.get('stderr'))[:300]}"
            )
    test.__name__ = f"test_{name}_refuses_with_blocked"
    return test


def _install():
    from app import attacks
    attacks.load_all(force=True)
    for name in sorted(attacks.load_all()):
        setattr(ErrorPathTests, f"test_{name}_refuses_with_blocked",
                _make_probe(name))


_install()


if __name__ == "__main__":
    unittest.main(verbosity=2)
