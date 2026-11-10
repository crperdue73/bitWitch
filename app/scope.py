"""Scope: who may be attacked.

Two roles.

  student — supplies a name, no password beyond the class password. Runs
            anything reachable. This is the Kali-box default and it is
            deliberately unconstrained.

  admin   — the classroom password plus the admin password. Sets the target
            scope. When a scope is set, students can only reach what is in it.

The scope is the boundary, and an admin sets it, not a constant in the source.
Hardcoding a CIDR would mean guessing a network I am not on and rebuilding the
image every time the class moves.

An empty scope means "no restriction" and says so out loud on the page, so
nobody can be surprised later by which state they were in.
"""

from __future__ import annotations

import ipaddress
import json
import os
import threading
from pathlib import Path

SCOPE_FILE = Path(os.environ.get("BITWITCH_SCOPE_FILE", "/data/scope.json"))

_LOCK = threading.Lock()
_CACHE: dict | None = None


def _load() -> dict:
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    try:
        _CACHE = json.loads(SCOPE_FILE.read_text())
    except (OSError, ValueError):
        _CACHE = {"networks": [], "note": ""}
    return _CACHE


def current() -> dict:
    with _LOCK:
        data = _load()
        return {
            "networks": list(data.get("networks") or []),
            "note": data.get("note", ""),
            "restricted": bool(data.get("networks")),
        }


def save(networks: list[str], note: str = "") -> dict:
    """Replace the scope. Raises ValueError on a bad entry.

    Every entry is parsed now rather than at use time, so a typo surfaces while
    an admin is looking at the screen instead of as a mystery refusal later.
    """
    cleaned: list[str] = []
    for raw in networks:
        text = (raw or "").strip()
        if not text:
            continue
        try:
            net = ipaddress.ip_network(text, strict=False)
        except ValueError as exc:
            raise ValueError(f"{text!r} is not a network or address: {exc}") from exc
        cleaned.append(str(net))

    # Dedupe while keeping the order an admin typed.
    seen = set()
    ordered = [n for n in cleaned if not (n in seen or seen.add(n))]

    global _CACHE
    with _LOCK:
        payload = {"networks": ordered, "note": note.strip()}
        SCOPE_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = SCOPE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, indent=2))
        tmp.replace(SCOPE_FILE)
        _CACHE = payload
        return dict(payload)


def check(target: str) -> tuple[bool, str]:
    """Is this target reachable under the current scope?

    Returns (allowed, reason). An empty scope allows everything, and the reason
    says so — a log line reading "allowed: no scope set" is honest about why,
    where a bare "allowed" is ambiguous three weeks later.
    """
    scope = current()
    if not scope["restricted"]:
        return True, "allowed: no scope set"

    try:
        addr = ipaddress.ip_address(target)
    except ValueError:
        return (
            False,
            f"blocked: {target} is a hostname and the scope is a list of "
            f"networks — enter an IP, or have an admin widen the scope",
        )

    for entry in scope["networks"]:
        net = ipaddress.ip_network(entry, strict=False)
        if addr in net:
            return True, f"allowed: {addr} is in {net}"

    return False, f"blocked: {addr} is not in {', '.join(scope['networks'])}"
