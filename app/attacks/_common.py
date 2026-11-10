"""Shared helpers for attack modules."""

from __future__ import annotations

import shutil

from ..jobs import Blocked


def require_tool(name: str) -> None:
    """Raise Blocked if a tool is not installed.

    A missing binary is not a failed test. Nothing ran, so nothing was proven
    and nothing was disproven. Reporting `fail` here would put a red mark in
    the log against the target when the fault is the container's — and that is
    the exact confusion Trapdoor's engagement report warns about: a result that
    looks like evidence but is a statement about the toolchain.
    """
    if shutil.which(name) is None:
        raise Blocked(f"{name} is not installed in this container")
