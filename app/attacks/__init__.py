"""Attack module registry.

Every .py file in this directory that is not named __init__ is loaded as an
attack. Adding a file is the entire process of adding an attack; nothing else
in the codebase needs editing.

A module must define:

    NAME      str   stable identifier, used in URLs and logs
    LABEL     str   human label shown in the web UI
    DESC      str   one line describing what it does
    CATEGORY  str   grouping in the UI (see CATEGORY_ORDER)
    NEEDS_PORT bool whether the UI must collect a port

and a function:

    run(target, port, emit) -> dict

`emit(text)` streams a line to the browser as it happens.
The return dict should carry at least:

    status   "pass" | "fail" | "blocked" | "complete"
    summary  short human sentence

`blocked` means the module refused to run because a precondition did not
hold (target unreachable, port closed, tool missing). `blocked` is not a
failure and it is not a pass. It is a statement that no claim was tested.

This distinction exists because of a defect Trapdoor's own engagement report
names: a check that cannot fail reads exactly like a check that passed.
Anything that did not actually run must say so in its own word.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path
from types import ModuleType

_HERE = Path(__file__).resolve().parent
_PKG = __name__

CATEGORY_ORDER = [
    "recon",
    "scenario",
    "decoy",
    "instrumentation",
]


def _load(path: Path) -> ModuleType | None:
    """Import a module file as a child of this package.

    Importing by file path alone leaves the module with no parent package, so
    a relative import like `from ..jobs import Blocked` fails with "attempted
    relative import with no known parent package". The module then silently
    drops out of the catalog — observed once, with every attack except the one
    that never raised Blocked. Loading under the real package name fixes it and
    relative imports resolve normally.
    """
    name = f"{_PKG}.{path.stem}"
    try:
        if name in sys.modules:
            del sys.modules[name]
        mod = importlib.import_module(name)
    except Exception as exc:  # a broken module must not take the server down
        print(f"[registry] failed to load {path.name}: {exc}", file=sys.stderr)
        return None
    return mod


# Put the package directory on the import machinery's path so the children
# resolve by dotted name without a separate package on disk.
if str(_HERE.parent) not in sys.path:
    sys.path.insert(0, str(_HERE.parent))


def _validate(mod: ModuleType, path: Path) -> bool:
    for attr in ("NAME", "LABEL", "DESC", "CATEGORY", "NEEDS_PORT", "run"):
        if not hasattr(mod, attr):
            print(f"[registry] {path.name} missing {attr}; skipped", file=sys.stderr)
            return False
    if not callable(getattr(mod, "run")):
        print(f"[registry] {path.name} run is not callable; skipped", file=sys.stderr)
        return False
    return True


_REGISTRY: dict[str, ModuleType] | None = None


def load_all(force: bool = False) -> dict[str, ModuleType]:
    """Load every attack module. Cached unless force=True."""
    global _REGISTRY
    if _REGISTRY is not None and not force:
        return _REGISTRY

    found: dict[str, ModuleType] = {}
    for path in sorted(_HERE.glob("*.py")):
        if path.name.startswith("_"):
            continue
        mod = _load(path)
        if mod is None or not _validate(mod, path):
            continue
        name = str(mod.NAME)
        if name in found:
            print(f"[registry] duplicate NAME {name!r} in {path.name}; skipped", file=sys.stderr)
            continue
        found[name] = mod

    _REGISTRY = found
    return found


def get(name: str) -> ModuleType | None:
    return load_all().get(name)


def catalog() -> list[dict]:
    """UI-facing list, grouped by category in CATEGORY_ORDER."""
    mods = load_all().values()
    ordered = sorted(
        mods,
        key=lambda m: (
            CATEGORY_ORDER.index(m.CATEGORY) if m.CATEGORY in CATEGORY_ORDER else 99,
            m.LABEL,
        ),
    )
    return [
        {
            "name": m.NAME,
            "label": m.LABEL,
            "desc": m.DESC,
            "category": m.CATEGORY,
            "needs_port": bool(m.NEEDS_PORT),
        }
        for m in ordered
    ]
