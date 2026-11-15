"""Job execution: spawn, stream, time out, cap output.

One job = one attack run. Jobs live in memory because a classroom run is
short-lived and the durable record is the JSONL log on disk, not the queue.

Design notes tied to Trapdoor's engagement report:

  * Every job records its own preconditions in the transcript before the
    first packet, so a later reader can tell "ran and passed" from "never
    sent anything."
  * A job that produced no output at all is `blocked`, never `complete`.
    Silence is not success.
"""

from __future__ import annotations

import inspect
import json
import os
import threading
import time
import traceback
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import attacks

RUN_LOG = Path(os.environ.get("BITWITCH_RUN_LOG", "/data/runs.jsonl"))
MAX_LINES = int(os.environ.get("BITWITCH_MAX_LINES", "4000"))
MAX_CHARS = int(os.environ.get("BITWITCH_MAX_CHARS", "400000"))
DEFAULT_TIMEOUT = int(os.environ.get("BITWITCH_TIMEOUT", "600"))


class Blocked(Exception):
    """Raised by an attack module when a precondition does not hold."""


@dataclass
class Job:
    id: str
    attack: str
    target: str
    port: int | None
    operator: str
    scope_note: str = ""
    opts: dict = field(default_factory=dict)
    started: float = field(default_factory=time.time)
    finished: float | None = None
    lines: list[str] = field(default_factory=list)
    status: str = "running"
    summary: str = ""
    chars: int = 0
    truncated: bool = False
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def emit(self, text: str) -> None:
        with self._lock:
            if len(self.lines) >= MAX_LINES or self.chars >= MAX_CHARS:
                if not self.truncated:
                    self.truncated = True
                    self.lines.append(
                        f"[bitWitch] output capped at {MAX_LINES} lines / "
                        f"{MAX_CHARS} chars — remaining output discarded"
                    )
                return
            for raw in str(text).splitlines() or [""]:
                if len(self.lines) >= MAX_LINES:
                    self.truncated = True
                    break
                self.lines.append(raw)
                self.chars += len(raw) + 1

    def snapshot(self, since: int = 0) -> dict[str, Any]:
        with self._lock:
            return {
                "id": self.id,
                "attack": self.attack,
                "target": self.target,
                "port": self.port,
                "operator": self.operator,
                "status": self.status,
                "summary": self.summary,
                "truncated": self.truncated,
                "elapsed": round((self.finished or time.time()) - self.started, 1),
                "lines": self.lines[since:],
                "cursor": len(self.lines),
            }


_JOBS: dict[str, Job] = {}
_JOBS_LOCK = threading.Lock()


def get_job(job_id: str) -> Job | None:
    with _JOBS_LOCK:
        return _JOBS.get(job_id)


def _record(job: Job, result: dict | None, error: str | None) -> None:
    """Append the durable record. Never raises into the caller."""
    try:
        RUN_LOG.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "job_id": job.id,
            "attack": job.attack,
            "target": job.target,
            "port": job.port,
            "operator": job.operator,
            "scope": job.scope_note,
            "status": job.status,
            "summary": job.summary,
            "elapsed_s": round((job.finished or time.time()) - job.started, 2),
            "truncated": job.truncated,
            "error": error,
            "result": result,
            "lines": len(job.lines),
        }
        with RUN_LOG.open("a") as fh:
            fh.write(json.dumps(entry) + "\n")
    except Exception:
        print(f"[jobs] failed to write run log: {traceback.format_exc()}")


def record_refusal(
    attack_name: str,
    target: str,
    operator: str,
    reason: str,
    port: int | None = None,
) -> None:
    """Append a durable record for a run that was refused before it started.

    A refusal that cannot be recorded is not a refusal, it is an unverified
    claim: the student was told no, and nothing durable says they asked. The
    compose file promises the run log holds "who, what, where, why it was
    allowed, verdict" — a refused attempt is the line an instructor most wants
    to read, and it was the one line that never got written.

    Same shape as an allowed record, so one parser reads both, with
    ``status: refused`` and ``scope`` carrying the reason.

    Unlike _record, this one **raises**. An allowed job that fails to log is a
    lost line; a refused job that fails to log is a boundary crossed with no
    trace, handed back as a clean 403. The caller turns this into a 500, which
    should be unreachable in normal operation — if that 500 ever fires, it is
    its own alarm.
    """
    RUN_LOG.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "job_id": None,
        "attack": attack_name,
        "target": target,
        "port": port,
        "operator": operator,
        "scope": reason,
        "status": "refused",
        "summary": reason,
        "elapsed_s": 0.0,
        "truncated": False,
        "error": None,
        "result": None,
        "lines": 0,
    }
    with RUN_LOG.open("a") as fh:
        fh.write(json.dumps(entry) + "\n")


def start(
    attack_name: str,
    target: str,
    port: int | None,
    operator: str,
    scope_note: str = "",
    opts: dict | None = None,
) -> Job:
    mod = attacks.get(attack_name)
    if mod is None:
        raise KeyError(attack_name)

    job = Job(
        id=uuid.uuid4().hex[:12],
        attack=attack_name,
        target=target,
        port=port,
        operator=operator or "anonymous",
        scope_note=scope_note,
        opts=dict(opts or {}),
    )
    with _JOBS_LOCK:
        _JOBS[job.id] = job

    def runner() -> None:
        result = None
        error = None
        job.emit(f"[bitWitch] job {job.id}")
        job.emit(f"[bitWitch] attack  {mod.LABEL} ({mod.NAME})")
        job.emit(f"[bitWitch] target  {target}" + (f":{port}" if port else ""))
        job.emit(f"[bitWitch] operator {job.operator} ({job.scope_note})")
        job.emit(f"[bitWitch] {datetime.now(timezone.utc).isoformat()}")
        job.emit("")
        try:
            # Optional params (path, protocol, ...) are passed only when the
            # module declares it takes them, so a module that predates the
            # mechanism keeps working unchanged.
            extra = job.opts or {}
            sig = inspect.signature(mod.run)
            takes_kwargs = any(
                p.kind is inspect.Parameter.VAR_KEYWORD
                for p in sig.parameters.values()
            )
            accepted = {
                k: v for k, v in extra.items()
                if takes_kwargs or k in sig.parameters
            }
            result = mod.run(target, port, job.emit, **accepted) or {}
            status = str(result.get("status", "") or "").strip().lower()
            if status == "complete":
                # `complete` means the module ran and has nothing to assert —
                # it gathered data but made no pass/fail claim (recon). That is
                # a legitimate outcome and must not be reported as blocked,
                # which would claim nothing ran at all.
                status = "complete"
            elif status not in ("pass", "fail", "blocked"):
                # A module that returns without a verdict did not state a claim.
                status = "blocked"
                job.emit("")
                job.emit(
                    f"[bitWitch]   module returned unrecognised "
                    f"status {result.get('status')!r}; nothing was tested"
                )
            job.status = status
            job.summary = str(result.get("summary", "") or "")
        except Blocked as exc:
            job.status = "blocked"
            job.summary = str(exc)
            job.emit("")
            # The detailed reason is emitted here; `finally` prints the outcome
            # line. Printing the reason in both places duplicated every blocked
            # summary verbatim, which reads like two separate failures.
            for line in str(exc).splitlines():
                job.emit(f"[bitWitch]   {line}")
            job.emit("")
            job.emit("[bitWitch] nothing was tested — see the reason above.")
        except Exception as exc:
            job.status = "fail"
            error = f"{type(exc).__name__}: {exc}"
            job.summary = error
            job.emit("")
            job.emit(f"[bitWitch] ERROR — {error}")
            job.emit(traceback.format_exc())
        finally:
            job.finished = time.time()
            if job.status == "running":
                job.status = "blocked"
            if not job.lines:
                job.status = "blocked"
                job.summary = job.summary or "no output produced"
            job.emit("")
            job.emit(
                f"[bitWitch] {job.status.upper()}"
                + (f" — {job.summary}" if job.summary else "")
                + f"  ({round(job.finished - job.started, 1)}s)"
            )
            _record(job, result, error)

    t = threading.Thread(target=runner, name=f"job-{job.id}", daemon=True)
    t.start()
    return job
