"""Deleting things - carefully, with a written record."""
from __future__ import annotations

import json
import os
import shutil
import stat
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

from . import rules
from .model import Finding
from .settings import app_data_dir
from .winutil import empty_recycle_bin, norm

try:
    from send2trash import send2trash
except Exception:  # pragma: no cover
    send2trash = None


@dataclass
class CleanReport:
    freed: int = 0
    ok: int = 0
    failed: list[tuple[str, str]] = field(default_factory=list)
    cancelled: bool = False


def log_path() -> str:
    return os.path.join(app_data_dir(), "cleanup_log.jsonl")


def _refuse(path: str) -> str | None:
    """Return a reason string if this path must never be deleted."""
    n = norm(path)
    drive, tail = os.path.splitdrive(n)
    if tail in ("", os.sep, "/"):
        return "refusing to delete a drive root"
    parts = tail.strip(os.sep).split(os.sep)
    if len(parts) == 1 and parts[0].lower() in rules.PROTECTED_ROOT_DIRS:
        return "refusing to delete a protected system folder"
    if parts and parts[0].lower() in ("windows", "program files", "program files (x86)") and len(parts) <= 2 \
            and parts[-1].lower() not in ("temp", "memory.dmp"):
        return "refusing to delete inside a protected system folder"
    if len(parts) == 2 and parts[0].lower() == "users":
        return "refusing to delete a user profile"
    base = os.path.basename(n)
    if base in ("ntuser.dat", "pagefile.sys", "hiberfil.sys", "swapfile.sys"):
        return "system file"
    if rules.is_model_store(path):
        return "model store - never deleted by SmartCleaner"
    return None


def _clear_readonly(path: str) -> None:
    try:
        os.chmod(path, stat.S_IWRITE)
    except OSError:
        pass


def _rmtree(path: str) -> None:
    def onerr(func, p, exc):
        _clear_readonly(p)
        func(p)
    shutil.rmtree(path, onexc=onerr)


def delete_findings(findings: list[Finding], permanent: bool,
                    progress: Callable[[str, int, int], None] | None = None,
                    cancel: threading.Event | None = None,
                    by: str = "gui") -> CleanReport:
    """Remove the given findings. Recycle Bin by default; permanent if asked.

    progress(current_path, done, total)
    `by` is written to the log so a headless clean-up ("cli") can be told apart from one
    you started yourself ("gui").
    """
    rep = CleanReport()
    total = len(findings)
    log = open(log_path(), "a", encoding="utf-8")
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    mode = "permanent" if permanent else "recycle"

    def record(f: Finding) -> None:
        rep.ok += 1
        rep.freed += f.size
        log.write(json.dumps({"t": stamp, "path": f.path, "size": f.size, "cat": f.category, "mode": mode, "by": by}) + "\n")

    def remove_one(f: Finding) -> None:
        if f.category == "recycle":
            root = os.path.splitdrive(f.path)[0] + os.sep
            if not empty_recycle_bin(root):
                raise OSError("SHEmptyRecycleBin failed")
        elif not os.path.lexists(f.path):
            raise FileNotFoundError("already gone")
        elif permanent or send2trash is None or f.category == "empty":
            if f.is_dir:
                if f.category == "empty":
                    os.rmdir(f.path)
                else:
                    _rmtree(f.path)
            else:
                _clear_readonly(f.path)
                os.remove(f.path)
        else:
            send2trash(f.path)

    batch: list[Finding] = []

    def flush_batch() -> None:
        """Recycle many files in one shell operation; fall back to one-by-one on failure."""
        if not batch:
            return
        try:
            send2trash([f.path for f in batch])
            for f in batch:
                record(f)
        except Exception:  # noqa: BLE001
            for f in batch:
                if not os.path.lexists(f.path):      # the shell got to it before failing
                    record(f)
                    continue
                try:
                    remove_one(f)
                    record(f)
                except Exception as ex:  # noqa: BLE001
                    rep.failed.append((f.path, _friendly(ex)))
        batch.clear()

    try:
        for i, f in enumerate(findings):
            if cancel is not None and cancel.is_set():
                rep.cancelled = True
                break
            if progress and (i % 25 == 0 or f.is_dir):
                progress(f.path, i, total)
            if not f.deletable:
                rep.failed.append((f.path, "not deletable"))
                continue
            why = _refuse(f.path)
            if why:
                rep.failed.append((f.path, why))
                continue
            batchable = (not permanent and send2trash is not None and not f.is_dir
                         and f.category not in ("recycle", "empty") and os.path.lexists(f.path))
            if batchable:
                batch.append(f)
                if len(batch) >= BATCH_SIZE:
                    flush_batch()
                continue
            try:
                remove_one(f)
                record(f)
            except Exception as ex:  # noqa: BLE001 - report every failure to the user
                rep.failed.append((f.path, _friendly(ex)))
        flush_batch()
    finally:
        log.close()
    if progress:
        progress("", total, total)
    return rep


BATCH_SIZE = 500


def _friendly(ex: Exception) -> str:
    msg = str(ex)
    if isinstance(ex, PermissionError) or "WinError 32" in msg or "0x80270027" in msg or "OLE error" in msg:
        return "in use by another program or access denied"
    if isinstance(ex, FileNotFoundError):
        return "already gone"
    return msg[:160]
