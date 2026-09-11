"""Headless SmartCleaner: the same scanner and the same cleaner, driven from a command line.

Written for two callers:

* **Sentinel's tray** - the service watches free disk space and, when a drive turns red,
  tells the tray (which runs as the interactive user, so it can reach `%TEMP%` and the
  browser caches) to run::

      python -m smartcleaner --headless --json --max-risk safe \\
          --categories temp,cache,logs,dumps,dev-cache --target-free-gb 25 --drive C:

* **Dexter** - "clean up space" runs the same command and reads the JSON.

Rules that hold no matter what the flags say:

* only ``Risk.SAFE`` findings are deleted, unless ``--max-risk review`` **and** the
  category was named explicitly on the command line;
* ``Risk.KEEP`` / ``Risk.PROTECTED`` findings are never deleted - model stores
  (Ollama, LM Studio, ``B:\\models``, the BuzzCode engine) are KEEP;
* the expensive developer directories (``node_modules``, ``target``, ``.venv`` ...) are
  never deleted headlessly, only listed - the CLI deletes the cheap build caches
  (``__pycache__``, ``.ruff_cache`` ...) that ``rules.DEV_DIRS`` marks SAFE;
* nothing is deleted at all without ``--headless``.

This module imports nothing from :mod:`smartcleaner.ui` and needs no display.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field

from . import APP_NAME, __version__
from .cleaner import delete_findings
from .model import CATEGORIES, Finding, Risk, ScanResult, human_size
from .scanner import ScanCancelled, Scanner
from .settings import Settings
from .winutil import fixed_drive_roots, is_admin

EXIT_OK = 0
EXIT_PARTIAL = 1
EXIT_ARGS = 2

#: What a headless run cleans when no ``--categories`` are given.
DEFAULT_CATEGORIES: tuple[str, ...] = ("temp", "cache", "logs", "debug", "dev")

#: Deleted permanently in a headless run even without ``--permanent``: sending a
#: temp file to the Recycle Bin moves it, it does not free the space.
PERMANENT_DEFAULT_CATEGORIES = frozenset({"temp", "cache", "logs", "debug"})

#: Never deleted by the CLI, whatever ``--max-risk`` says.
NEVER_DELETABLE_CATEGORIES = frozenset({"models"})

#: Friendly spellings, so a caller may say `dumps` or `dev-cache`.
CATEGORY_ALIASES = {
    "tmp": "temp", "temporary": "temp",
    "caches": "cache",
    "log": "logs",
    "dump": "debug", "dumps": "debug", "crash": "debug", "crashdumps": "debug", "diagnostics": "debug",
    "dev-cache": "dev", "devcache": "dev", "dev_cache": "dev", "devleftovers": "dev",
    "downloads-old": "olddownloads", "old-downloads": "olddownloads", "olddownload": "olddownloads",
    "installer": "installers",
    "duplicates": "dupes", "dupe": "dupes",
    "recyclebin": "recycle", "recycle-bin": "recycle", "trash": "recycle",
    "empty-folders": "empty", "emptyfolders": "empty",
    "backup": "backups",
    "model": "models", "modelstores": "models",
}

#: Findings are deleted in batches of this many, so ``--target-free-gb`` can stop early.
DELETE_BATCH = 128

_PROGRESS_EVERY = 5.0


# ======================================================================== output


class Out:
    """Human text - stderr when the machine output owns stdout, plus an optional log file."""

    def __init__(self, stream, log_path: str | None = None) -> None:
        self.stream = stream
        self.fh = None
        if log_path:
            try:
                os.makedirs(os.path.dirname(os.path.abspath(log_path)), exist_ok=True)
                self.fh = open(log_path, "a", encoding="utf-8")
                self.fh.write(f"\n===== {APP_NAME} {__version__} {time.strftime('%Y-%m-%d %H:%M:%S')} =====\n")
            except OSError as ex:
                print(f"cannot write --log {log_path}: {ex}", file=stream)

    def __call__(self, text: str = "") -> None:
        print(text, file=self.stream)
        if self.fh:
            self.fh.write(text + "\n")
            self.fh.flush()

    def close(self) -> None:
        if self.fh:
            self.fh.close()
            self.fh = None


# ======================================================================== arguments


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m smartcleaner",
        description="SmartCleaner - disk clean-up. With no arguments it opens the window; "
                    "with --headless it cleans from the command line.",
        epilog="Nothing is deleted without --headless. Model stores (Ollama, LM Studio, "
               "B:\\models, the BuzzCode engine) and node_modules/target/.venv are never "
               "deleted by the CLI.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--gui", action="store_true", help="open the window (the default with no arguments)")
    p.add_argument("--headless", action="store_true", help="no window; scan and clean on the command line")
    p.add_argument("--scan-only", action="store_true", help="report what would be deleted, delete nothing")
    p.add_argument("--json", dest="as_json", action="store_true",
                   help="machine-readable JSON on stdout (human text goes to stderr)")
    p.add_argument("--categories", default="", metavar="a,b,+c",
                   help="categories to clean; `+x` adds x to the default set "
                        f"({','.join(DEFAULT_CATEGORIES)}). Known: " + ",".join(CATEGORIES))
    p.add_argument("--max-risk", choices=("safe", "review"), default="safe",
                   help="`review` also deletes REVIEW findings, but only in categories named explicitly")
    p.add_argument("--target-free-gb", type=float, default=None, metavar="N",
                   help="stop deleting once the drive has this much free space")
    p.add_argument("--drive", default=None, metavar="C:", help="only findings on this drive")
    p.add_argument("--permanent", action="store_true",
                   help="delete permanently instead of using the Recycle Bin "
                        f"(already the default for {','.join(sorted(PERMANENT_DEFAULT_CATEGORIES))})")
    p.add_argument("--log", default=None, metavar="PATH", help="append the human report to this file")
    p.add_argument("--max-seconds", type=float, default=None, metavar="N",
                   help="time budget for the scan; a longer scan is cut short and what was found is used")
    p.add_argument("--root", action="append", default=None, metavar="PATH",
                   help="scan this path (repeatable). Default: every fixed drive")
    p.add_argument("--version", action="version", version=f"{APP_NAME} {__version__}")
    return p


def parse_categories(spec: str, parser: argparse.ArgumentParser) -> tuple[set[str], set[str]]:
    """`"a,b,+c"` -> (categories to clean, categories named explicitly).

    Plain names replace the default set; `+name` adds to whatever the set already is.
    Both count as "named explicitly" for the --max-risk review rule.
    """
    named: set[str] = set()
    base: set[str] = set()
    added: set[str] = set()
    for raw in spec.replace(";", ",").split(","):
        tok = raw.strip()
        if not tok:
            continue
        plus = tok.startswith("+")
        key = tok.lstrip("+-").strip().lower()
        key = CATEGORY_ALIASES.get(key, key)
        if key not in CATEGORIES:
            parser.error(f"unknown category {tok!r}. Known: {', '.join(CATEGORIES)}")
        named.add(key)
        (added if plus else base).add(key)
    cats = (base or set(DEFAULT_CATEGORIES)) | added
    return cats, named


def normalise_drive(value: str | None, parser: argparse.ArgumentParser) -> str | None:
    if value is None:
        return None
    v = value.strip().strip('"').rstrip("\\/")
    if len(v) == 1 and v.isalpha():
        v += ":"
    if len(v) != 2 or v[1] != ":" or not v[0].isalpha():
        parser.error(f"--drive expects a drive letter like C:, got {value!r}")
    return v.upper()


def _drive_of(path: str) -> str:
    return os.path.splitdrive(os.path.abspath(path))[0].upper() or os.sep


def _free_bytes(drive: str) -> int:
    """Free bytes on the drive holding `drive` ("C:") - patched in tests."""
    try:
        return shutil.disk_usage(drive + os.sep if len(drive) == 2 else drive).free
    except OSError:
        return 0


def resolve_roots(args: argparse.Namespace, drive: str | None,
                  parser: argparse.ArgumentParser) -> list[str]:
    if args.root:
        roots = []
        for r in args.root:
            r = os.path.abspath(os.path.expandvars(os.path.expanduser(r.strip().strip('"'))))
            if not os.path.exists(r):
                parser.error(f"--root {r} does not exist")
            roots.append(r)
    else:
        roots = fixed_drive_roots()
    if drive:
        roots = [r for r in roots if _drive_of(r) == drive]
    return roots


# ======================================================================== the run


@dataclass
class RunState:
    scanned: int = 0
    findings: list[Finding] = field(default_factory=list)
    truncated: bool = False
    deleted_count: int = 0
    freed: int = 0
    failed: list[dict[str, str]] = field(default_factory=list)


def selectable(f: Finding, cats: set[str], named: set[str], max_risk: str) -> bool:
    """Would this finding be deleted with these flags?  The one rule that matters."""
    if f.category not in cats or f.category in NEVER_DELETABLE_CATEGORIES:
        return False
    if f.risk == Risk.SAFE:
        return True
    if f.risk != Risk.REVIEW:
        return False                       # KEEP and PROTECTED: never, by any flag
    if f.category == "dev":
        return False                       # node_modules / target / .venv: listed, never headless
    return max_risk == "review" and f.category in named


def _permanent_for(f: Finding, args: argparse.Namespace) -> bool:
    return bool(args.permanent) or f.category in PERMANENT_DEFAULT_CATEGORIES


def scan(roots: list[str], settings: Settings, args: argparse.Namespace,
         out: Out, state: RunState) -> None:
    cancel = threading.Event()
    timer = None
    if args.max_seconds and args.max_seconds > 0:
        timer = threading.Timer(args.max_seconds, cancel.set)
        timer.daemon = True
        timer.start()
    last = [0.0]

    def progress(status: str, files: int, nbytes: int) -> None:
        now = time.time()
        if now - last[0] >= _PROGRESS_EVERY:
            last[0] = now
            out(f"    {status[:96]}  ({files:,} files, {human_size(nbytes)})")

    try:
        for root in roots:
            if cancel.is_set():
                state.truncated = True
                out(f"  skipped {root}: out of time")
                continue
            out(f"  scanning {root} ...")
            scanner = Scanner(root, settings, progress, cancel)
            try:
                result: ScanResult = scanner.run()
                state.findings.extend(result.findings)
                state.scanned += result.stats.files_seen
            except ScanCancelled:
                state.truncated = True
                state.findings.extend(scanner.findings)
                state.scanned += scanner.stats.files_seen
                out(f"  time budget reached in {root}: keeping what was found so far")
            except OSError as ex:
                out(f"  {root}: {ex}")
    finally:
        if timer:
            timer.cancel()


def clean(selected: list[Finding], args: argparse.Namespace, out: Out, state: RunState) -> None:
    target = int(args.target_free_gb * (1024 ** 3)) if args.target_free_gb else None
    by_drive: dict[str, list[Finding]] = defaultdict(list)
    for f in selected:
        by_drive[_drive_of(f.path)].append(f)

    for drive in sorted(by_drive):
        items = sorted(by_drive[drive], key=lambda f: -f.size)
        if target is not None:
            free = _free_bytes(drive)
            if free >= target:
                out(f"  {drive} already has {human_size(free)} free (target {human_size(target)}): nothing to do")
                continue
        for start in range(0, len(items), DELETE_BATCH):
            batch = items[start:start + DELETE_BATCH]
            for permanent in (True, False):
                group = [f for f in batch if _permanent_for(f, args) is permanent]
                if not group:
                    continue
                rep = delete_findings(group, permanent, by="cli")
                state.deleted_count += rep.ok
                state.freed += rep.freed
                state.failed.extend({"path": p, "error": e} for p, e in rep.failed)
            if target is not None and _free_bytes(drive) >= target:
                out(f"  {drive} reached {human_size(target)} free: stopping here")
                break


def summarise(findings: list[Finding]) -> dict[str, tuple[int, int]]:
    out: dict[str, tuple[int, int]] = {}
    for f in findings:
        count, size = out.get(f.category, (0, 0))
        out[f.category] = (count + 1, size + f.size)
    return dict(sorted(out.items(), key=lambda kv: CATEGORIES[kv[0]].order if kv[0] in CATEGORIES else 99))


def run(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    t0 = time.time()
    scan_only = bool(args.scan_only or not args.headless)
    cats, named = parse_categories(args.categories, parser)
    drive = normalise_drive(args.drive, parser)
    roots = resolve_roots(args, drive, parser)
    if not roots:
        parser.error("nothing to scan" + (f": no fixed drive {drive}" if drive else ""))

    for stream in (sys.stdout, sys.stderr):
        try:                                   # a cp1252 console must not break the report
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass
    out = Out(sys.stderr if args.as_json else sys.stdout, args.log)
    state = RunState()
    try:
        settings = Settings.load()
        # Duplicate hashing reads every candidate file; only pay for it when asked.
        settings.find_duplicates = "dupes" in cats

        out(f"{APP_NAME} {__version__} | {'scan' if scan_only else args.max_risk + ' clean'} | "
            f"admin: {'yes' if is_admin() else 'no'}")
        out(f"  categories: {','.join(sorted(cats))}"
            + (f" | explicit: {','.join(sorted(named))}" if named else "")
            + (f" | drive {drive}" if drive else ""))
        scan(roots, settings, args, out, state)

        if drive:
            state.findings = [f for f in state.findings if _drive_of(f.path) == drive]

        selected = [f for f in state.findings if selectable(f, cats, named, args.max_risk)]
        chosen = {id(f) for f in selected}
        out(f"  scanned {state.scanned:,} files in {time.time() - t0:.1f} s"
            + (" (cut short by --max-seconds)" if state.truncated else ""))
        out("  found:")
        for cat, (count, size) in summarise(state.findings).items():
            title = CATEGORIES[cat].title if cat in CATEGORIES else cat
            picked = sum(1 for f in state.findings if f.category == cat and id(f) in chosen)
            mark = f"-> {picked:,} to delete" if picked else ("kept" if cat in NEVER_DELETABLE_CATEGORIES else "")
            out(f"    {title:<26} {count:>9,} items {human_size(size):>12}   {mark}")

        if scan_only:
            out(f"  scan only: nothing deleted ({len(selected):,} items, "
                f"{human_size(sum(f.size for f in selected))} would go)")
        elif not selected:
            out("  nothing to delete")
        else:
            out(f"  deleting {len(selected):,} items ({human_size(sum(f.size for f in selected))}) ...")
            clean(selected, args, out, state)
            out(f"  deleted {state.deleted_count:,} items, freed {human_size(state.freed)}"
                + (f", {len(state.failed):,} failed" if state.failed else ""))
            for row in state.failed[:10]:
                out(f"    ! {row['path']}: {row['error']}")
            if len(state.failed) > 10:
                out(f"    ... and {len(state.failed) - 10:,} more")

        payload = {
            "scanned": state.scanned,
            "candidates": [{"cat": c, "count": n, "bytes": b}
                           for c, (n, b) in summarise(selected).items()],
            "deleted": {"count": state.deleted_count, "bytes": state.freed},
            "failed": state.failed,
            "freed_bytes": state.freed,
            "drive_free_after": {d: _free_bytes(d) for d in sorted({_drive_of(r) for r in roots})},
            "elapsed_s": round(time.time() - t0, 2),
            "is_admin": is_admin(),
            "mode": args.max_risk,
            "scan_only": scan_only,
        }
        if args.as_json:
            # ensure_ascii: the JSON survives any console code page, whatever a path holds
            json.dump(payload, sys.stdout)
            sys.stdout.write("\n")
            sys.stdout.flush()
        for d, free in payload["drive_free_after"].items():
            out(f"  {d} free: {human_size(free)}")
        return EXIT_PARTIAL if state.failed else EXIT_OK
    finally:
        out.close()


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        return _launch_gui()
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.gui:
        if args.headless or args.scan_only or args.as_json:
            parser.error("--gui cannot be combined with --headless / --scan-only / --json")
        return _launch_gui()
    try:
        return run(args, parser)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return EXIT_PARTIAL


def _launch_gui() -> int:
    from .gui import main as gui_main      # imported here so the CLI needs no Qt / no display
    return gui_main()


if __name__ == "__main__":          # pragma: no cover
    sys.exit(main())
