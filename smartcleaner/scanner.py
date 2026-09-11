"""Filesystem walk + classification + duplicate detection.

Pure Python, no Qt: it can be driven from the UI (in a thread) or from a test script.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

from . import rules
from .model import Finding, Risk, ScanResult, ScanStats
from .settings import Settings
from .winutil import (FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_SYSTEM, is_admin, is_reparse, norm,
                      recycle_bin_info)

ProgressCB = Callable[[str, int, int], None]  # (status text, files seen, bytes seen)


class ScanCancelled(Exception):
    pass


class Scanner:
    def __init__(self, root: str, settings: Settings,
                 progress: ProgressCB | None = None,
                 cancel: threading.Event | None = None) -> None:
        self.root = os.path.abspath(root)
        if not self.root.endswith(os.sep) and len(self.root) == 2 and self.root[1] == ":":
            self.root += os.sep
        self.settings = settings
        self.progress = progress or (lambda *_: None)
        self.cancel = cancel or threading.Event()
        self.stats = ScanStats(root=self.root, is_admin=is_admin())
        self.findings: list[Finding] = []
        self._dupe_candidates: list[tuple[str, int, float]] = []
        self._pruned: set[str] = set()
        self._now = time.time()
        self._last_report = 0.0
        self._is_drive_root = os.path.splitdrive(self.root)[1] in ("\\", "/", "")
        self._downloads_dirs = set()

    # ------------------------------------------------------------------ public
    def run(self) -> ScanResult:
        t0 = time.time()
        s = self.settings
        try:
            usage = shutil.disk_usage(self.root)
            disk = (usage.total, usage.used, usage.free)
        except OSError:
            disk = (0, 0, 0)

        self._report("Preparing…", force=True)
        if self._is_drive_root:
            self._recycle_bin()
            self._system_files()

        # 0) Model stores and engines: measured, listed as KEEP, never walked further.
        self._model_stores()

        # 1) Known locations first: they are walked with a fixed category and pruned
        #    from the generic walk.
        known = rules.expand_locations(self.root)
        for path, loc in known:
            self._pruned.add(norm(path))
        for path, loc in known:
            self._check_cancel()
            if rules.is_excluded(path, s):
                continue
            self._walk_known(path, loc)

        # 2) Generic walk with heuristics.
        self._walk_generic(self.root)

        # 3) Duplicates
        if s.find_duplicates and self._dupe_candidates:
            before = len(self.findings)
            self._find_duplicates()
            dup_paths = {norm(f.path) for f in self.findings[before:]}
            if dup_paths:
                self.findings = [f for i, f in enumerate(self.findings)
                                 if i >= before or f.category not in ("installers", "olddownloads", "backups", "large")
                                 or norm(f.path) not in dup_paths]

        self.stats.seconds = time.time() - t0
        self._report("Done", force=True)
        return ScanResult(self.root, self.findings, self.stats, *disk)

    # ------------------------------------------------------------------ helpers
    def _check_cancel(self) -> None:
        if self.cancel.is_set():
            raise ScanCancelled()

    def _report(self, status: str, force: bool = False) -> None:
        now = time.time()
        if force or now - self._last_report > 0.15:
            self._last_report = now
            self.progress(status, self.stats.files_seen, self.stats.bytes_seen)

    def _add(self, f: Finding) -> None:
        self.findings.append(f)

    def _age(self, mtime: float) -> float:
        return (self._now - mtime) / 86400.0

    def _scandir(self, path: str):
        try:
            with os.scandir(path) as it:
                return list(it)
        except PermissionError:
            self.stats.errors += 1
            if len(self.stats.denied_paths) < 200:
                self.stats.denied_paths.append(path)
        except OSError:
            self.stats.errors += 1
        return None

    def _is_protected_root_dir(self, entry_path: str, name: str) -> bool:
        """Top-level-of-drive folders we never walk generically."""
        parent = os.path.dirname(entry_path.rstrip(os.sep))
        if norm(parent) == norm(self.root) and self._is_drive_root:
            return name.lower() in rules.PROTECTED_ROOT_DIRS
        return False

    def _is_protected_profile_dir(self, entry_path: str) -> bool:
        n = norm(entry_path).lower().replace(os.sep, "/")
        return any(n.endswith("/" + sub) for sub in rules.PROTECTED_PROFILE_SUBDIRS)

    # ------------------------------------------------------------------ special
    def _recycle_bin(self) -> None:
        size, items = recycle_bin_info(self.root)
        if items:
            self._add(Finding(os.path.join(self.root, "$Recycle.Bin"), size, self._now, "recycle",
                              Risk.SAFE, f"{items:,} item(s) in the Recycle Bin", is_dir=True))

    def _system_files(self) -> None:
        for name, advice in rules.SYSTEM_FILES_INFO.items():
            p = os.path.join(self.root, name)
            try:
                st = os.stat(p)
            except OSError:
                continue
            self._add(Finding(p, st.st_size, st.st_mtime, "large", Risk.PROTECTED, advice))

    def _model_stores(self) -> None:
        """Report Ollama / LM Studio / B:\\models / buzzcode engine stores as Risk.KEEP.

        They are pruned from every later pass, so nothing inside them can be reported as a
        large file, a duplicate or a developer leftover - and therefore nothing inside them
        can ever be selected for deletion.
        """
        for path, loc in rules.keep_locations(self.root):
            self._check_cancel()
            self._pruned.add(norm(path))
            if rules.is_excluded(path, self.settings):
                continue
            size, files, newest = self._dir_size(path)
            self._add(Finding(path, size, newest or self._now, loc.category, Risk.KEEP,
                              f"{loc.reason}. {files:,} files - kept, never deleted.",
                              is_dir=True, note=loc.note))

    # ------------------------------------------------------------------ known locations
    def _walk_known(self, path: str, loc: rules.Location) -> None:
        if os.path.isfile(path):
            try:
                st = os.stat(path)
            except OSError:
                return
            if fnmatch(os.path.basename(path), loc.file_glob) and self._age(st.st_mtime) >= loc.min_age_days:
                self._add(Finding(path, st.st_size, st.st_mtime, loc.category, loc.risk, loc.reason, note=loc.note))
            return
        stack = [path]
        while stack:
            self._check_cancel()
            d = stack.pop()
            entries = self._scandir(d)
            if entries is None:
                continue
            self.stats.dirs_seen += 1
            for e in entries:
                try:
                    st = e.stat(follow_symlinks=False)
                except OSError:
                    self.stats.errors += 1
                    continue
                if is_reparse(st):
                    continue
                if e.is_dir(follow_symlinks=False):
                    stack.append(e.path)
                    continue
                self.stats.files_seen += 1
                self.stats.bytes_seen += st.st_size
                if not fnmatch(e.name, loc.file_glob):
                    continue
                if self._age(st.st_mtime) < loc.min_age_days:
                    continue
                self._add(Finding(e.path, st.st_size, st.st_mtime, loc.category, loc.risk, loc.reason, note=loc.note))
            self._report(f"Scanning {d}")

    # ------------------------------------------------------------------ generic walk
    def _walk_generic(self, root: str) -> None:
        s = self.settings
        large_bytes = s.large_file_mb * 1024 * 1024
        dupe_min = s.dupe_min_kb * 1024
        hash_max = s.hash_max_mb * 1024 * 1024 if s.hash_max_mb else None
        stack = [root]
        while stack:
            self._check_cancel()
            d = stack.pop()
            entries = self._scandir(d)
            if entries is None:
                continue
            self.stats.dirs_seen += 1
            in_appdata = rules.is_app_owned(d)           # app-owned: only temp/log/dump rules apply
            cloud = rules.is_cloud_path(d + os.sep)
            downloads_top = rules.is_downloads_top(os.path.join(d, "x")) and not in_appdata
            leveldb = rules.is_leveldb_dir({e.name.lower() for e in entries})
            non_empty = False
            for e in entries:
                non_empty = True
                try:
                    st = e.stat(follow_symlinks=False)
                except OSError:
                    self.stats.errors += 1
                    continue
                if is_reparse(st) or e.is_symlink():
                    continue
                attrs = getattr(st, "st_file_attributes", 0)
                name = e.name
                lname = name.lower()

                if e.is_dir(follow_symlinks=False):
                    npath = norm(e.path)
                    if npath in self._pruned or rules.is_excluded(e.path, s):
                        continue
                    if lname in rules.PROTECTED_DIR_NAMES or self._is_protected_root_dir(e.path, name) \
                            or self._is_protected_profile_dir(e.path):
                        continue
                    if attrs & FILE_ATTRIBUTE_SYSTEM and attrs & FILE_ATTRIBUTE_HIDDEN:
                        continue  # system-hidden dirs (junction targets, protected shells)
                    if s.find_dev_leftovers and not in_appdata:
                        dev = rules.dev_dir_matches(name, d)
                        if dev:
                            self._dev_leftover(e.path, dev, d, name)
                            continue
                    stack.append(e.path)
                    continue

                # ---- files
                self.stats.files_seen += 1
                self.stats.bytes_seen += st.st_size
                if attrs & FILE_ATTRIBUTE_SYSTEM:
                    continue
                if rules.is_excluded(e.path, s):
                    continue
                ext = os.path.splitext(lname)[1]
                age = self._age(st.st_mtime)
                size = st.st_size
                note = "Cloud-synced folder: deleting here also deletes it in the cloud." if cloud else ""
                handled = False

                # junk by name / extension
                if lname in ("thumbs.db", ".ds_store", "ehthumbs.db"):
                    self._add(Finding(e.path, size, st.st_mtime, "cache", Risk.SAFE, "Thumbnail cache file", note=note)); handled = True
                elif lname == "desktop.ini":
                    handled = True
                elif lname.startswith("~$") and age >= s.temp_age_days:
                    self._add(Finding(e.path, size, st.st_mtime, "temp", Risk.SAFE, "Office lock file left behind", note=note)); handled = True
                elif ext in rules.TEMP_EXTS:
                    min_age = max(s.temp_age_days, 2) if ext in (".crdownload", ".part", ".partial", ".download", ".!ut", ".bc!") else s.temp_age_days
                    if age >= min_age:
                        self._add(Finding(e.path, size, st.st_mtime, "temp", Risk.SAFE, f"Temporary file ({ext})", note=note)); handled = True
                elif ext in rules.DUMP_EXTS and age >= s.dump_age_days:
                    self._add(Finding(e.path, size, st.st_mtime, "debug", Risk.SAFE, "Crash dump", note=note)); handled = True
                elif (ext in rules.LOG_EXTS or rules.LOG_ROTATED_RE.search(lname)) and age >= s.log_age_days \
                        and not leveldb and (not in_appdata or "log" in os.path.basename(d).lower()):
                    self._add(Finding(e.path, size, st.st_mtime, "logs", Risk.SAFE if not cloud else Risk.REVIEW,
                                      f"Log file untouched for {age:.0f} days", note=note)); handled = True
                elif (ext in rules.BACKUP_EXTS or lname.endswith("~")) and not in_appdata:
                    self._add(Finding(e.path, size, st.st_mtime, "backups", Risk.REVIEW,
                                      f"Backup / old copy ({ext or '~'}), {age:.0f} days old",
                                      suggested=age >= 180 and ext in (".old", ".bak", ".orig"), note=note)); handled = True
                elif downloads_top and ext in rules.INSTALLER_EXTS and age >= s.installer_age_days:
                    self._add(Finding(e.path, size, st.st_mtime, "installers", Risk.REVIEW,
                                      f"Installer downloaded {age:.0f} days ago", suggested=True, note=note)); handled = True
                elif downloads_top and age >= s.old_download_days and not in_appdata:
                    self._add(Finding(e.path, size, st.st_mtime, "olddownloads", Risk.REVIEW,
                                      f"In Downloads, untouched for {age/365:.1f} years", note=note)); handled = True

                # large files (also for files handled above? no: avoid double counting)
                if not handled and s.find_large and size >= large_bytes:
                    hint = rules.large_file_hint(ext)
                    reason = f"{size / 2**30:.1f} GB. " + (hint or "Large file.")
                    n2 = note
                    if in_appdata:
                        n2 = (n2 + " " if n2 else "") + "Inside AppData: an application owns this file."
                    self._add(Finding(e.path, size, st.st_mtime, "large", Risk.REVIEW, reason, note=n2))

                # duplicate candidates (not in AppData, not junk). Files already reported as
                # installer/old download/backup/large stay candidates: if they turn out to be a
                # duplicate, that finding replaces the softer one.
                soft = handled and self.findings and self.findings[-1].path == e.path \
                    and self.findings[-1].category in ("installers", "olddownloads", "backups")
                if s.find_duplicates and size >= dupe_min and not in_appdata and (not handled or soft) \
                        and (hash_max is None or size <= hash_max):
                    self._dupe_candidates.append((e.path, size, st.st_mtime))

            if not non_empty and s.find_empty_folders:
                self._maybe_empty(d, in_appdata)
            self._report(f"Scanning {d}")

    def _maybe_empty(self, d: str, in_appdata: bool) -> None:
        if in_appdata or norm(d) == norm(self.root):
            return
        lname = os.path.basename(d).lower()
        if lname in rules.STANDARD_USER_DIRS:
            return
        parent_l = os.path.basename(os.path.dirname(d)).lower()
        if parent_l in ("users", "") or norm(os.path.dirname(d)) == norm(self.root):
            return  # top-level drive folders and profile folders: too important to be tidy about
        try:
            st = os.stat(d)
        except OSError:
            return
        if self._age(st.st_mtime) < self.settings.empty_folder_age_days:
            return
        self._add(Finding(d, 0, st.st_mtime, "empty", Risk.REVIEW,
                          "Empty folder (frees no space; some programs recreate theirs)", is_dir=True, suggested=True))

    def _dev_leftover(self, path: str, dev: tuple[Risk, str], parent: str, name: str) -> None:
        risk, reason = dev
        size, files, newest = self._dir_size(path)
        if files == 0:
            return
        activity = rules.project_last_activity(parent, name)
        idle = self._age(activity) if activity else 999
        suggested = False
        if risk == Risk.SAFE:
            r = f"{reason}. {files:,} files."
        elif idle >= self.settings.stale_project_days:
            r = f"{reason}. Project untouched for {idle:.0f} days ({files:,} files)."
            suggested = True
        else:
            r = f"{reason}. Project active {idle:.0f} days ago ({files:,} files)."
        self._add(Finding(path, size, newest, "dev", risk, r, is_dir=True, suggested=suggested))

    def _dir_size(self, path: str) -> tuple[int, int, float]:
        total = files = 0
        newest = 0.0
        stack = [path]
        while stack:
            self._check_cancel()
            d = stack.pop()
            entries = self._scandir(d)
            if entries is None:
                continue
            for e in entries:
                try:
                    st = e.stat(follow_symlinks=False)
                except OSError:
                    continue
                if is_reparse(st):
                    continue
                if e.is_dir(follow_symlinks=False):
                    stack.append(e.path)
                else:
                    files += 1
                    total += st.st_size
                    newest = max(newest, st.st_mtime)
                    self.stats.files_seen += 1
                    self.stats.bytes_seen += st.st_size
            self._report(f"Measuring {path}")
        return total, files, newest

    # ------------------------------------------------------------------ duplicates
    def _find_duplicates(self) -> None:
        by_size: dict[int, list[tuple[str, int, float]]] = defaultdict(list)
        for rec in self._dupe_candidates:
            by_size[rec[1]].append(rec)
        groups = [v for v in by_size.values() if len(v) > 1]
        self._dupe_candidates.clear()
        if not groups:
            return
        total_files = sum(len(g) for g in groups)
        done = 0

        def quick(rec):
            return rec, _hash_file(rec[0], quick=True)

        def full(rec):
            return rec, _hash_file(rec[0], quick=False)

        # stage 1: quick hash (head + tail)
        by_quick: dict[tuple[int, str], list] = defaultdict(list)
        with ThreadPoolExecutor(max_workers=4) as ex:
            futs = [ex.submit(quick, rec) for g in groups for rec in g]
            for fut in as_completed(futs):
                self._check_cancel()
                rec, h = fut.result()
                done += 1
                if h:
                    by_quick[(rec[1], h)].append(rec)
                if done % 50 == 0:
                    self.progress(f"Comparing files {done:,}/{total_files:,}", self.stats.files_seen, self.stats.bytes_seen)
        groups = [v for v in by_quick.values() if len(v) > 1]
        if not groups:
            return

        # stage 2: full hash for anything larger than the quick window
        by_full: dict[str, list] = defaultdict(list)
        need_full = []
        for (size, qh), members in by_quick.items():
            if len(members) < 2:
                continue
            if size <= _QUICK_BYTES * 2:
                by_full[f"q{size}-{qh}"].extend(members)   # quick hash covered the whole file
            else:
                need_full.extend(members)
        done = 0
        with ThreadPoolExecutor(max_workers=4) as ex:
            futs = [ex.submit(full, rec) for rec in need_full]
            for fut in as_completed(futs):
                self._check_cancel()
                rec, h = fut.result()
                done += 1
                self.stats.hashed_files += 1
                self.stats.hashed_bytes += rec[1]
                if h:
                    by_full[f"f{rec[1]}-{h}"].append(rec)
                if done % 10 == 0:
                    self.progress(f"Verifying duplicates {done:,}/{len(need_full):,}", self.stats.files_seen, self.stats.bytes_seen)

        for key, members in by_full.items():
            if len(members) < 2:
                continue
            oldest = min(m[2] for m in members)
            ranked = sorted(members, key=lambda m: rules.keeper_score(m[0], m[2], oldest), reverse=True)
            keeper = ranked[0]
            n = len(members)
            for i, (path, size, mtime) in enumerate(ranked):
                ext = os.path.splitext(path)[1].lower()
                note = ""
                if rules.is_cloud_path(path):
                    note = "Cloud-synced folder: deleting here also deletes it in the cloud."
                if ext in rules.IMPORTANT_EXTS:
                    note = (note + " " if note else "") + "Document/project file: same content, but keep the copy in the right place."
                if i == 0:
                    self._add(Finding(path, size, mtime, "dupes", Risk.KEEP,
                                      f"Suggested original of {n} identical copies", group=key, note=note))
                else:
                    self._add(Finding(path, size, mtime, "dupes", Risk.REVIEW,
                                      f"Identical to {os.path.basename(keeper[0])} ({n} copies)", group=key,
                                      suggested=True, note=note))


_QUICK_BYTES = 64 * 1024


def _hash_file(path: str, quick: bool) -> str | None:
    try:
        h = hashlib.blake2b(digest_size=20)
        with open(path, "rb", buffering=0) as fh:
            if quick:
                h.update(fh.read(_QUICK_BYTES))
                fh.seek(0, os.SEEK_END)
                size = fh.tell()
                if size > _QUICK_BYTES * 2:
                    fh.seek(-_QUICK_BYTES, os.SEEK_END)
                    h.update(fh.read(_QUICK_BYTES))
                elif size > _QUICK_BYTES:
                    fh.seek(_QUICK_BYTES)
                    h.update(fh.read())
            else:
                for chunk in iter(lambda: fh.read(4 * 1024 * 1024), b""):
                    h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def fnmatch(name: str, pattern: str) -> bool:
    if pattern == "*":
        return True
    import fnmatch as _fn
    return _fn.fnmatch(name.lower(), pattern.lower())
