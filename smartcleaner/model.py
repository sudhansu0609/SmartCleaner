from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import IntEnum


class Risk(IntEnum):
    """How safe it is to remove a finding. Lower = safer."""
    SAFE = 0        # pre-selected: temp, caches, logs, empty folders...
    REVIEW = 1      # shown, never pre-selected: duplicates, installers, large files
    KEEP = 2        # the copy of a duplicate group we suggest keeping (not deletable)
    PROTECTED = 3   # informational only, never deletable from the app


RISK_LABEL = {
    Risk.SAFE: "Safe",
    Risk.REVIEW: "Review",
    Risk.KEEP: "Keep",
    Risk.PROTECTED: "Protected",
}


@dataclass(slots=True)
class Finding:
    path: str
    size: int
    mtime: float
    category: str
    risk: Risk
    reason: str
    is_dir: bool = False
    group: str | None = None      # duplicate-group id (content hash)
    suggested: bool = False       # recommended for removal (beyond SAFE)
    note: str = ""                # extra caveat shown in details (cloud-synced, etc.)

    @property
    def deletable(self) -> bool:
        return self.risk in (Risk.SAFE, Risk.REVIEW)

    @property
    def age_days(self) -> float:
        return max(0.0, (time.time() - self.mtime) / 86400.0)


@dataclass(slots=True)
class Category:
    key: str
    title: str
    description: str
    order: int
    icon: str


# Ordered registry of categories shown in the UI.
CATEGORIES: dict[str, Category] = {}


def _reg(key: str, title: str, description: str, icon: str) -> None:
    CATEGORIES[key] = Category(key, title, description, len(CATEGORIES), icon)


_reg("recycle", "Recycle Bin",
     "Files already deleted and waiting in the Recycle Bin of this drive.", "🗑️")
_reg("temp", "Temporary files",
     "Windows and application temp folders, leftover .tmp/.part downloads, Office lock files.", "🧹")
_reg("cache", "Caches",
     "Browser, thumbnail, package-manager and app caches. They are rebuilt automatically when needed.", "📦")
_reg("logs", "Logs",
     "Old log files that nothing reads any more.", "📄")
_reg("debug", "Debug & diagnostic files",
     "Crash dumps, minidumps, kernel memory dumps, Windows Error Reporting queues, crash-reporter uploads "
     "and diagnostic traces. Only useful if you are actively debugging a crash.", "🐞")
_reg("empty", "Empty folders",
     "Folders that contain nothing at all. Tidy-up only: they take no space.", "📁")
_reg("dev", "Developer leftovers",
     "node_modules, __pycache__, virtual envs, build outputs. Rebuilt with one command, but re-downloading takes time.", "🛠️")
_reg("installers", "Old installers",
     "Setup files (.exe/.msi/.msix) in Downloads that you most likely already ran.", "💿")
_reg("olddownloads", "Old downloads",
     "Files sitting in Downloads untouched for a long time.", "⏳")
_reg("dupes", "Duplicate files",
     "Identical content stored more than once. One copy in each group is marked KEEP.", "👯")
_reg("large", "Large files",
     "Very big files. Nothing is wrong with them, but they are where the space goes.", "🐘")
_reg("windows", "Windows leftovers",
     "Previous Windows installation, update downloads and similar. Usually needs Administrator rights.", "🪟")
_reg("backups", "Backup & old copies",
     ".bak, .old, ~ files and 'Copy of' style leftovers.", "🗃️")
_reg("models", "AI model stores",
     "Ollama / LM Studio model stores, B:\\models and the BuzzCode engine. Listed so you can see "
     "what they cost; never deletable from SmartCleaner - remove models with their own tool.", "🧠")


@dataclass
class ScanStats:
    root: str = ""
    files_seen: int = 0
    bytes_seen: int = 0
    dirs_seen: int = 0
    errors: int = 0
    denied_paths: list[str] = field(default_factory=list)
    hashed_files: int = 0
    hashed_bytes: int = 0
    seconds: float = 0.0
    is_admin: bool = False


@dataclass
class ScanResult:
    root: str
    findings: list[Finding]
    stats: ScanStats
    disk_total: int = 0
    disk_used: int = 0
    disk_free: int = 0

    def by_category(self) -> dict[str, list[Finding]]:
        out: dict[str, list[Finding]] = {k: [] for k in CATEGORIES}
        for f in self.findings:
            out.setdefault(f.category, []).append(f)
        return out


def human_size(n: float) -> str:
    n = float(n)
    if n < 1024:
        return f"{n:,.0f} B"
    for unit in ("KB", "MB", "GB", "TB"):
        n /= 1024.0
        if abs(n) < 1024.0 or unit == "TB":
            return f"{n:,.1f} {unit}"
    return f"{n:,.1f} TB"
