"""A throw-away machine in a folder.

Every test runs against a fake profile tree, never against the real drives:

    <sandbox>/root/Users/tester/...      the "machine" that gets scanned
    <sandbox>/appdata/                   %LOCALAPPDATA% for this test (settings, cleanup log)

The tree lives next to the tests (``tests/.tmp``) rather than in ``%TEMP%`` on purpose:
the real temp folder is inside ``AppData``, and ``rules.is_app_owned`` treats everything
under an ``AppData`` segment as owned by an application - which would switch off half the
heuristics under test.
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

TMP_BASE = Path(os.environ.get("SMARTCLEANER_TEST_TMP") or (TESTS_DIR / ".tmp"))

from smartcleaner import cleaner, rules  # noqa: E402

DAY = 86400.0


def write(path: Path, size: int = 64, age_days: float = 0.0) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(b"x" * size)
    if age_days:
        when = time.time() - age_days * DAY
        os.utime(path, (when, when))
    return path


@dataclass
class Sandbox:
    dir: Path
    root: Path
    appdata: Path

    @property
    def profile(self) -> Path:
        return self.root / "Users" / "tester"

    def exists(self, rel: str) -> bool:
        return (self.root / rel).exists()

    def cleanup_log(self) -> list[str]:
        p = self.appdata / "SmartCleaner" / "cleanup_log.jsonl"
        return p.read_text(encoding="utf-8").splitlines() if p.exists() else []


def build_tree(root: Path) -> None:
    prof = root / "Users" / "tester"
    # --- safe: temp / cache / dumps / logs
    write(prof / "AppData/Local/Temp/old.tmp", 5_000, 3)
    write(prof / "AppData/Local/Temp/sub/deep.tmp", 7_000, 3)
    write(prof / "AppData/Local/CrashDumps/app.dmp", 11_000, 30)
    write(prof / "AppData/Local/Google/Chrome/User Data/Default/Cache/f_000001", 13_000, 2)
    # --- review: an installer and an ancient download
    write(prof / "Downloads/setup.exe", 17_000, 200)
    write(prof / "Downloads/ancient.pdf", 19_000, 500)
    # --- keep: model stores and the coding engine
    write(prof / ".ollama/models/blobs/sha256-aaaa", 23_000, 10)
    write(prof / ".ollama/models/manifests/registry/library/qwen/latest", 300, 10)
    write(prof / ".lmstudio/models/vendor/model.gguf", 29_000, 10)
    write(prof / ".buzzcode/engine/llama-server.exe", 31_000, 10)
    # --- a stale project: node_modules (REVIEW) beside __pycache__ (SAFE)
    proj = root / "proj"
    write(proj / "package.json", 120, 200)
    write(proj / "app.py", 300, 200)
    write(proj / "app.log", 3_000, 200)
    write(proj / "node_modules/left-pad/index.js", 41_000, 200)
    write(proj / "__pycache__/app.cpython-314.pyc", 2_000, 200)
    # --- an active project: node_modules is listed but not suggested
    live = root / "live"
    write(live / "package.json", 120, 0)
    write(live / "node_modules/react/index.js", 43_000, 0)


@pytest.fixture
def sandbox(monkeypatch) -> Sandbox:
    assert "appdata" not in str(TMP_BASE).lower().split(os.sep), (
        f"the test sandbox must not live under AppData ({TMP_BASE}); "
        "set SMARTCLEANER_TEST_TMP to a folder outside it")
    TMP_BASE.mkdir(parents=True, exist_ok=True)
    d = Path(tempfile.mkdtemp(prefix="sc-", dir=TMP_BASE))
    appdata = d / "appdata"
    appdata.mkdir()
    monkeypatch.setenv("LOCALAPPDATA", str(appdata))
    for var in rules.KEEP_ENV_VARS:
        monkeypatch.delenv(var, raising=False)
    root = d / "root"
    build_tree(root)
    yield Sandbox(d, root, appdata)
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture(autouse=True)
def never_touch_the_real_recycle_bin(monkeypatch):
    """Recycle-bin calls are recorded, never performed."""
    sent: list[str] = []

    def fake_send2trash(paths):
        sent.extend([paths] if isinstance(paths, str) else list(paths))

    monkeypatch.setattr(cleaner, "send2trash", fake_send2trash)
    monkeypatch.setattr(cleaner, "empty_recycle_bin", lambda root: True)
    return sent
