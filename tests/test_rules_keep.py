"""SC2: model stores are listed and never deletable; the expensive dev dirs stay REVIEW."""
from __future__ import annotations

import os
import threading

from smartcleaner import cleaner, rules
from smartcleaner.model import Risk
from smartcleaner.scanner import Scanner
from smartcleaner.settings import Settings
from smartcleaner.winutil import norm


def _scan(root):
    return Scanner(str(root), Settings(), None, threading.Event()).run()


# ---------------------------------------------------------------- the KEEP rules

def test_keep_locations_finds_the_model_stores(sandbox):
    found = {norm(p) for p, _ in rules.keep_locations(str(sandbox.root))}
    for rel in (".ollama/models", ".lmstudio/models", ".buzzcode/engine"):
        assert norm(str(sandbox.profile / rel)) in found, rel


def test_keep_location_from_an_environment_variable(sandbox, monkeypatch):
    elsewhere = sandbox.root / "weights"
    (elsewhere / "sub").mkdir(parents=True)
    monkeypatch.setenv("OLLAMA_MODELS", str(elsewhere))
    found = {norm(p) for p, _ in rules.keep_locations(str(sandbox.root))}
    assert norm(str(elsewhere)) in found
    assert rules.is_model_store(str(elsewhere / "sub" / "blob"))


def test_is_model_store_recognises_the_stores_without_a_scan():
    yes = [r"C:\Users\me\.ollama\models\blobs\sha256-1",
           r"C:\Users\me\.lmstudio\models\pub\m.gguf",
           r"C:\Users\me\.cache\lm-studio\models\m.gguf",
           r"C:\Users\me\.buzzcode\engine\llama-server.exe",
           r"B:\models\qwen.gguf",
           r"B:\models"]
    no = [r"C:\Users\me\Downloads\models\thing.zip",
          r"B:\projects\models",
          r"C:\Users\me\AppData\Local\Temp\x.tmp"]
    for p in yes:
        assert rules.is_model_store(p), p
    for p in no:
        assert not rules.is_model_store(p), p


def test_the_cleaner_refuses_a_model_store_path():
    assert cleaner._refuse(r"C:\Users\me\.ollama\models\blobs\sha256-1")
    assert cleaner._refuse(r"B:\models\qwen.gguf")
    assert cleaner._refuse(r"C:\Users\me\AppData\Local\Temp\x.tmp") is None


def test_the_scan_lists_the_store_as_keep_and_never_looks_inside(sandbox):
    result = _scan(sandbox.root)
    stores = [f for f in result.findings if f.category == "models"]
    assert stores, "no model store reported"
    assert all(f.risk == Risk.KEEP and not f.deletable for f in stores)
    ollama = next(f for f in stores if f.path.lower().endswith(os.path.join(".ollama", "models")))
    assert ollama.size >= 23_000 and ollama.is_dir
    inside = [f for f in result.findings
              if norm(f.path).startswith(norm(ollama.path) + os.sep)]
    assert inside == [], inside


# ---------------------------------------------------------------- the REVIEW rules

def test_expensive_dev_dirs_are_review():
    for name in ("node_modules", "target", ".venv", "venv", ".tox"):
        assert rules.DEV_DIRS[name][0] == Risk.REVIEW, name
    for name in ("__pycache__", ".ruff_cache", ".mypy_cache", ".pytest_cache"):
        assert rules.DEV_DIRS[name][0] == Risk.SAFE, name


def test_a_stale_project_is_suggested_and_an_active_one_is_not(sandbox):
    result = _scan(sandbox.root)
    dev = {os.path.basename(os.path.dirname(f.path)): f
           for f in result.findings if f.category == "dev" and f.path.endswith("node_modules")}
    assert dev["proj"].risk == Risk.REVIEW and dev["proj"].suggested      # untouched 200 days
    assert dev["live"].risk == Risk.REVIEW and not dev["live"].suggested  # touched today


def test_windows_update_and_model_caches_stay_review():
    by_rel = {loc.rel: loc for loc in rules.SYSTEM_LOCATIONS}
    assert by_rel["Windows/SoftwareDistribution/Download"].risk == Risk.REVIEW
    profile = {loc.rel: loc for loc in rules.PROFILE_LOCATIONS}
    assert profile[".cache/huggingface"].risk == Risk.REVIEW
    assert profile[".cache/torch"].risk == Risk.REVIEW
