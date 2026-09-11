"""The headless CLI: what it deletes, what it refuses, what it prints, what it returns."""
from __future__ import annotations

import json
import os

import pytest

from smartcleaner import cleaner, cli

JSON_KEYS = {"scanned", "candidates", "deleted", "failed", "freed_bytes",
             "drive_free_after", "elapsed_s", "is_admin", "mode", "scan_only"}


def run(capsys, *argv):
    try:
        code = cli.main(list(argv))
    except SystemExit as ex:                     # argparse errors
        code = ex.code if ex.code is not None else 0
    out, err = capsys.readouterr()
    return code, out, err


def run_json(capsys, sandbox, *argv):
    code, out, err = run(capsys, "--headless", "--json", "--root", str(sandbox.root), *argv)
    return code, json.loads(out), err


# ---------------------------------------------------------------- mode selection

def test_no_arguments_opens_the_window(monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "_launch_gui", lambda: calls.append("gui") or 0)
    assert cli.main([]) == 0
    assert calls == ["gui"]


def test_gui_flag_opens_the_window(monkeypatch):
    monkeypatch.setattr(cli, "_launch_gui", lambda: 7)
    assert cli.main(["--gui"]) == 7


def test_without_headless_nothing_is_deleted(capsys, sandbox):
    code, out, err = run(capsys, "--json", "--root", str(sandbox.root))
    payload = json.loads(out)
    assert code == cli.EXIT_OK
    assert payload["scan_only"] is True
    assert payload["deleted"] == {"count": 0, "bytes": 0}
    assert sandbox.exists("Users/tester/AppData/Local/Temp/old.tmp")


# ---------------------------------------------------------------- JSON contract

def test_json_shape_and_scan_only(capsys, sandbox):
    before = sum(len(files) for _, _, files in os.walk(sandbox.root))
    code, payload, err = run_json(capsys, sandbox, "--scan-only")
    assert code == cli.EXIT_OK
    assert set(payload) == JSON_KEYS
    assert payload["scan_only"] is True and payload["mode"] == "safe"
    assert isinstance(payload["scanned"], int) and payload["scanned"] > 0
    assert payload["deleted"] == {"count": 0, "bytes": 0}
    assert payload["freed_bytes"] == 0 and payload["failed"] == []
    assert isinstance(payload["is_admin"], bool)
    assert isinstance(payload["elapsed_s"], float)
    assert all(set(c) == {"cat", "count", "bytes"} for c in payload["candidates"])
    assert {c["cat"] for c in payload["candidates"]} <= set(cli.CATEGORIES)
    drive = cli._drive_of(str(sandbox.root))
    assert payload["drive_free_after"][drive] > 0
    # scan-only really is read-only
    assert before == sum(len(files) for _, _, files in os.walk(sandbox.root))
    assert "found:" in err and "nothing deleted" in err


def test_json_goes_to_stdout_and_prose_to_stderr(capsys, sandbox):
    code, out, err = run(capsys, "--headless", "--scan-only", "--json", "--root", str(sandbox.root))
    json.loads(out)                      # stdout is nothing but JSON
    assert "SmartCleaner" in err


# ---------------------------------------------------------------- what gets deleted

def test_safe_only_deletion(capsys, sandbox):
    code, payload, _ = run_json(capsys, sandbox, "--permanent")
    assert code == cli.EXIT_OK
    assert payload["scan_only"] is False
    assert payload["deleted"]["count"] >= 5
    assert payload["freed_bytes"] == payload["deleted"]["bytes"] > 0
    # SAFE went away
    assert not sandbox.exists("Users/tester/AppData/Local/Temp/old.tmp")
    assert not sandbox.exists("Users/tester/AppData/Local/Temp/sub/deep.tmp")
    assert not sandbox.exists("Users/tester/AppData/Local/CrashDumps/app.dmp")
    assert not sandbox.exists("Users/tester/AppData/Local/Google/Chrome/User Data/Default/Cache/f_000001")
    assert not sandbox.exists("proj/__pycache__")
    assert not sandbox.exists("proj/app.log")
    # REVIEW stayed
    assert sandbox.exists("Users/tester/Downloads/setup.exe")
    assert sandbox.exists("Users/tester/Downloads/ancient.pdf")
    assert sandbox.exists("proj/node_modules/left-pad/index.js")
    # KEEP stayed
    assert sandbox.exists("Users/tester/.ollama/models/blobs/sha256-aaaa")


def test_review_findings_need_the_flag_and_an_explicit_category(capsys, sandbox):
    # --max-risk review alone: installers are not even in the default category set
    code, payload, _ = run_json(capsys, sandbox, "--permanent", "--max-risk", "review")
    assert sandbox.exists("Users/tester/Downloads/setup.exe")

    # the category on its own, still safe mode: listed, not deleted
    code, payload, _ = run_json(capsys, sandbox, "--permanent", "--categories", "installers")
    assert code == cli.EXIT_OK
    assert payload["deleted"]["count"] == 0
    assert sandbox.exists("Users/tester/Downloads/setup.exe")

    # both: the installer goes, the old download (not named) stays
    code, payload, _ = run_json(capsys, sandbox, "--permanent",
                                "--categories", "installers", "--max-risk", "review")
    assert code == cli.EXIT_OK
    assert not sandbox.exists("Users/tester/Downloads/setup.exe")
    assert sandbox.exists("Users/tester/Downloads/ancient.pdf")


def test_plus_adds_to_the_default_set(capsys, sandbox):
    code, payload, _ = run_json(capsys, sandbox, "--permanent",
                                "--categories", "+installers", "--max-risk", "review")
    assert not sandbox.exists("Users/tester/Downloads/setup.exe")   # added category
    assert not sandbox.exists("Users/tester/AppData/Local/Temp/old.tmp")  # default kept
    assert sandbox.exists("Users/tester/Downloads/ancient.pdf")


def test_keep_is_never_deleted_even_in_review_mode(capsys, sandbox):
    code, payload, _ = run_json(capsys, sandbox, "--permanent",
                                "--categories", "+models,+large", "--max-risk", "review")
    assert code == cli.EXIT_OK
    assert sandbox.exists("Users/tester/.ollama/models/blobs/sha256-aaaa")
    assert sandbox.exists("Users/tester/.ollama/models/manifests/registry/library/qwen/latest")
    assert sandbox.exists("Users/tester/.lmstudio/models/vendor/model.gguf")
    assert sandbox.exists("Users/tester/.buzzcode/engine/llama-server.exe")
    assert "models" not in {c["cat"] for c in payload["candidates"]}


def test_expensive_dev_dirs_are_never_deleted_headlessly(capsys, sandbox):
    code, payload, _ = run_json(capsys, sandbox, "--permanent",
                                "--categories", "dev", "--max-risk", "review")
    assert code == cli.EXIT_OK
    assert not sandbox.exists("proj/__pycache__")                       # SAFE build cache
    assert sandbox.exists("proj/node_modules/left-pad/index.js")        # REVIEW: listed only
    assert sandbox.exists("live/node_modules/react/index.js")


def test_recycle_bin_is_the_default_outside_the_temp_categories(capsys, sandbox,
                                                                never_touch_the_real_recycle_bin):
    sent = never_touch_the_real_recycle_bin
    code, payload, _ = run_json(capsys, sandbox)          # no --permanent
    assert code == cli.EXIT_OK
    # temp/cache/logs/dumps are deleted permanently: really gone, never handed to the shell
    assert not sandbox.exists("Users/tester/AppData/Local/Temp/old.tmp")
    assert not any("old.tmp" in p for p in sent)
    # everything else goes to the Recycle Bin
    assert any(p.endswith("__pycache__") for p in sent)


# ---------------------------------------------------------------- target free space

def test_target_free_gb_already_met_deletes_nothing(capsys, sandbox):
    code, payload, err = run_json(capsys, sandbox, "--permanent", "--target-free-gb", "0.001")
    assert code == cli.EXIT_OK
    assert payload["deleted"]["count"] == 0
    assert payload["freed_bytes"] == 0
    assert "already has" in err
    assert sandbox.exists("Users/tester/AppData/Local/Temp/old.tmp")


def test_target_free_gb_stops_as_soon_as_the_drive_is_comfortable(capsys, sandbox, monkeypatch):
    target = int(1.0 * 1024 ** 3)
    answers = iter([0, 0, target, target, target, target])
    monkeypatch.setattr(cli, "_free_bytes", lambda drive: next(answers, target))
    monkeypatch.setattr(cli, "DELETE_BATCH", 1)
    code, payload, err = run_json(capsys, sandbox, "--permanent", "--target-free-gb", "1")
    assert code == cli.EXIT_OK
    assert payload["deleted"]["count"] == 2          # one batch, one check, one more batch
    assert "stopping here" in err
    # biggest first: the two largest SAFE findings went, the rest stayed
    assert sandbox.exists("Users/tester/AppData/Local/Temp/old.tmp")


# ---------------------------------------------------------------- drive filter

def test_drive_filter_keeps_only_that_drive(capsys, sandbox):
    drive = cli._drive_of(str(sandbox.root))
    code, payload, _ = run_json(capsys, sandbox, "--scan-only", "--drive", drive.lower())
    assert code == cli.EXIT_OK
    assert list(payload["drive_free_after"]) == [drive]
    assert payload["candidates"]


def test_drive_filter_that_matches_nothing_is_an_argument_error(capsys, sandbox):
    other = "Z:" if cli._drive_of(str(sandbox.root)) != "Z:" else "Y:"
    code, out, err = run(capsys, "--headless", "--json", "--root", str(sandbox.root), "--drive", other)
    assert code == cli.EXIT_ARGS
    assert out == ""


# ---------------------------------------------------------------- exit codes

def test_unknown_category_is_exit_2(capsys, sandbox):
    code, out, err = run(capsys, "--headless", "--root", str(sandbox.root), "--categories", "nonsense")
    assert code == cli.EXIT_ARGS
    assert "unknown category" in err


def test_missing_root_is_exit_2(capsys, sandbox):
    code, out, err = run(capsys, "--headless", "--root", str(sandbox.root / "nope"))
    assert code == cli.EXIT_ARGS


def test_bad_drive_is_exit_2(capsys, sandbox):
    code, out, err = run(capsys, "--headless", "--root", str(sandbox.root), "--drive", "hello")
    assert code == cli.EXIT_ARGS


def test_failures_are_reported_and_exit_1(capsys, sandbox, monkeypatch):
    def refuse(path):
        raise PermissionError("in use")
    monkeypatch.setattr(cleaner.os, "remove", refuse)
    monkeypatch.setattr(cleaner, "_rmtree", refuse)
    code, payload, _ = run_json(capsys, sandbox, "--permanent")
    assert code == cli.EXIT_PARTIAL
    assert payload["deleted"]["count"] == 0
    assert payload["failed"]
    assert set(payload["failed"][0]) == {"path", "error"}
    assert sandbox.exists("Users/tester/AppData/Local/Temp/old.tmp")


# ---------------------------------------------------------------- logging

def test_log_file_and_cleanup_record(capsys, sandbox):
    log = sandbox.dir / "logs" / "clean.log"
    code, payload, _ = run_json(capsys, sandbox, "--permanent", "--log", str(log))
    assert code == cli.EXIT_OK
    text = log.read_text(encoding="utf-8")
    assert "SmartCleaner" in text and "deleted" in text

    rows = [json.loads(line) for line in sandbox.cleanup_log()]
    assert rows and all(r["by"] == "cli" for r in rows)
    assert set(rows[0]) == {"t", "path", "size", "cat", "mode", "by"}
    assert {r["mode"] for r in rows} == {"permanent"}


def test_max_seconds_never_hangs(capsys, sandbox):
    code, payload, err = run_json(capsys, sandbox, "--scan-only", "--max-seconds", "30")
    assert code == cli.EXIT_OK
    assert payload["scanned"] > 0


@pytest.mark.parametrize("spec,expected_extra", [
    ("dumps", "debug"),
    ("dev-cache", "dev"),
    ("+downloads-old", "olddownloads"),
    ("recyclebin", "recycle"),
])
def test_category_aliases(spec, expected_extra):
    parser = cli.build_parser()
    cats, named = cli.parse_categories(spec, parser)
    assert expected_extra in cats and expected_extra in named
