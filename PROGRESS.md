# SmartCleaner progress

## SC1–SC3 — the headless CLI, the KEEP rules and a test suite (2026-09-10)

Step A of `Buzzcaf_Media\GUARDIAN_PLAN.md`: SmartCleaner becomes the disk hand of
Sentinel's tray (§1 rule 3, §2 G13) without changing anything the window does.

### What was built

| Piece | File | Notes |
|---|---|---|
| CLI | `smartcleaner/cli.py` (new) | argparse, JSON contract, exit codes, category aliases, per-drive target-free stop. Imports nothing from `smartcleaner.ui` and needs no display |
| Entry point | `smartcleaner/__main__.py` (rewritten, 9 lines) | no arguments = the window, flags = the CLI |
| Window | `smartcleaner/gui.py` (new) | the old `__main__.py` body, unchanged, imported only when a window is wanted |
| KEEP rules | `smartcleaner/rules.py` | `KEEP_PROFILE_LOCATIONS`, `KEEP_SYSTEM_LOCATIONS`, `KEEP_ENV_VARS`, `keep_locations()`, `is_model_store()`, `profile_dirs()` |
| Category | `smartcleaner/model.py` | `models` — "AI model stores" |
| Scan pass | `smartcleaner/scanner.py` | `_model_stores()` runs first: measures each store, reports it `Risk.KEEP`, and **prunes** it so no later pass can propose anything inside it |
| Refusal | `smartcleaner/cleaner.py` | `_refuse()` rejects any path inside a model store; `delete_findings(..., by=)` writes `"by":"cli"` into `cleanup_log.jsonl` |
| Drives | `smartcleaner/winutil.py` | `fixed_drive_roots()` — the default scan set |
| Tests | `tests/` | 33 tests on a fake profile tree; `pytest.ini`; `.gitignore`; `git init` (no commit) |

### The rules that hold whatever the flags say

1. `Risk.SAFE` only — unless `--max-risk review` **and** the category was named on the
   command line (`--categories installers` alone is not enough, `--max-risk review` alone
   is not enough).
2. `Risk.KEEP` / `Risk.PROTECTED` are never deletable, by the CLI or the window. Model
   stores are KEEP: `~/.ollama/models`, `~/.lmstudio/models`, `~/.cache/lm-studio/models`,
   `AppData/Local/LM-Studio/models`, `<drive>\models` (so `B:\models`), `~/.buzzcode/engine`,
   plus whatever `%OLLAMA_MODELS%`, `%LMSTUDIO_MODELS_DIR%`, `%BUZZCODE_ENGINE_DIR%` or
   `%SMARTCLEANER_KEEP_DIRS%` point at. `cleaner._refuse()` re-checks by path shape, so a
   stale finding cannot slip through either.
3. The expensive developer folders (`node_modules`, `target`, `.venv`, `build`, `dist`, …)
   are listed but never deleted headlessly — the CLI only removes the build caches
   `rules.DEV_DIRS` marks SAFE (`__pycache__`, `.ruff_cache`, …). This is `GUARDIAN_PLAN`
   §2 G13 ("still never touches model stores or `DEV_DIRS`").
4. Nothing is deleted at all without `--headless`; `--scan-only` and `--json` on their own
   are read-only.
5. `recycle` (emptying the bin) and `windows` (Update leftovers) are **not** in the default
   category set — they must be asked for by name.

### Evidence

**Tests** (`python -m pytest`, Python 3.14.4, pytest 9.1.1):

```
.................................                                        [100%]
33 passed in 2.21s
```

Covered: no-args opens the window · safe-only deletion · REVIEW untouched without
`--max-risk review` · REVIEW untouched with `review` but no explicit category · KEEP never
deleted even in review mode · `node_modules` never deleted while `__pycache__` is · JSON
key set / types / stdout-vs-stderr split · `--scan-only` is byte-for-byte read-only ·
`--target-free-gb` already met, and stopping mid-way after two batches · `--drive` filter
and its exit 2 · unknown category / missing root / bad drive → exit 2 · per-file failures →
exit 1 with `{"path","error"}` rows · Recycle Bin vs permanent routing · `--log` file ·
`cleanup_log.jsonl` rows carry `"by":"cli"` · category aliases · `--max-seconds`.
The suite fakes `send2trash` and `empty_recycle_bin`, so it never touches the real bin, and
builds its tree under `tests\.tmp` (not `%TEMP%`, which lives under `AppData` and would
switch off half the heuristics).

**Real machine, read-only** — `python -m smartcleaner --headless --scan-only --json
--max-seconds 60` (all six fixed drives; the budget ran out inside C:, so this is B: plus
part of C:):

```
scanned 1,281,820 files in 60.2 s (cut short by --max-seconds)
found:
  Recycle Bin                        2 items      28.9 GB
  Temporary files                  331 items      73.2 MB   -> 331 to delete
  Caches                         4,484 items     515.9 MB   -> 888 to delete
  Logs                             411 items      32.1 MB   -> 411 to delete
  Debug & diagnostic files         256 items       2.0 GB   ->  13 to delete
  Empty folders                    268 items          0 B
  Developer leftovers              408 items      98.4 GB   -> 357 to delete
  Large files                      257 items     585.4 GB
  Windows leftovers                933 items       5.1 GB
  Backup & old copies              126 items     401.2 KB
  AI model stores                    4 items      54.8 GB   kept
scan only: nothing deleted (2,000 items, 351.3 MB would go)
```

```json
{"scanned": 1281820,
 "candidates": [{"cat":"temp","count":331,"bytes":76788092},
                {"cat":"cache","count":888,"bytes":203480956},
                {"cat":"logs","count":411,"bytes":33616301},
                {"cat":"debug","count":13,"bytes":9365666},
                {"cat":"dev","count":357,"bytes":45144523}],
 "deleted": {"count": 0, "bytes": 0}, "failed": [], "freed_bytes": 0,
 "drive_free_after": {"B:":90755207168,"C:":102584311808,"D:":259874159616,
                      "E:":417122938880,"F:":372850429952,"H:":249168875520},
 "elapsed_s": 60.22, "is_admin": false, "mode": "safe", "scan_only": true}
```

The four AI model stores (54.8 GB: `C:\Users\singh\.ollama\models`, the LM Studio store,
`~/.buzzcode/engine`, `B:\models`) were reported as KEEP and pruned — nothing inside them
appears anywhere else in the scan. No deleting run was made on this machine.

**Exit codes**, measured:

| Command | Exit |
|---|---|
| `--version`, `--headless --scan-only --json --root <dir>` | 0 |
| a run with per-file failures (`failed` non-empty) | 1 |
| `--categories nonsense --headless` | 2 |
| `--headless --json --root Q:\nope` | 2 |
| `--headless --json --drive Z: --root B:\…` | 2 |

### Deviations from the SC1–SC3 brief, and why

* **`candidates` = what would be deleted with the flags given**, not every finding, so
  `--scan-only --json` is an exact dry run for Sentinel. The full survey of every category
  is in the human report (stderr), which is where a person reads it.
* **A `models` category was added to `model.py`** so the stores have somewhere to live; the
  window shows them as a non-selectable "Info" row (`_refresh_cat_item_inner` already
  handles a category with nothing deletable in it).
* **The default category set is `temp,cache,logs,debug,dev`** — `recycle` is excluded
  because emptying the bin destroys the owner's undo (28.9 GB sits there today; ask for it
  with `--categories +recycle`).
* **Duplicate hashing is off unless `dupes` is requested.** It reads every candidate file
  and holds a record per file; a headless run that is not asked for duplicates should not
  pay that in time or RAM.
* **Aliases** (`dumps`→`debug`, `dev-cache`→`dev`, `downloads-old`→`olddownloads`) exist so
  the exact command lines written in `GUARDIAN_PLAN` §2 G13 work as written.
* **`delete_findings` now always writes `"by"`** — `"cli"` headless, `"gui"` from the
  window. The rest of the record is unchanged.
* **`--max-seconds` is one budget for the whole run**, not per root. With the default
  (every fixed drive) the alphabetically first drive can eat it, so time-boxed callers
  should pass `--drive` or `--root`. Sentinel's tray does.

### Not done here (belongs to other steps)

Sentinel's `[disk]` section, the `DiskTight`/`RequestCleanup`/`ReportCleanup` protocol and
the tray that calls this CLI are Sentinel G13. Dexter's "clean up space" tool is D-series.
