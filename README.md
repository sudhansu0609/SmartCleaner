# SmartCleaner

A safety-first disk clean-up tool for Windows. Point it at any drive or folder, and it finds
temp files, caches, logs, duplicates, old installers, stale developer folders, empty folders
and the big files that eat your disk. It explains every finding, pre-selects only the items
that are safe, and never deletes anything until you press a button. By default everything
goes to the Recycle Bin, so you can undo.

## Run it

```bat
run.bat
```

`run.bat` installs the two dependencies (PySide6, send2trash) on first use and launches
`SmartCleaner.pyw` without a console window. You can also run `python -m smartcleaner`
from this folder. To create a desktop shortcut, right-click `SmartCleaner.pyw` > Send to >
Desktop.

Use **Restart as Administrator** in the toolbar to include `C:\Windows\Temp`, Windows
Update caches and other users' profiles.

## Headless: `python -m smartcleaner --headless`

With **no arguments SmartCleaner opens the window** exactly as before. Any flag switches it
to the command line, where it uses the same scanner, the same rules and the same cleaner -
no Qt, no display needed. This is how Sentinel's tray frees space when a drive turns red,
and how Dexter answers "clean up space".

```bat
:: what would go, machine-readable, read-only
python -m smartcleaner --headless --scan-only --json --drive C: --max-seconds 120

:: the safe clean-up Sentinel's tray runs (it must run as the logged-in user)
python -m smartcleaner --headless --json --max-risk safe ^
    --categories temp,cache,logs,dumps,dev-cache --target-free-gb 25 --drive C:

:: a deeper one the owner asks for by name
python -m smartcleaner --headless --json --max-risk review ^
    --categories +installers,+downloads-old,+recycle --drive C:
```

| Flag | Meaning |
|------|---------|
| `--headless` | no window. **Nothing is ever deleted without it** |
| `--scan-only` | report only |
| `--json` | JSON on stdout, the human report on stderr |
| `--categories a,b,+c` | category keys; `+x` adds x to the default set (`temp,cache,logs,debug,dev`). `dumps`, `dev-cache`, `downloads-old`, `recyclebin` are accepted spellings |
| `--max-risk safe\|review` | `review` also deletes REVIEW findings - but only in categories you named explicitly |
| `--target-free-gb N` | stop deleting as soon as the drive has that much free |
| `--drive C:` | only findings on that drive |
| `--permanent` | skip the Recycle Bin (already the default for temp/cache/logs/dumps) |
| `--log PATH` | append the human report to a file |
| `--max-seconds N` | time budget for the scan; a longer scan is cut short and what was found is used |
| `--root PATH` | scan this path (repeatable). Default: every fixed drive |

```json
{"scanned": 1405712,
 "candidates": [{"cat": "temp", "count": 296, "bytes": 19765893}],
 "deleted": {"count": 0, "bytes": 0}, "failed": [], "freed_bytes": 0,
 "drive_free_after": {"C:": 101477302272}, "elapsed_s": 45.04,
 "is_admin": false, "mode": "safe", "scan_only": true}
```

`candidates` is what *would* be deleted with the flags you passed (so `--scan-only --json`
is an exact dry run); the full survey of everything the scan found is in the human report.
Exit codes: **0** done, **1** finished with per-file failures (`failed` says which), **2**
bad arguments or nothing to scan.

### What the CLI will never do

* delete anything that is not `Risk.SAFE`, unless you pass `--max-risk review` *and* name
  the category on the command line;
* delete a `Risk.KEEP` or `Risk.PROTECTED` finding - **model stores are KEEP**:
  `~/.ollama/models`, `~/.lmstudio/models`, `~/.cache/lm-studio/models`, `B:\models`,
  `~/.buzzcode/engine`, and anything `%OLLAMA_MODELS%` points at. They are measured and
  listed so you can see what they cost, and refused by the cleaner itself;
* delete the expensive developer folders (`node_modules`, `target`, `.venv`, `build`,
  `dist` ...). It removes only the cheap build caches `rules.DEV_DIRS` marks SAFE
  (`__pycache__`, `.ruff_cache`, `.mypy_cache`, `.pytest_cache` ...);
* touch `Windows`, `Program Files`, `ProgramData` or anything else in `PROTECTED_ROOT_DIRS`.

Two things are *not* in the default category set on purpose: `recycle` (emptying the
Recycle Bin throws away your undo) and `windows` (Windows Update leftovers are REVIEW).
Ask for them by name - `--categories +recycle` - when you mean it.

Every deletion is appended to `%LOCALAPPDATA%\SmartCleaner\cleanup_log.jsonl` with
`"by": "cli"`, so a headless clean-up can be told apart from one you did yourself.

### Tests

```bat
python -m pytest
```

The tests build a fake profile tree under `tests\.tmp` and never touch your real drives or
your Recycle Bin.

## How it decides

| Level | Meaning | Pre-selected |
|-------|---------|--------------|
| **Safe** | Temp folders, caches, old logs, crash dumps and error reports, empty folders, `__pycache__`, Recycle Bin | yes |
| **Review** | Duplicates, installers in Downloads, old downloads, `node_modules`/venv, large files, `.bak` files | no (★ marks recommended ones) |
| **Keep** | The copy of a duplicate group we suggest keeping, and every AI model store (Ollama, LM Studio, `B:\models`, the BuzzCode engine) | cannot be selected |
| **Protected** | `hiberfil.sys` and friends, shown only for advice | cannot be selected |

Never touched at all: `Windows`, `Program Files`, `ProgramData` (except known caches),
`System Volume Information`, `Recovery`, `.git` folders, credential stores, files with the
System attribute, junctions and symlinks, anything in **Settings > Protected folders**.

Duplicates are found by size, then a quick head+tail hash, then a full BLAKE2 hash, so a
match means byte-identical content. The keeper is chosen by location (not Downloads or
Desktop, not named "Copy" or "(1)", inside Documents/Pictures, oldest). Use **Keep this one
instead** in the Details panel to override.

## Memory & caches (RAM, VRAM, live caches)

**Memory & caches** in the toolbar handles the things that are not files on disk. Nothing in
that window deletes user data; it only asks Windows to let go of memory it is holding.

| Clean-up | What it does | Admin |
|----------|--------------|-------|
| Trim working sets | Every program hands unused RAM back; pages are reloaded on demand | no (more reach with admin) |
| Empty working sets system-wide | The kernel does the same for services and other users | yes |
| Purge standby list | Drops cached file pages so "Cached" RAM becomes "Free" (what RAMMap does) | yes |
| Flush modified list / file cache | Writes dirty pages out and trims the kernel file cache | yes |
| Clear clipboard | A copied screenshot or spreadsheet block can hold hundreds of MB | no |
| Restart graphics driver | Sends Win+Ctrl+Shift+B: the screen blinks once and leaked VRAM is released | no |
| Flush DNS, refresh icon cache, thumbnail cache, Microsoft Store cache | The usual "fix it" caches | no |
| Delivery Optimization cache, font cache | Service-owned caches, cleared the way the service expects | yes |

The **Programs using memory** tab lists every process with its RAM (working set), committed
(private) bytes and dedicated / shared VRAM, taken from Windows performance counters. You can
trim a single program or end it. Committed memory only drops when a program frees memory or
exits, which is why that tab exists; core Windows processes are greyed out and cannot be ended.

Debug leftovers on disk (crash dumps, minidumps, `MEMORY.DMP`, Windows Error Reporting queues,
Crashpad reports from browsers and Electron apps, WPR traces, setup and driver logs) show up
under **Debug & diagnostic files** after a scan.

## Layout

```
smartcleaner/
  __main__.py     `python -m smartcleaner`: no arguments = the window, flags = the CLI
  cli.py          The headless command line (argparse, JSON, exit codes; no Qt)
  gui.py          Starts the PySide6 application
  model.py        Finding / Category / Risk data types
  rules.py        The knowledge base: known clean-up locations, protected areas, heuristics
  scanner.py      Filesystem walk, classification, duplicate hashing (no Qt)
  cleaner.py      Recycle Bin / permanent deletion with refusal checks and a JSONL log
  settings.py     Thresholds persisted to %LOCALAPPDATA%\SmartCleaner\settings.json
  winutil.py      ctypes helpers: drives, Recycle Bin, admin, Explorer
  sysclean.py     RAM / VRAM / live-cache operations (ctypes, PDH counters, no Qt)
  ui/             PySide6 window, dialogs, suggestions text, worker threads
  ui/memory_dialog.py   The Memory & caches window
tests/            pytest suite: the CLI and the KEEP rules, on a fake profile tree
```

Every deletion is appended to `%LOCALAPPDATA%\SmartCleaner\cleanup_log.jsonl`.

## Extending

Add a line to `PROFILE_LOCATIONS` or `SYSTEM_LOCATIONS` in `rules.py` to teach it a new
cache folder; add to `DEV_DIRS` for a new build-output folder name. Everything else follows.
# SmartCleaner
