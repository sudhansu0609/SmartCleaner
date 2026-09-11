"""Small Windows helpers (ctypes based, no extra dependencies)."""
from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
import sys

FILE_ATTRIBUTE_READONLY = 0x1
FILE_ATTRIBUTE_HIDDEN = 0x2
FILE_ATTRIBUTE_SYSTEM = 0x4
FILE_ATTRIBUTE_REPARSE_POINT = 0x400

IS_WINDOWS = sys.platform == "win32"

if IS_WINDOWS:
    import ctypes.wintypes as wt


def is_admin() -> bool:
    if not IS_WINDOWS:
        return os.geteuid() == 0  # type: ignore[attr-defined]
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin() -> bool:
    """Restart this program elevated. Returns True if the request was issued."""
    if not IS_WINDOWS:
        return False
    params = " ".join(f'"{a}"' for a in sys.argv)
    exe = sys.executable
    pyw = os.path.join(os.path.dirname(exe), "pythonw.exe")
    if os.path.exists(pyw) and exe.lower().endswith("python.exe"):
        exe = pyw
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
    return rc > 32


def list_drives() -> list[tuple[str, str, int, int]]:
    """Return [(root, label, total, free)] for ready fixed/removable drives."""
    out: list[tuple[str, str, int, int]] = []
    if not IS_WINDOWS:
        t = shutil.disk_usage("/")
        return [("/", "root", t.total, t.free)]
    try:
        roots = os.listdrives()  # py3.12+
    except AttributeError:
        roots = [f"{c}:\\" for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f"{c}:\\")]
    for root in roots:
        try:
            dtype = ctypes.windll.kernel32.GetDriveTypeW(root)
            if dtype not in (2, 3):  # DRIVE_REMOVABLE, DRIVE_FIXED
                continue
            usage = shutil.disk_usage(root)
            out.append((root, volume_label(root), usage.total, usage.free))
        except Exception:
            continue
    return out


def fixed_drive_roots() -> list[str]:
    """Roots of the fixed (internal) drives - what a headless clean-up scans by default."""
    if not IS_WINDOWS:
        return ["/"]
    try:
        roots = os.listdrives()  # py3.12+
    except AttributeError:
        roots = [f"{c}:\\" for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f"{c}:\\")]
    out: list[str] = []
    for root in roots:
        try:
            if ctypes.windll.kernel32.GetDriveTypeW(root) != 3:   # DRIVE_FIXED
                continue
            shutil.disk_usage(root)      # skip drives that are not ready
        except Exception:
            continue
        out.append(root)
    return out


def volume_label(root: str) -> str:
    if not IS_WINDOWS:
        return ""
    buf = ctypes.create_unicode_buffer(261)
    fs = ctypes.create_unicode_buffer(261)
    ok = ctypes.windll.kernel32.GetVolumeInformationW(
        root, buf, 261, None, None, None, fs, 261)
    return buf.value if ok else ""


if IS_WINDOWS:
    class _SHQUERYRBINFO(ctypes.Structure):
        _fields_ = [("cbSize", wt.DWORD), ("i64Size", ctypes.c_ulonglong),
                    ("i64NumItems", ctypes.c_ulonglong)]


def recycle_bin_info(root: str) -> tuple[int, int]:
    """(bytes, items) currently in the recycle bin of the given drive root."""
    if not IS_WINDOWS:
        return 0, 0
    info = _SHQUERYRBINFO()
    info.cbSize = ctypes.sizeof(info)
    rc = ctypes.windll.shell32.SHQueryRecycleBinW(root, ctypes.byref(info))
    if rc != 0:
        return 0, 0
    return int(info.i64Size), int(info.i64NumItems)


def empty_recycle_bin(root: str) -> bool:
    if not IS_WINDOWS:
        return False
    SHERB_NOCONFIRMATION, SHERB_NOPROGRESSUI, SHERB_NOSOUND = 1, 2, 4
    rc = ctypes.windll.shell32.SHEmptyRecycleBinW(
        None, root, SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND)
    return rc == 0


def open_in_explorer(path: str) -> None:
    if not IS_WINDOWS:
        return
    if os.path.exists(path):
        subprocess.Popen(["explorer", "/select,", path])
    else:
        subprocess.Popen(["explorer", os.path.dirname(path)])


def open_file(path: str) -> None:
    if IS_WINDOWS:
        os.startfile(path)  # type: ignore[attr-defined]


def norm(p: str) -> str:
    """Normalised, lower-case path used for comparisons."""
    return os.path.normcase(os.path.normpath(p))


def is_reparse(entry_or_stat) -> bool:
    attrs = getattr(entry_or_stat, "st_file_attributes", 0)
    return bool(attrs & FILE_ATTRIBUTE_REPARSE_POINT)


def is_system(st) -> bool:
    return bool(getattr(st, "st_file_attributes", 0) & FILE_ATTRIBUTE_SYSTEM)
