"""Live-system clean-up: RAM, committed memory, VRAM and the caches that are not plain files.

Everything here is ctypes / subprocess based (no Qt, no extra packages) so it can be driven
from a worker thread or from a test script.  Every operation returns an OpResult and never
raises, so the UI can always show *what* happened and *why* something was skipped.

Terminology (matches Task Manager):
  working set   RAM a process currently holds.  Trimming it pushes pages to the standby
                list / pagefile; the program pulls them back on demand.
  standby list  RAM holding cached file data / trimmed pages.  Counted as "available"
                but shown as "cached"; purging it gives truly free RAM.
  commit charge the memory programs have *promised* to use (RAM + pagefile).  It only goes
                down when a program releases memory or exits - no tool can lower it from the
                outside, so we show the biggest committers and let you decide.
"""
from __future__ import annotations

import ctypes
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass, field

from .winutil import IS_WINDOWS, is_admin

if IS_WINDOWS:
    import ctypes.wintypes as wt
    import winreg

    kernel32 = ctypes.windll.kernel32
    psapi = ctypes.windll.psapi
    advapi32 = ctypes.windll.advapi32
    ntdll = ctypes.windll.ntdll
    user32 = ctypes.windll.user32

_CREATE_NO_WINDOW = 0x08000000


# --------------------------------------------------------------------------------------
# Results
# --------------------------------------------------------------------------------------

@dataclass
class OpResult:
    key: str
    title: str
    ok: bool
    message: str
    freed: int = 0                 # bytes, when meaningful
    needs_admin: bool = False      # failed only because we are not elevated
    details: list[str] = field(default_factory=list)


@dataclass
class MemoryStatus:
    total: int = 0
    available: int = 0
    used: int = 0
    load_pct: int = 0
    commit_total: int = 0
    commit_limit: int = 0
    commit_peak: int = 0
    system_cache: int = 0          # file cache resident in RAM
    standby: int = 0               # bytes on the standby list (0 if it could not be read)
    modified: int = 0              # bytes on the modified page list
    free_zero: int = 0             # free + zeroed pages
    pagefile_used: int = 0


@dataclass
class ProcInfo:
    pid: int
    name: str
    working_set: int = 0
    private: int = 0               # private (committed) bytes
    gpu_dedicated: int = 0
    gpu_shared: int = 0
    exe: str = ""


@dataclass
class GpuInfo:
    name: str
    dedicated_used: int = 0
    dedicated_total: int = 0
    shared_used: int = 0
    luid: str = ""


# --------------------------------------------------------------------------------------
# Structures
# --------------------------------------------------------------------------------------

if IS_WINDOWS:
    class MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [("dwLength", wt.DWORD), ("dwMemoryLoad", wt.DWORD),
                    ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]

    class PERFORMANCE_INFORMATION(ctypes.Structure):
        _fields_ = [("cb", wt.DWORD), ("CommitTotal", ctypes.c_size_t), ("CommitLimit", ctypes.c_size_t),
                    ("CommitPeak", ctypes.c_size_t), ("PhysicalTotal", ctypes.c_size_t),
                    ("PhysicalAvailable", ctypes.c_size_t), ("SystemCache", ctypes.c_size_t),
                    ("KernelTotal", ctypes.c_size_t), ("KernelPaged", ctypes.c_size_t),
                    ("KernelNonpaged", ctypes.c_size_t), ("PageSize", ctypes.c_size_t),
                    ("HandleCount", wt.DWORD), ("ProcessCount", wt.DWORD), ("ThreadCount", wt.DWORD)]

    class SYSTEM_MEMORY_LIST_INFORMATION(ctypes.Structure):
        _fields_ = [("ZeroPageCount", ctypes.c_size_t), ("FreePageCount", ctypes.c_size_t),
                    ("ModifiedPageCount", ctypes.c_size_t), ("ModifiedNoWritePageCount", ctypes.c_size_t),
                    ("BadPageCount", ctypes.c_size_t), ("PageCountByPriority", ctypes.c_size_t * 8),
                    ("RepurposedPagesByPriority", ctypes.c_size_t * 8),
                    ("ModifiedPageCountPageFile", ctypes.c_size_t)]

    class PROCESS_MEMORY_COUNTERS_EX(ctypes.Structure):
        _fields_ = [("cb", wt.DWORD), ("PageFaultCount", wt.DWORD),
                    ("PeakWorkingSetSize", ctypes.c_size_t), ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t), ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t), ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t), ("PeakPagefileUsage", ctypes.c_size_t),
                    ("PrivateUsage", ctypes.c_size_t)]

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [("dwSize", wt.DWORD), ("cntUsage", wt.DWORD), ("th32ProcessID", wt.DWORD),
                    ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)), ("th32ModuleID", wt.DWORD),
                    ("cntThreads", wt.DWORD), ("th32ParentProcessID", wt.DWORD), ("pcPriClassBase", ctypes.c_long),
                    ("dwFlags", wt.DWORD), ("szExeFile", ctypes.c_wchar * 260)]

    class LUID(ctypes.Structure):
        _fields_ = [("LowPart", wt.DWORD), ("HighPart", ctypes.c_long)]

    class LUID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Luid", LUID), ("Attributes", wt.DWORD)]

    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [("PrivilegeCount", wt.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)]

    class KEYBDINPUT(ctypes.Structure):
        _fields_ = [("wVk", wt.WORD), ("wScan", wt.WORD), ("dwFlags", wt.DWORD), ("time", wt.DWORD),
                    ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong))]

    class _INPUT_UNION(ctypes.Union):
        _fields_ = [("ki", KEYBDINPUT), ("padding", ctypes.c_byte * 32)]

    class INPUT(ctypes.Structure):
        _fields_ = [("type", wt.DWORD), ("u", _INPUT_UNION)]

    class PDH_FMT_COUNTERVALUE(ctypes.Structure):
        _fields_ = [("CStatus", wt.DWORD), ("padding", wt.DWORD), ("largeValue", ctypes.c_longlong)]

    class PDH_FMT_COUNTERVALUE_ITEM_W(ctypes.Structure):
        _fields_ = [("szName", wt.LPWSTR), ("FmtValue", PDH_FMT_COUNTERVALUE)]

    kernel32.OpenProcess.restype = wt.HANDLE
    kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    kernel32.CloseHandle.argtypes = [wt.HANDLE]
    kernel32.CreateToolhelp32Snapshot.restype = wt.HANDLE
    kernel32.GetCurrentProcess.restype = wt.HANDLE
    psapi.EmptyWorkingSet.argtypes = [wt.HANDLE]
    psapi.GetProcessMemoryInfo.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.DWORD]
    kernel32.QueryFullProcessImageNameW.argtypes = [wt.HANDLE, wt.DWORD, wt.LPWSTR, ctypes.POINTER(wt.DWORD)]
    kernel32.TerminateProcess.argtypes = [wt.HANDLE, wt.UINT]

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_SET_QUOTA = 0x0100
PROCESS_TERMINATE = 0x0001
TH32CS_SNAPPROCESS = 0x2
INVALID_HANDLE_VALUE = wt.HANDLE(-1).value if IS_WINDOWS else -1

SE_PRIVILEGE_ENABLED = 0x2
TOKEN_ADJUST_PRIVILEGES = 0x20
TOKEN_QUERY = 0x8

SystemFileCacheInformation = 21
SystemMemoryListInformation = 80
MemoryEmptyWorkingSets = 2
MemoryFlushModifiedList = 3
MemoryPurgeStandbyList = 4
MemoryPurgeLowPriorityStandbyList = 5

# Processes that must never be terminated from a clean-up tool.
CRITICAL_PROCESSES = {
    "system", "registry", "memory compression", "secure system", "smss.exe", "csrss.exe", "wininit.exe",
    "winlogon.exe", "services.exe", "lsass.exe", "lsaiso.exe", "svchost.exe", "dwm.exe", "fontdrvhost.exe",
    "sihost.exe", "ctfmon.exe", "audiodg.exe", "spoolsv.exe", "wudfhost.exe", "conhost.exe", "runtimebroker.exe",
    "taskhostw.exe", "explorer.exe", "startmenuexperiencehost.exe", "shellexperiencehost.exe", "searchhost.exe",
    "textinputhost.exe", "securityhealthservice.exe", "msmpeng.exe", "nissrv.exe", "mssense.exe", "dllhost.exe",
    "wmiprvse.exe", "userinit.exe", "logonui.exe", "smartscreen.exe", "applicationframehost.exe",
    "systemsettings.exe", "nvdisplay.container.exe", "nvcontainer.exe", "atieclxx.exe", "igfxem.exe",
}
# Never trimmed: trimming these causes visible stutter or is pointless.
NO_TRIM_PROCESSES = {"system", "registry", "memory compression", "secure system", "dwm.exe", "csrss.exe",
                     "audiodg.exe", "lsass.exe", "smss.exe", "wininit.exe", "winlogon.exe"}


def _err(rc: int | None = None) -> str:
    if not IS_WINDOWS:
        return "not Windows"
    code = ctypes.get_last_error() if rc is None else rc
    try:
        return f"{ctypes.FormatError(code).strip()} (error {code})"
    except Exception:  # noqa: BLE001
        return f"error {code}"


# --------------------------------------------------------------------------------------
# Privileges
# --------------------------------------------------------------------------------------

def enable_privilege(name: str) -> bool:
    """Turn on a privilege the current token already holds (needs an elevated token for most)."""
    if not IS_WINDOWS:
        return False
    token = wt.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                                     ctypes.byref(token)):
        return False
    try:
        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        if not advapi32.LookupPrivilegeValueW(None, name, ctypes.byref(tp.Privileges[0].Luid)):
            return False
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
        advapi32.AdjustTokenPrivileges(token, False, ctypes.byref(tp), 0, None, None)
        return kernel32.GetLastError() == 0
    finally:
        kernel32.CloseHandle(token)


# --------------------------------------------------------------------------------------
# Memory status
# --------------------------------------------------------------------------------------

def memory_status() -> MemoryStatus:
    ms = MemoryStatus()
    if not IS_WINDOWS:
        return ms
    m = MEMORYSTATUSEX()
    m.dwLength = ctypes.sizeof(m)
    if kernel32.GlobalMemoryStatusEx(ctypes.byref(m)):
        ms.total, ms.available, ms.load_pct = int(m.ullTotalPhys), int(m.ullAvailPhys), int(m.dwMemoryLoad)
        ms.used = ms.total - ms.available
    pi = PERFORMANCE_INFORMATION()
    pi.cb = ctypes.sizeof(pi)
    if psapi.GetPerformanceInfo(ctypes.byref(pi), pi.cb):
        page = int(pi.PageSize) or 4096
        ms.commit_total = int(pi.CommitTotal) * page
        ms.commit_limit = int(pi.CommitLimit) * page
        ms.commit_peak = int(pi.CommitPeak) * page
        ms.system_cache = int(pi.SystemCache) * page
        ms.pagefile_used = max(0, ms.commit_total - ms.used)
        info = SYSTEM_MEMORY_LIST_INFORMATION()
        rc = ntdll.NtQuerySystemInformation(SystemMemoryListInformation, ctypes.byref(info),
                                            ctypes.sizeof(info), None)
        if rc == 0:
            ms.standby = sum(int(c) for c in info.PageCountByPriority) * page
            ms.modified = int(info.ModifiedPageCount) * page
            ms.free_zero = (int(info.FreePageCount) + int(info.ZeroPageCount)) * page
    return ms


# --------------------------------------------------------------------------------------
# Processes
# --------------------------------------------------------------------------------------

def _open(pid: int, access: int):
    h = kernel32.OpenProcess(access, False, pid)
    return h or None


def _proc_memory(h) -> tuple[int, int]:
    pmc = PROCESS_MEMORY_COUNTERS_EX()
    pmc.cb = ctypes.sizeof(pmc)
    if psapi.GetProcessMemoryInfo(h, ctypes.byref(pmc), pmc.cb):
        return int(pmc.WorkingSetSize), int(pmc.PrivateUsage)
    return 0, 0


def _proc_exe(h) -> str:
    buf = ctypes.create_unicode_buffer(1024)
    n = wt.DWORD(1024)
    if kernel32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(n)):
        return buf.value
    return ""


def list_processes(with_gpu: bool = True) -> list[ProcInfo]:
    """Every process we can see, with RAM / committed / VRAM usage (0 where not readable)."""
    out: list[ProcInfo] = []
    if not IS_WINDOWS:
        return out
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == INVALID_HANDLE_VALUE:
        return out
    try:
        pe = PROCESSENTRY32W()
        pe.dwSize = ctypes.sizeof(pe)
        ok = kernel32.Process32FirstW(snap, ctypes.byref(pe))
        while ok:
            p = ProcInfo(int(pe.th32ProcessID), pe.szExeFile)
            h = _open(p.pid, PROCESS_QUERY_LIMITED_INFORMATION)
            if h:
                p.working_set, p.private = _proc_memory(h)
                p.exe = _proc_exe(h)
                kernel32.CloseHandle(h)
            out.append(p)
            ok = kernel32.Process32NextW(snap, ctypes.byref(pe))
    finally:
        kernel32.CloseHandle(snap)
    if with_gpu:
        gpu = gpu_process_memory()
        for p in out:
            ded, sh = gpu.get(p.pid, (0, 0))
            p.gpu_dedicated, p.gpu_shared = ded, sh
    return out


def is_critical(p: ProcInfo) -> bool:
    return p.pid in (0, 4, os.getpid()) or p.name.lower() in CRITICAL_PROCESSES


def trim_working_sets(skip_pids: set[int] | None = None) -> OpResult:
    """Ask every process we may touch to give its working set back to the system.

    Programs keep working normally; pages they still need come back on first touch (a
    short slowdown).  This is the same thing "memory cleaner" tools do.
    """
    if not IS_WINDOWS:
        return OpResult("trim", "Trim working sets", False, "Only available on Windows.")
    skip = set(skip_pids or ())
    before = memory_status()
    trimmed = failed = skipped = 0
    for p in list_processes(with_gpu=False):
        if p.pid in skip or p.pid in (0, 4, os.getpid()) or p.name.lower() in NO_TRIM_PROCESSES:
            skipped += 1
            continue
        h = _open(p.pid, PROCESS_QUERY_INFORMATION | PROCESS_SET_QUOTA)
        if not h:
            failed += 1
            continue
        try:
            if psapi.EmptyWorkingSet(h):
                trimmed += 1
            else:
                failed += 1
        finally:
            kernel32.CloseHandle(h)
    time.sleep(0.4)
    after = memory_status()
    freed = max(0, after.available - before.available)
    msg = f"Trimmed {trimmed} processes ({failed} not accessible, {skipped} skipped on purpose)."
    if failed and not is_admin():
        msg += " Run as Administrator to reach processes of other users and services."
    return OpResult("trim", "Trim working sets", trimmed > 0, msg, freed=freed,
                    needs_admin=trimmed == 0 and failed > 0 and not is_admin())


def trim_process(pid: int) -> OpResult:
    if not IS_WINDOWS:
        return OpResult("trim1", "Trim process", False, "Only available on Windows.")
    h = _open(pid, PROCESS_QUERY_INFORMATION | PROCESS_SET_QUOTA)
    if not h:
        return OpResult("trim1", "Trim process", False, f"Cannot open process {pid}: {_err()}",
                        needs_admin=not is_admin())
    try:
        ws_before, _ = _proc_memory(h)
        ok = bool(psapi.EmptyWorkingSet(h))
        ws_after, _ = _proc_memory(h)
    finally:
        kernel32.CloseHandle(h)
    if not ok:
        return OpResult("trim1", "Trim process", False, _err())
    return OpResult("trim1", "Trim process", True, "Working set released.", freed=max(0, ws_before - ws_after))


def end_process(pid: int, name: str) -> OpResult:
    """Terminate a process the user explicitly chose.  Refuses anything Windows needs."""
    if not IS_WINDOWS:
        return OpResult("kill", "End process", False, "Only available on Windows.")
    if pid in (0, 4, os.getpid()) or name.lower() in CRITICAL_PROCESSES:
        return OpResult("kill", "End process", False, f"{name} is part of Windows and will not be ended from here.")
    h = _open(pid, PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION)
    if not h:
        return OpResult("kill", "End process", False, f"Cannot open {name}: {_err()}", needs_admin=not is_admin())
    try:
        _, private = _proc_memory(h)
        if not kernel32.TerminateProcess(h, 1):
            return OpResult("kill", "End process", False, f"Cannot end {name}: {_err()}")
    finally:
        kernel32.CloseHandle(h)
    return OpResult("kill", "End process", True, f"{name} (PID {pid}) ended. Unsaved work in it is lost.", freed=private)


# --------------------------------------------------------------------------------------
# System-wide memory lists (Administrator)
# --------------------------------------------------------------------------------------

def _memory_list_command(cmd: int, key: str, title: str, what: str) -> OpResult:
    if not IS_WINDOWS:
        return OpResult(key, title, False, "Only available on Windows.")
    if not is_admin():
        return OpResult(key, title, False, "Needs Administrator rights (use Restart as Administrator).", needs_admin=True)
    enable_privilege("SeProfileSingleProcessPrivilege")
    enable_privilege("SeIncreaseQuotaPrivilege")
    before = memory_status()
    c = ctypes.c_int(cmd)
    rc = ntdll.NtSetSystemInformation(SystemMemoryListInformation, ctypes.byref(c), ctypes.sizeof(c))
    if rc != 0:
        return OpResult(key, title, False, f"NtSetSystemInformation failed (NTSTATUS 0x{rc & 0xFFFFFFFF:08X}).")
    time.sleep(0.4)
    after = memory_status()
    freed = max(0, after.free_zero - before.free_zero) if before.free_zero or after.free_zero \
        else max(0, after.available - before.available)
    return OpResult(key, title, True, f"{what} Free RAM went from "
                    f"{_hs(before.free_zero or before.available)} to {_hs(after.free_zero or after.available)}.",
                    freed=freed)


def purge_standby_list() -> OpResult:
    return _memory_list_command(MemoryPurgeStandbyList, "standby", "Purge standby list",
                                "Cached pages were dropped; they are re-read from disk when needed.")


def purge_low_priority_standby() -> OpResult:
    return _memory_list_command(MemoryPurgeLowPriorityStandbyList, "standby_low", "Purge low-priority standby list",
                                "Low-priority cached pages (prefetch, background reads) were dropped.")


def flush_modified_list() -> OpResult:
    return _memory_list_command(MemoryFlushModifiedList, "modified", "Flush modified page list",
                                "Dirty pages were written to the pagefile so they can be reused.")


def empty_all_working_sets() -> OpResult:
    return _memory_list_command(MemoryEmptyWorkingSets, "ws_all", "Empty all working sets (system-wide)",
                                "Windows trimmed every process, including services and other users.")


def flush_system_file_cache() -> OpResult:
    """Release the system file cache (the 'Cached' number in Task Manager)."""
    key, title = "filecache", "Flush system file cache"
    if not IS_WINDOWS:
        return OpResult(key, title, False, "Only available on Windows.")
    if not is_admin():
        return OpResult(key, title, False, "Needs Administrator rights.", needs_admin=True)
    enable_privilege("SeIncreaseQuotaPrivilege")

    class SYSTEM_FILECACHE_INFORMATION(ctypes.Structure):
        _fields_ = [("CurrentSize", ctypes.c_size_t), ("PeakSize", ctypes.c_size_t),
                    ("PageFaultCount", wt.ULONG), ("MinimumWorkingSet", ctypes.c_size_t),
                    ("MaximumWorkingSet", ctypes.c_size_t), ("CurrentSizeIncludingTransitionInPages", ctypes.c_size_t),
                    ("PeakSizeIncludingTransitionInPages", ctypes.c_size_t), ("TransitionRePurposeCount", wt.ULONG),
                    ("Flags", wt.ULONG)]
    before = memory_status()
    info = SYSTEM_FILECACHE_INFORMATION()
    info.MinimumWorkingSet = ctypes.c_size_t(-1).value
    info.MaximumWorkingSet = ctypes.c_size_t(-1).value
    rc = ntdll.NtSetSystemInformation(SystemFileCacheInformation, ctypes.byref(info), ctypes.sizeof(info))
    if rc != 0:
        return OpResult(key, title, False, f"NtSetSystemInformation failed (NTSTATUS 0x{rc & 0xFFFFFFFF:08X}).")
    time.sleep(0.3)
    after = memory_status()
    return OpResult(key, title, True, f"System file cache trimmed from {_hs(before.system_cache)} to "
                    f"{_hs(after.system_cache)}.", freed=max(0, before.system_cache - after.system_cache))


# --------------------------------------------------------------------------------------
# Clipboard
# --------------------------------------------------------------------------------------

def clear_clipboard() -> OpResult:
    """A copied screenshot or spreadsheet block can hold hundreds of MB."""
    key, title = "clipboard", "Clear clipboard"
    if not IS_WINDOWS:
        return OpResult(key, title, False, "Only available on Windows.")
    if not user32.OpenClipboard(None):
        return OpResult(key, title, False, "Clipboard is in use by another program.")
    try:
        ok = bool(user32.EmptyClipboard())
    finally:
        user32.CloseClipboard()
    return OpResult(key, title, ok, "Clipboard emptied." if ok else _err())


# --------------------------------------------------------------------------------------
# GPU / VRAM
# --------------------------------------------------------------------------------------

_PDH_MORE_DATA = 0x800007D2
PDH_FMT_LARGE = 0x400


def _pdh_counter_array(path: str) -> dict[str, int]:
    """Read every instance of a counter path in one go. {} if PDH or the counter is missing."""
    if not IS_WINDOWS:
        return {}
    try:
        pdh = ctypes.windll.pdh
    except OSError:
        return {}
    query = wt.HANDLE()
    if pdh.PdhOpenQueryW(None, 0, ctypes.byref(query)) != 0:
        return {}
    out: dict[str, int] = {}
    try:
        counter = wt.HANDLE()
        if pdh.PdhAddEnglishCounterW(query, path, 0, ctypes.byref(counter)) != 0:
            return {}
        if pdh.PdhCollectQueryData(query) != 0:
            return {}
        size = wt.DWORD(0)
        count = wt.DWORD(0)
        rc = pdh.PdhGetFormattedCounterArrayW(counter, PDH_FMT_LARGE, ctypes.byref(size), ctypes.byref(count), None)
        if (rc & 0xFFFFFFFF) != _PDH_MORE_DATA or size.value == 0:
            return {}
        buf = ctypes.create_string_buffer(size.value)
        rc = pdh.PdhGetFormattedCounterArrayW(counter, PDH_FMT_LARGE, ctypes.byref(size), ctypes.byref(count), buf)
        if rc != 0:
            return {}
        items = ctypes.cast(buf, ctypes.POINTER(PDH_FMT_COUNTERVALUE_ITEM_W))
        for i in range(count.value):
            it = items[i]
            if it.szName:
                out[it.szName] = int(it.FmtValue.largeValue)
    finally:
        pdh.PdhCloseQuery(query)
    return out


_PID_RE = re.compile(r"pid_(\d+)_luid_(0x[0-9A-Fa-f]+_0x[0-9A-Fa-f]+)", re.I)
_LUID_RE = re.compile(r"luid_(0x[0-9A-Fa-f]+_0x[0-9A-Fa-f]+)", re.I)


def gpu_process_memory() -> dict[int, tuple[int, int]]:
    """pid -> (dedicated bytes, shared bytes) across all adapters."""
    ded = _pdh_counter_array(r"\GPU Process Memory(*)\Dedicated Usage")
    sh = _pdh_counter_array(r"\GPU Process Memory(*)\Shared Usage")
    out: dict[int, list[int]] = {}
    for src, idx in ((ded, 0), (sh, 1)):
        for inst, val in src.items():
            m = _PID_RE.search(inst)
            if m:
                out.setdefault(int(m.group(1)), [0, 0])[idx] += val
    return {pid: (v[0], v[1]) for pid, v in out.items()}


def _registry_gpu_totals() -> list[tuple[str, int]]:
    """[(adapter description, dedicated VRAM bytes)] from the display class registry key."""
    out: list[tuple[str, int]] = []
    if not IS_WINDOWS:
        return out
    base = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base) as k:
            i = 0
            while True:
                try:
                    sub = winreg.EnumKey(k, i)
                except OSError:
                    break
                i += 1
                if not sub.isdigit():
                    continue
                try:
                    with winreg.OpenKey(k, sub) as sk:
                        desc = winreg.QueryValueEx(sk, "DriverDesc")[0]
                        try:
                            size = winreg.QueryValueEx(sk, "HardwareInformation.qwMemorySize")[0]
                        except OSError:
                            raw = winreg.QueryValueEx(sk, "HardwareInformation.MemorySize")[0]
                            size = int.from_bytes(raw, "little") if isinstance(raw, bytes) else int(raw)
                        if int(size) > 0:
                            out.append((str(desc), int(size)))
                except OSError:
                    continue
    except OSError:
        pass
    return out


def _nvidia_smi() -> list[tuple[str, int, int]]:
    """[(name, used bytes, total bytes)] via nvidia-smi when present."""
    exe = "nvidia-smi"
    for cand in (os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "nvidia-smi.exe"),
                 r"C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe"):
        if os.path.exists(cand):
            exe = cand
            break
    try:
        res = subprocess.run([exe, "--query-gpu=name,memory.used,memory.total", "--format=csv,noheader,nounits"],
                             capture_output=True, text=True, timeout=6, creationflags=_CREATE_NO_WINDOW)
    except Exception:  # noqa: BLE001
        return []
    out = []
    for line in res.stdout.splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) == 3 and parts[1].isdigit() and parts[2].isdigit():
            out.append((parts[0], int(parts[1]) * 1024 * 1024, int(parts[2]) * 1024 * 1024))
    return out


_gpu_static: tuple[list[tuple[str, int]], list[tuple[str, int, int]]] | None = None


def _gpu_static_info() -> tuple[list[tuple[str, int]], list[tuple[str, int, int]]]:
    """(registry totals, nvidia-smi rows) - slow-ish, so read once per session."""
    global _gpu_static
    if _gpu_static is None:
        _gpu_static = (_registry_gpu_totals(), _nvidia_smi())
    return _gpu_static


def gpu_status() -> list[GpuInfo]:
    """Per-adapter VRAM use.  Performance counters first, nvidia-smi / registry for totals."""
    ded = _pdh_counter_array(r"\GPU Adapter Memory(*)\Dedicated Usage")
    sh = _pdh_counter_array(r"\GPU Adapter Memory(*)\Shared Usage")
    per_luid: dict[str, GpuInfo] = {}
    for inst, val in ded.items():
        m = _LUID_RE.search(inst)
        luid = m.group(1) if m else inst
        g = per_luid.setdefault(luid, GpuInfo(name="GPU", luid=luid))
        g.dedicated_used += val
    for inst, val in sh.items():
        m = _LUID_RE.search(inst)
        luid = m.group(1) if m else inst
        g = per_luid.setdefault(luid, GpuInfo(name="GPU", luid=luid))
        g.shared_used += val
    gpus = sorted(per_luid.values(), key=lambda g: -g.dedicated_used)
    totals, smi = _gpu_static_info()
    if not gpus:
        # counters unavailable: fall back to whatever nvidia-smi / registry tells us
        for name, used, total in smi:
            gpus.append(GpuInfo(name=name, dedicated_used=used, dedicated_total=total))
        if not gpus:
            for name, total in totals:
                gpus.append(GpuInfo(name=name, dedicated_total=total))
        return gpus
    # Windows also lists indirect/virtual display adapters; they own no VRAM, so drop the
    # extra LUIDs that show (almost) nothing before naming the real ones.
    real = [g for g in gpus if g.dedicated_used >= 1 << 20]
    gpus = real[:max(len(totals), 1)] if real else gpus[:1]
    # name + total: match by size order (biggest VRAM <-> most usage) - good enough for 1-2 GPUs
    named = sorted(totals, key=lambda t: -t[1])
    for g, (name, total) in zip(gpus, named):
        g.name, g.dedicated_total = name, total
    for g in gpus:
        for name, used, total in smi:
            if g.name == name:
                g.dedicated_total = total
                g.dedicated_used = max(g.dedicated_used, used)
    return gpus


def restart_graphics_driver() -> OpResult:
    """Send Win+Ctrl+Shift+B: Windows restarts the display driver, which drops every VRAM
    allocation apps have leaked.  The screen goes black for about a second and beeps."""
    key, title = "gpu_restart", "Restart graphics driver"
    if not IS_WINDOWS:
        return OpResult(key, title, False, "Only available on Windows.")
    VK_LWIN, VK_CONTROL, VK_SHIFT, VK_B = 0x5B, 0x11, 0x10, 0x42
    KEYEVENTF_KEYUP = 0x2

    def key_input(vk: int, up: bool) -> INPUT:
        inp = INPUT()
        inp.type = 1  # INPUT_KEYBOARD
        inp.u.ki = KEYBDINPUT(vk, 0, KEYEVENTF_KEYUP if up else 0, 0, None)
        return inp

    keys = [VK_LWIN, VK_CONTROL, VK_SHIFT, VK_B]
    seq = [key_input(k, False) for k in keys] + [key_input(k, True) for k in reversed(keys)]
    arr = (INPUT * len(seq))(*seq)
    before = gpu_status()
    sent = user32.SendInput(len(seq), arr, ctypes.sizeof(INPUT))
    if sent != len(seq):
        return OpResult(key, title, False, f"Could not send the key sequence: {_err()}")
    time.sleep(2.5)
    after = gpu_status()
    b = sum(g.dedicated_used for g in before)
    a = sum(g.dedicated_used for g in after)
    return OpResult(key, title, True, f"Driver restart requested. Dedicated VRAM in use: {_hs(b)} → {_hs(a)}.",
                    freed=max(0, b - a))


# --------------------------------------------------------------------------------------
# Non-file caches
# --------------------------------------------------------------------------------------

def _run(cmd: list[str], timeout: int = 60) -> tuple[int, str]:
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, creationflags=_CREATE_NO_WINDOW)
        return res.returncode, (res.stdout + res.stderr).strip()
    except FileNotFoundError:
        return 127, f"{cmd[0]} not found"
    except subprocess.TimeoutExpired:
        return 124, "timed out"
    except Exception as ex:  # noqa: BLE001
        return 1, str(ex)


def flush_dns_cache() -> OpResult:
    key, title = "dns", "Flush DNS resolver cache"
    if not IS_WINDOWS:
        return OpResult(key, title, False, "Only available on Windows.")
    try:
        if ctypes.windll.dnsapi.DnsFlushResolverCache():
            return OpResult(key, title, True, "DNS cache flushed (same as `ipconfig /flushdns`).")
    except OSError:
        pass
    rc, out = _run(["ipconfig", "/flushdns"])
    return OpResult(key, title, rc == 0, out[-200:] or "Done.")


def reset_store_cache() -> OpResult:
    """wsreset.exe clears the Microsoft Store cache; it opens the Store when done."""
    key, title = "store", "Reset Microsoft Store cache"
    if not IS_WINDOWS:
        return OpResult(key, title, False, "Only available on Windows.")
    exe = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "WSReset.exe")
    if not os.path.exists(exe):
        return OpResult(key, title, False, "WSReset.exe not found (Store not installed?).")
    try:
        subprocess.Popen([exe], creationflags=_CREATE_NO_WINDOW)
    except OSError as ex:
        return OpResult(key, title, False, str(ex))
    return OpResult(key, title, True, "Store cache reset started; the Store app opens when it is done.")


def rebuild_icon_cache() -> OpResult:
    key, title = "icons", "Refresh icon cache"
    if not IS_WINDOWS:
        return OpResult(key, title, False, "Only available on Windows.")
    rc, out = _run(["ie4uinit.exe", "-show"], timeout=30)
    if rc == 0:
        return OpResult(key, title, True, "Shell icon cache refreshed. Stale icons update on the next Explorer redraw.")
    return OpResult(key, title, False, out or f"exit code {rc}")


def clear_delivery_optimization() -> OpResult:
    """Windows Update peer-to-peer cache (Settings > Delivery Optimization)."""
    key, title = "do", "Clear Delivery Optimization cache"
    if not IS_WINDOWS:
        return OpResult(key, title, False, "Only available on Windows.")
    if not is_admin():
        return OpResult(key, title, False, "Needs Administrator rights.", needs_admin=True)
    rc, out = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                    "Delete-DeliveryOptimizationCache -Force -ErrorAction Stop"], timeout=120)
    if rc == 0:
        return OpResult(key, title, True, "Delivery Optimization cache deleted.")
    return OpResult(key, title, False, out[-300:] or f"exit code {rc}")


def clear_font_cache() -> OpResult:
    """Stop the font cache service, delete its files, start it again."""
    key, title = "fonts", "Rebuild font cache"
    if not IS_WINDOWS:
        return OpResult(key, title, False, "Only available on Windows.")
    if not is_admin():
        return OpResult(key, title, False, "Needs Administrator rights.", needs_admin=True)
    root = os.environ.get("SystemRoot", r"C:\Windows")
    targets = [os.path.join(root, "ServiceProfiles", "LocalService", "AppData", "Local", "FontCache"),
               os.path.join(root, "System32", "FNTCACHE.DAT")]
    details: list[str] = []
    freed = 0
    _run(["net", "stop", "FontCache", "/y"], timeout=60)
    _run(["net", "stop", "FontCache3.0.0.0", "/y"], timeout=60)
    time.sleep(1.0)
    for t in targets:
        if os.path.isfile(t):
            try:
                freed += os.path.getsize(t)
                os.remove(t)
                details.append(f"removed {t}")
            except OSError as ex:
                details.append(f"kept {t}: {ex}")
        elif os.path.isdir(t):
            for e in os.scandir(t):
                if e.is_file():
                    try:
                        freed += e.stat().st_size
                        os.remove(e.path)
                    except OSError as ex:
                        details.append(f"kept {e.path}: {ex}")
            details.append(f"emptied {t}")
    rc, out = _run(["net", "start", "FontCache"], timeout=60)
    ok = rc == 0 or "already been started" in out
    return OpResult(key, title, ok, "Font cache rebuilt; Windows recreates it in the background." if ok
                    else f"Font cache files removed but the service did not restart: {out[-200:]}",
                    freed=freed, details=details)


def clear_thumbnail_cache() -> OpResult:
    """Explorer's thumbcache_*.db / iconcache_*.db.  Files in use are skipped (Explorer holds them)."""
    key, title = "thumbs", "Clear thumbnail & icon cache files"
    if not IS_WINDOWS:
        return OpResult(key, title, False, "Only available on Windows.")
    d = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "Windows", "Explorer")
    freed = removed = skipped = 0
    try:
        for e in os.scandir(d):
            n = e.name.lower()
            if e.is_file() and (n.startswith("thumbcache_") or n.startswith("iconcache_")) and n.endswith(".db"):
                try:
                    size = e.stat().st_size
                    os.remove(e.path)
                    freed += size
                    removed += 1
                except OSError:
                    skipped += 1
    except OSError as ex:
        return OpResult(key, title, False, str(ex))
    msg = f"Removed {removed} cache database(s)."
    if skipped:
        msg += f" {skipped} are in use by Explorer; sign out and back in to release them."
    return OpResult(key, title, removed > 0 or skipped == 0, msg, freed=freed)


# --------------------------------------------------------------------------------------
# Catalogue used by the UI
# --------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Operation:
    key: str
    group: str                    # "ram" | "vram" | "cache"
    title: str
    description: str
    needs_admin: bool = False
    default_on: bool = True
    disruptive: str = ""          # short warning for things the user will notice


OPERATIONS: list[Operation] = [
    Operation("trim", "ram", "Trim working sets of all programs",
              "Every program hands unused RAM back to Windows. It is pulled back in on demand, so programs may "
              "feel sluggish for a moment afterwards. Frees the most 'In use' memory."),
    Operation("ws_all", "ram", "Empty working sets system-wide",
              "Same as above but done by the kernel, so it also reaches services and other users' programs.",
              needs_admin=True, default_on=False),
    Operation("standby", "ram", "Purge standby list (cached RAM)",
              "Drops file data Windows keeps in RAM 'just in case'. Turns 'Cached' into 'Free'. "
              "Games and tools like RAMMap do exactly this; disk reads are slower for a short while.",
              needs_admin=True),
    Operation("modified", "ram", "Flush modified page list",
              "Writes dirty pages to the pagefile so that RAM can be reused immediately.",
              needs_admin=True, default_on=False),
    Operation("filecache", "ram", "Flush system file cache",
              "Releases the kernel's own file cache working set.", needs_admin=True, default_on=False),
    Operation("clipboard", "ram", "Clear clipboard",
              "A copied screenshot or a big spreadsheet selection can occupy hundreds of MB.", default_on=False,
              disruptive="You lose what you last copied."),
    Operation("gpu_restart", "vram", "Restart the graphics driver (frees leaked VRAM)",
              "Presses Win+Ctrl+Shift+B for you. The screen blinks black for a second and Windows reloads "
              "the display driver, releasing VRAM that closed or crashed programs never gave back. "
              "Fullscreen games and GPU renders may need to be restarted.", default_on=False,
              disruptive="Screen goes black for ~1 s; running GPU jobs can be interrupted."),
    Operation("dns", "cache", "Flush DNS resolver cache",
              "Forgets cached website-to-address lookups (fixes 'site moved' problems)."),
    Operation("thumbs", "cache", "Clear thumbnail & icon cache files",
              "Deletes Explorer's thumbcache/iconcache databases; they are rebuilt as you browse folders."),
    Operation("icons", "cache", "Refresh shell icon cache",
              "Runs ie4uinit -show so stale or wrong icons are redrawn.", default_on=False),
    Operation("store", "cache", "Reset Microsoft Store cache",
              "Runs WSReset. Fixes Store downloads that hang. The Store app opens when done.", default_on=False,
              disruptive="Opens the Microsoft Store when finished."),
    Operation("do", "cache", "Clear Delivery Optimization cache",
              "Windows Update's peer-sharing cache (often several GB).", needs_admin=True, default_on=False),
    Operation("fonts", "cache", "Rebuild font cache",
              "Stops the Font Cache service, deletes its database and starts it again. Fixes garbled fonts.",
              needs_admin=True, default_on=False,
              disruptive="Text may flicker while the cache is rebuilt."),
]

_RUNNERS = {
    "trim": trim_working_sets,
    "ws_all": empty_all_working_sets,
    "standby": purge_standby_list,
    "modified": flush_modified_list,
    "filecache": flush_system_file_cache,
    "clipboard": clear_clipboard,
    "gpu_restart": restart_graphics_driver,
    "dns": flush_dns_cache,
    "thumbs": clear_thumbnail_cache,
    "icons": rebuild_icon_cache,
    "store": reset_store_cache,
    "do": clear_delivery_optimization,
    "fonts": clear_font_cache,
}


def run_operation(key: str) -> OpResult:
    fn = _RUNNERS.get(key)
    if fn is None:
        return OpResult(key, key, False, "Unknown operation.")
    try:
        return fn()
    except Exception as ex:  # noqa: BLE001 - never let one step kill the batch
        op = next((o for o in OPERATIONS if o.key == key), None)
        return OpResult(key, op.title if op else key, False, f"Unexpected error: {ex}")


def _hs(n: float) -> str:
    from .model import human_size
    return human_size(n)
