"""Knowledge base: what is junk, what is precious, and where Windows keeps its clutter.

Everything here is pure data + small functions so it is easy to audit and extend.
"""
from __future__ import annotations

import fnmatch
import os
import re
import time
from dataclasses import dataclass

from .model import Risk
from .settings import Settings
from .winutil import norm

# --------------------------------------------------------------------------------------
# Known clean-up locations
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Location:
    rel: str                 # relative path, may contain * wildcards per segment
    category: str
    risk: Risk
    reason: str
    min_age_days: int = 0    # only files older than this are reported
    file_glob: str = "*"     # only matching file names are reported
    note: str = ""


# Relative to each user profile folder (C:\Users\<name>)
PROFILE_LOCATIONS: list[Location] = [
    Location("AppData/Local/Temp", "temp", Risk.SAFE, "User temp folder", 1),
    Location("AppData/Local/Microsoft/Windows/INetCache", "cache", Risk.SAFE, "Internet cache"),
    Location("AppData/Local/Microsoft/Windows/Temporary Internet Files", "cache", Risk.SAFE, "Internet cache (legacy)"),
    Location("AppData/Local/Microsoft/Windows/Explorer", "cache", Risk.SAFE,
             "Explorer thumbnail / icon cache (rebuilt automatically)", 0, "*cache_*.db"),
    Location("AppData/Local/Microsoft/Windows/WER", "debug", Risk.SAFE, "Windows Error Reporting files"),
    Location("AppData/Local/CrashDumps", "debug", Risk.SAFE, "Application crash dumps"),
    Location("AppData/Local/Microsoft/Windows/Caches", "cache", Risk.SAFE, "Shell property / search cache (rebuilt automatically)"),
    Location("AppData/Local/Microsoft/Windows/AppCache", "cache", Risk.SAFE, "Windows app cache"),
    Location("AppData/Local/Microsoft/Windows/SchCache", "cache", Risk.SAFE, "Active Directory schema cache"),
    Location("AppData/Local/Microsoft/Windows/ActionCenterCache", "cache", Risk.SAFE, "Action Center image cache"),
    Location("AppData/Local/Microsoft/Windows/Notifications/wpnidm", "cache", Risk.SAFE, "Notification image cache"),
    Location("AppData/Local/Microsoft/Windows/Explorer/ThumbCacheToDelete", "cache", Risk.SAFE, "Thumbnail cache scheduled for deletion"),
    Location("AppData/Local/Microsoft/Windows/PowerShell/CommandAnalysis", "cache", Risk.SAFE, "PowerShell command analysis cache"),
    Location("AppData/Local/IconCache.db", "cache", Risk.SAFE, "Legacy icon cache (rebuilt automatically)"),
    Location("AppData/Local/Microsoft/Windows/WebCache", "cache", Risk.REVIEW,
             "Legacy IE / WebView cache database", note="Locked while you are signed in; sign out first."),
    Location("AppData/Local/Packages/*/LocalCache", "cache", Risk.REVIEW, "Store app local cache (a few apps keep settings here)"),
    Location("AppData/Local/NVIDIA/ComputeCache", "cache", Risk.SAFE, "NVIDIA CUDA compute cache"),
    Location("AppData/Local/NVIDIA Corporation/NV_Cache", "cache", Risk.SAFE, "NVIDIA shader cache"),
    Location("AppData/Local/NVIDIA Corporation/NvTelemetry", "logs", Risk.SAFE, "NVIDIA telemetry logs", 7),
    # crash reporters (Crashpad / Breakpad uploads and pending reports)
    Location("AppData/Local/Google/Chrome/User Data/Crashpad/reports", "debug", Risk.SAFE, "Chrome crash reports"),
    Location("AppData/Local/Microsoft/Edge/User Data/Crashpad/reports", "debug", Risk.SAFE, "Edge crash reports"),
    Location("AppData/Local/BraveSoftware/Brave-Browser/User Data/Crashpad/reports", "debug", Risk.SAFE, "Brave crash reports"),
    Location("AppData/Roaming/Mozilla/Firefox/Crash Reports", "debug", Risk.SAFE, "Firefox crash reports"),
    Location("AppData/Roaming/discord/Crashpad/reports", "debug", Risk.SAFE, "Discord crash reports"),
    Location("AppData/Roaming/Code/Crashpad/reports", "debug", Risk.SAFE, "VS Code crash reports"),
    Location("AppData/Roaming/Slack/Crashpad/reports", "debug", Risk.SAFE, "Slack crash reports"),
    Location("AppData/Local/Microsoft/Teams/Crashpad/reports", "debug", Risk.SAFE, "Teams crash reports"),
    Location("AppData/Local/Packages/*/LocalState/Crashpad/reports", "debug", Risk.SAFE, "Store app crash reports"),
    Location("AppData/Local/Microsoft/Windows/Wpr", "debug", Risk.SAFE, "Windows Performance Recorder traces"),
    Location("AppData/Local/Diagnostics", "debug", Risk.SAFE, "Windows troubleshooter diagnostic packages", 7),
    Location("AppData/Local/ElevatedDiagnostics", "debug", Risk.SAFE, "Windows troubleshooter diagnostic packages", 7),
    Location("AppData/Local/Microsoft/Windows/PowerShell/StartupProfileData-*", "cache", Risk.SAFE, "PowerShell startup cache"),
    Location("AppData/Local/D3DSCache", "cache", Risk.SAFE, "DirectX shader cache"),
    Location("AppData/Local/NVIDIA/DXCache", "cache", Risk.SAFE, "NVIDIA shader cache"),
    Location("AppData/Local/NVIDIA/GLCache", "cache", Risk.SAFE, "NVIDIA shader cache"),
    Location("AppData/LocalLow/NVIDIA/PerDriverVersion/DXCache", "cache", Risk.SAFE, "NVIDIA shader cache"),
    Location("AppData/Local/AMD/DxCache", "cache", Risk.SAFE, "AMD shader cache"),
    Location("AppData/Local/Intel/ShaderCache", "cache", Risk.SAFE, "Intel shader cache"),
    Location("AppData/Local/Microsoft/Terminal Server Client/Cache", "cache", Risk.SAFE, "Remote Desktop bitmap cache"),
    Location("AppData/Local/Packages/*/AC/INetCache", "cache", Risk.SAFE, "Store app internet cache"),
    Location("AppData/Local/Packages/*/AC/Temp", "temp", Risk.SAFE, "Store app temp files", 1),
    Location("AppData/Local/Packages/*/TempState", "temp", Risk.SAFE, "Store app temp state", 1),
    # browsers
    Location("AppData/Local/Google/Chrome/User Data/*/Cache", "cache", Risk.SAFE, "Chrome cache"),
    Location("AppData/Local/Google/Chrome/User Data/*/Code Cache", "cache", Risk.SAFE, "Chrome code cache"),
    Location("AppData/Local/Google/Chrome/User Data/*/GPUCache", "cache", Risk.SAFE, "Chrome GPU cache"),
    Location("AppData/Local/Google/Chrome/User Data/*/Service Worker/CacheStorage", "cache", Risk.SAFE, "Chrome service-worker cache"),
    Location("AppData/Local/Microsoft/Edge/User Data/*/Cache", "cache", Risk.SAFE, "Edge cache"),
    Location("AppData/Local/Microsoft/Edge/User Data/*/Code Cache", "cache", Risk.SAFE, "Edge code cache"),
    Location("AppData/Local/Microsoft/Edge/User Data/*/GPUCache", "cache", Risk.SAFE, "Edge GPU cache"),
    Location("AppData/Local/Microsoft/Edge/User Data/*/Service Worker/CacheStorage", "cache", Risk.SAFE, "Edge service-worker cache"),
    Location("AppData/Local/BraveSoftware/Brave-Browser/User Data/*/Cache", "cache", Risk.SAFE, "Brave cache"),
    Location("AppData/Local/BraveSoftware/Brave-Browser/User Data/*/Code Cache", "cache", Risk.SAFE, "Brave code cache"),
    Location("AppData/Local/Vivaldi/User Data/*/Cache", "cache", Risk.SAFE, "Vivaldi cache"),
    Location("AppData/Local/Opera Software/*/Cache", "cache", Risk.SAFE, "Opera cache"),
    Location("AppData/Local/Mozilla/Firefox/Profiles/*/cache2", "cache", Risk.SAFE, "Firefox cache"),
    Location("AppData/Local/Mozilla/Firefox/Profiles/*/startupCache", "cache", Risk.SAFE, "Firefox startup cache"),
    # chat / electron apps
    Location("AppData/Roaming/discord/Cache", "cache", Risk.SAFE, "Discord cache"),
    Location("AppData/Roaming/discord/Code Cache", "cache", Risk.SAFE, "Discord code cache"),
    Location("AppData/Roaming/discord/GPUCache", "cache", Risk.SAFE, "Discord GPU cache"),
    Location("AppData/Roaming/Slack/Cache", "cache", Risk.SAFE, "Slack cache"),
    Location("AppData/Roaming/Slack/Code Cache", "cache", Risk.SAFE, "Slack code cache"),
    Location("AppData/Local/Packages/MSTeams_*/LocalCache/Microsoft/MSTeams/EBWebView/*/Cache", "cache", Risk.SAFE, "Teams cache"),
    Location("AppData/Roaming/Spotify/Data", "cache", Risk.REVIEW, "Spotify streaming cache (offline songs live elsewhere)"),
    Location("AppData/Roaming/Zoom/data/*/Cache", "cache", Risk.SAFE, "Zoom cache"),
    Location("AppData/Local/Steam/htmlcache", "cache", Risk.SAFE, "Steam web cache"),
    # developer tooling
    Location("AppData/Local/pip/cache", "cache", Risk.SAFE, "pip download cache"),
    Location("AppData/Local/npm-cache", "cache", Risk.SAFE, "npm cache"),
    Location("AppData/Roaming/npm-cache", "cache", Risk.SAFE, "npm cache"),
    Location("AppData/Local/Yarn/Cache", "cache", Risk.SAFE, "Yarn cache"),
    Location("AppData/Local/uv/cache", "cache", Risk.SAFE, "uv cache"),
    Location("AppData/Local/NuGet/v3-cache", "cache", Risk.SAFE, "NuGet HTTP cache"),
    Location("AppData/Local/Microsoft/VisualStudio/*/ComponentModelCache", "cache", Risk.SAFE, "Visual Studio component cache"),
    Location("AppData/Local/JetBrains/*/caches", "cache", Risk.REVIEW, "JetBrains IDE index caches (rebuilt on next open)"),
    Location("AppData/Local/JetBrains/*/log", "logs", Risk.SAFE, "JetBrains IDE logs", 14),
    Location("AppData/Roaming/Code/Cache", "cache", Risk.SAFE, "VS Code cache"),
    Location("AppData/Roaming/Code/CachedData", "cache", Risk.SAFE, "VS Code cached data"),
    Location("AppData/Roaming/Code/CachedExtensionVSIXs", "cache", Risk.SAFE, "VS Code extension installers"),
    Location("AppData/Roaming/Code/logs", "logs", Risk.SAFE, "VS Code logs", 7),
    Location("AppData/Roaming/Code/User/workspaceStorage", "cache", Risk.REVIEW, "VS Code per-workspace state (loses unsaved editor state)"),
    Location(".gradle/caches", "cache", Risk.REVIEW, "Gradle dependency cache (re-downloaded on next build)"),
    Location(".m2/repository", "cache", Risk.REVIEW, "Maven local repository (re-downloaded on next build)"),
    Location(".nuget/packages", "cache", Risk.REVIEW, "NuGet package cache (restored on next build)"),
    Location(".cargo/registry", "cache", Risk.REVIEW, "Cargo registry cache (re-downloaded on next build)"),
    Location("go/pkg/mod/cache", "cache", Risk.REVIEW, "Go module cache"),
    Location(".cache/huggingface", "large", Risk.REVIEW, "Hugging Face model cache (re-downloaded when a model is used)"),
    Location(".cache/torch", "large", Risk.REVIEW, "PyTorch model cache"),
    Location(".cache/pip", "cache", Risk.SAFE, "pip cache"),
    Location("Anaconda3/pkgs", "cache", Risk.REVIEW, "Conda package cache (same as `conda clean --all`)"),
    Location("anaconda3/pkgs", "cache", Risk.REVIEW, "Conda package cache (same as `conda clean --all`)"),
    Location("miniconda3/pkgs", "cache", Risk.REVIEW, "Conda package cache (same as `conda clean --all`)"),
    Location(".conda/pkgs", "cache", Risk.REVIEW, "Conda package cache (same as `conda clean --all`)"),
    Location("AppData/Local/Docker/wsl", "large", Risk.REVIEW, "Docker Desktop virtual disk (use `docker system prune`, do not delete the file)"),
    # creative apps
    Location("AppData/Roaming/Adobe/Common/Media Cache Files", "cache", Risk.SAFE, "Adobe media cache (Premiere/After Effects rebuild it)"),
    Location("AppData/Roaming/Adobe/Common/Media Cache", "cache", Risk.SAFE, "Adobe media cache database"),
    Location("AppData/Roaming/Adobe/Common/Peak Files", "cache", Risk.SAFE, "Adobe audio peak files"),
    Location("AppData/Local/Adobe/*/Cache", "cache", Risk.SAFE, "Adobe app cache"),
    Location("AppData/Local/Blender Foundation/Blender/*/cache", "cache", Risk.SAFE, "Blender cache"),
    Location("AppData/Local/Microsoft/OneDrive/logs", "logs", Risk.SAFE, "OneDrive logs", 7),
    Location("AppData/Local/Microsoft/Office/16.0/OfficeFileCache", "cache", Risk.REVIEW, "Office document cache (unsynced changes could be lost)"),
]

# Relative to the drive root
SYSTEM_LOCATIONS: list[Location] = [
    Location("Windows/Temp", "temp", Risk.SAFE, "Windows temp folder", 1),
    Location("Windows/Logs", "logs", Risk.SAFE, "Windows component logs", 14),
    Location("Windows/SystemTemp", "temp", Risk.SAFE, "Windows system temp folder", 1),
    Location("Windows/ServiceProfiles/*/AppData/Local/Temp", "temp", Risk.SAFE, "Service account temp folder", 1),
    Location("Windows/Minidump", "debug", Risk.SAFE, "Kernel minidumps (blue-screen crash files)"),
    Location("Windows/LiveKernelReports", "debug", Risk.SAFE, "Live kernel reports"),
    Location("Windows/MEMORY.DMP", "debug", Risk.SAFE, "Full kernel memory dump"),
    Location("Windows/debug", "debug", Risk.SAFE, "Windows debug logs (network setup, MRT, WIA)", 14),
    Location("Windows/System32/LogFiles", "debug", Risk.SAFE, "System component log files", 30),
    Location("Windows/Panther", "debug", Risk.REVIEW, "Windows setup / upgrade logs", 30,
             note="Useful when diagnosing a failed upgrade; otherwise safe."),
    Location("Windows/inf", "debug", Risk.REVIEW, "Driver installation logs (setupapi)", 30, "*.log",
             note="setupapi.dev.log helps diagnose driver problems; delete only if you are not chasing one."),
    Location("Windows/SoftwareDistribution/DataStore/Logs", "logs", Risk.SAFE, "Windows Update database logs", 14),
    Location("Windows/Prefetch", "cache", Risk.REVIEW, "Prefetch data (speeds up program launches)", 30,
             note="Windows rebuilds it, but programs start a little slower for a few days. Rarely worth it."),
    Location("Windows/ServiceProfiles/NetworkService/AppData/Local/Microsoft/Windows/DeliveryOptimization/Cache",
             "cache", Risk.REVIEW, "Delivery Optimization (Windows Update peer cache)",
             note="Better cleared from Memory & caches, which asks the service to do it cleanly."),
    Location("Windows/System32/config/systemprofile/AppData/Local/Microsoft/Windows/INetCache", "cache", Risk.SAFE,
             "System profile internet cache"),
    Location("Windows/Downloaded Program Files", "cache", Risk.SAFE, "Legacy ActiveX downloads"),
    Location("Windows/SoftwareDistribution/Download", "windows", Risk.REVIEW,
             "Windows Update downloads (safe once updates are installed)", 7,
             note="Stop the Windows Update service first if deletion fails."),
    Location("Windows.old", "windows", Risk.REVIEW, "Previous Windows installation", 0,
             note="Deleting removes the ability to roll back the last upgrade. Storage Sense removes it after 10 days anyway."),
    Location("$Windows.~BT", "windows", Risk.REVIEW, "Windows upgrade working files"),
    Location("$Windows.~WS", "windows", Risk.REVIEW, "Windows upgrade working files"),
    Location("ProgramData/Microsoft/Windows/WER", "debug", Risk.SAFE, "Windows Error Reporting (all users)"),
    Location("ProgramData/NVIDIA Corporation/Downloader", "installers", Risk.REVIEW, "GeForce driver downloads already installed"),
    Location("ProgramData/NVIDIA Corporation/NV_Cache", "cache", Risk.SAFE, "NVIDIA shader cache"),
    Location("ProgramData/Microsoft/Diagnosis/ETLLogs", "debug", Risk.SAFE, "Diagnostics traces", 7),
    Location("ProgramData/Microsoft/Windows/WDF", "debug", Risk.SAFE, "Driver framework dumps"),
    Location("ProgramData/Microsoft/Windows Defender/Scans/History/CacheManager", "cache", Risk.SAFE, "Defender scan cache"),
    Location("ProgramData/NVIDIA Corporation/NvTelemetry", "logs", Risk.SAFE, "NVIDIA telemetry logs", 7),
    Location("ProgramData/NVIDIA Corporation/CrashDumps", "debug", Risk.SAFE, "NVIDIA driver crash dumps"),
    Location("ProgramData/Microsoft/Windows/Power/Reports", "debug", Risk.SAFE, "Power / sleep diagnostic reports", 14),
    Location("Intel/Logs", "logs", Risk.SAFE, "Intel driver logs", 14),
    Location("AMD/*/Logs", "logs", Risk.SAFE, "AMD driver logs", 14),
]

# --------------------------------------------------------------------------------------
# Model stores and engines: listed so you can see what they cost, never deletable.
#
# These hold gigabytes of downloaded model weights.  They *are* re-downloadable, which is
# exactly why a heuristic would happily suggest them - and why re-downloading them costs
# hours.  SmartCleaner reports them with Risk.KEEP: the GUI cannot select them and the
# headless CLI refuses them even with --max-risk review.
# --------------------------------------------------------------------------------------

# Relative to each user profile folder.
KEEP_PROFILE_LOCATIONS: list[Location] = [
    Location(".ollama/models", "models", Risk.KEEP, "Ollama model store (blobs + manifests)",
             note="Remove models with `ollama rm <model>`, never by deleting files."),
    Location(".lmstudio/models", "models", Risk.KEEP, "LM Studio model store",
             note="Remove models from LM Studio's My Models tab."),
    Location(".cache/lm-studio/models", "models", Risk.KEEP, "LM Studio model cache"),
    Location(".cache/lm_studio/models", "models", Risk.KEEP, "LM Studio model cache"),
    Location("AppData/Local/LM-Studio/models", "models", Risk.KEEP, "LM Studio model store"),
    Location(".buzzcode/engine", "models", Risk.KEEP, "BuzzCode engine (llama-server + weights)",
             note="Managed by `buzzcode engine`; deleting it breaks the coding engine."),
    Location(".cache/buzzcode/engine", "models", Risk.KEEP, "BuzzCode engine cache"),
]

# Relative to the drive root (B:\models, C:\models, ...).
KEEP_SYSTEM_LOCATIONS: list[Location] = [
    Location("models", "models", Risk.KEEP, "Local model store",
             note="Shared weights directory (B:\\models). Move models out by hand if you need the space."),
    Location("ProgramData/lmstudio/models", "models", Risk.KEEP, "LM Studio model store (all users)"),
]

# Environment variables that relocate a model store.
KEEP_ENV_VARS = ("OLLAMA_MODELS", "LMSTUDIO_MODELS_DIR", "BUZZCODE_ENGINE_DIR", "SMARTCLEANER_KEEP_DIRS")


# Big system files we report but never touch, with advice.
SYSTEM_FILES_INFO = {
    "hiberfil.sys": "Hibernation file. Reclaim with `powercfg /h off` (disables Fast Startup & hibernate).",
    "pagefile.sys": "Virtual memory paging file. Managed by Windows; do not delete.",
    "swapfile.sys": "Store-app swap file. Managed by Windows; do not delete.",
}

# --------------------------------------------------------------------------------------
# Protected areas (never walked by generic rules, never deletable)
# --------------------------------------------------------------------------------------

PROTECTED_ROOT_DIRS = {
    "windows", "program files", "program files (x86)", "programdata", "system volume information",
    "$recycle.bin", "recovery", "boot", "efi", "perflogs", "config.msi", "msocache",
    "documents and settings", "$winreagent", "onedrivetemp", "windowsapps", "program files (arm)",
}
PROTECTED_PROFILE_SUBDIRS = {
    "appdata/roaming/microsoft/credentials", "appdata/roaming/microsoft/protect",
    "appdata/roaming/microsoft/crypto", "appdata/roaming/microsoft/vault",
    "appdata/roaming/microsoft/systemcertificates", "appdata/local/microsoft/credentials",
    "appdata/local/microsoft/windowsapps", "appdata/local/packages/microsoft.windows.shellexperiencehost_cw5n1h2txyewy",
}
PROTECTED_DIR_NAMES = {".git", ".svn", ".hg", ".bzr", "$recycle.bin", "system volume information"}

# Files whose duplicates / age we handle extra carefully.
IMPORTANT_EXTS = {
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".odt", ".ods", ".one",
    ".psd", ".psb", ".ai", ".indd", ".xd", ".fig", ".sketch", ".veg", ".blend", ".prproj",
    ".aep", ".drp", ".flp", ".als", ".pst", ".ost", ".kdbx", ".key", ".pem", ".p12", ".pfx",
    ".wallet", ".sqlite", ".db", ".accdb", ".mdb", ".ppk", ".gpg", ".asc", ".vdi", ".vhd",
    ".vhdx", ".vmdk", ".qcow2", ".ova",
}

CLOUD_DIR_PATTERNS = ("onedrive", "dropbox", "google drive", "creative cloud files", "iclouddrive",
                      "box", "mega", "pcloud", "sync", "nextcloud")

TEMP_EXTS = {".tmp", ".temp", ".crdownload", ".part", ".partial", ".download", ".!ut", ".bc!", ".chk", ".gid", ".~tmp"}
DUMP_EXTS = {".dmp", ".mdmp", ".hdmp"}
LOG_EXTS = {".log", ".etl", ".trace"}
BACKUP_EXTS = {".bak", ".old", ".orig", ".backup", ".bkp", ".bk", ".prev"}
INSTALLER_EXTS = {".exe", ".msi", ".msix", ".msixbundle", ".appx", ".appxbundle", ".msp"}
ARCHIVE_EXTS = {".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".xz", ".bz2", ".iso", ".img", ".dmg"}
LOG_ROTATED_RE = re.compile(r"\.log[._-]?\d+$|\.log\.(old|bak|gz|zip)$", re.I)
COPY_NAME_RE = re.compile(r"(\s\(\d+\)|\s-\s?copy(\s\(\d+\))?|\scopy\s?\d*|^copy of\s)", re.I)

LARGE_FILE_HINTS: list[tuple[set[str], str]] = [
    ({".iso", ".img"}, "Disc image. Safe to delete if you still have the source or the installer already ran."),
    ({".vdi", ".vhd", ".vhdx", ".vmdk", ".qcow2", ".ova", ".vbox-prev"}, "Virtual machine disk. Delete only if the VM is gone."),
    ({".safetensors", ".ckpt", ".pt", ".pth", ".gguf", ".bin", ".onnx"}, "AI model weights. Re-downloadable, but usually slow to fetch."),
    ({".mp4", ".mkv", ".mov", ".avi", ".wmv", ".m4v", ".mts", ".webm"}, "Video file."),
    ({".zip", ".7z", ".rar", ".tar", ".gz", ".tgz"}, "Archive. Check whether you already extracted it."),
    ({".pst", ".ost"}, "Outlook mailbox. Do NOT delete unless the account is gone."),
    ({".psd", ".psb", ".blend", ".veg", ".prproj", ".aep", ".ai", ".indd"}, "Project file from a creative app."),
    ({".wim", ".esd", ".swm"}, "Windows image. Leftover from an installer or backup."),
    ({".exe", ".msi"}, "Installer. If the program is installed, this can go."),
    ({".bak", ".old"}, "Backup copy."),
    ({".sql", ".dump", ".mdf", ".ldf", ".ibd"}, "Database file or dump."),
]

# Developer leftovers: dir name -> (risk, reason, sibling markers required (any) or None)
DEV_DIRS: dict[str, tuple[Risk, str, tuple[str, ...] | None]] = {
    "__pycache__": (Risk.SAFE, "Python bytecode cache", None),
    ".pytest_cache": (Risk.SAFE, "pytest cache", None),
    ".mypy_cache": (Risk.SAFE, "mypy cache", None),
    ".ruff_cache": (Risk.SAFE, "ruff cache", None),
    ".tox": (Risk.REVIEW, "tox environments", None),
    ".nox": (Risk.REVIEW, "nox environments", None),
    "node_modules": (Risk.REVIEW, "npm dependencies (`npm install` restores them)", ("package.json",)),
    ".next": (Risk.REVIEW, "Next.js build output", ("package.json",)),
    ".nuxt": (Risk.REVIEW, "Nuxt build output", ("package.json",)),
    ".parcel-cache": (Risk.SAFE, "Parcel cache", None),
    ".turbo": (Risk.SAFE, "Turborepo cache", None),
    ".angular": (Risk.SAFE, "Angular CLI cache", ("angular.json",)),
    ".gradle": (Risk.REVIEW, "Gradle project cache", ("build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts")),
    "target": (Risk.REVIEW, "Build output (Maven/Cargo)", ("pom.xml", "Cargo.toml")),
    "build": (Risk.REVIEW, "Build output", ("build.gradle", "build.gradle.kts", "CMakeLists.txt", "setup.py", "pyproject.toml", "package.json")),
    "dist": (Risk.REVIEW, "Distribution build output", ("package.json", "setup.py", "pyproject.toml")),
    "out": (Risk.REVIEW, "Build output", ("package.json", "tsconfig.json")),
    "obj": (Risk.SAFE, ".NET intermediate build output", ("*.csproj", "*.vbproj", "*.fsproj", "*.sln")),
    "bin": (Risk.REVIEW, ".NET build output", ("*.csproj", "*.vbproj", "*.fsproj")),
    ".venv": (Risk.REVIEW, "Python virtual environment (`pip install -r requirements.txt` restores it)", ("pyvenv.cfg@",)),
    "venv": (Risk.REVIEW, "Python virtual environment", ("pyvenv.cfg@",)),
    "env": (Risk.REVIEW, "Python virtual environment", ("pyvenv.cfg@",)),
    ".ipynb_checkpoints": (Risk.SAFE, "Jupyter checkpoints", None),
    ".terraform": (Risk.REVIEW, "Terraform providers (`terraform init` restores them)", ("*.tf",)),
    "Pods": (Risk.REVIEW, "CocoaPods dependencies", ("Podfile",)),
    ".dart_tool": (Risk.SAFE, "Dart/Flutter tool cache", ("pubspec.yaml",)),
}

# Standard user folders that must never be reported as "empty folder"
STANDARD_USER_DIRS = {"desktop", "documents", "downloads", "pictures", "music", "videos", "favorites",
                      "links", "contacts", "searches", "saved games", "3d objects", "onedrive"}


# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------

def profile_dirs(root: str) -> list[str]:
    """User profile folders under `root` (plus this user's own home when it lives there)."""
    users = os.path.join(root, "Users")
    profiles: list[str] = []
    if os.path.isdir(users):
        try:
            for e in os.scandir(users):
                if e.is_dir(follow_symlinks=False) and e.name.lower() not in (
                        "default", "default user", "all users", "public"):
                    profiles.append(e.path)
        except OSError:
            pass
    # A user profile may also live on another drive, or root itself may be a profile/subfolder.
    home = os.path.expanduser("~")
    if norm(home).startswith(norm(root)) and home not in profiles:
        profiles.append(home)
    return profiles


def keep_locations(root: str) -> list[tuple[str, Location]]:
    """Model stores / engines under `root`: listed, never deleted (Risk.KEEP)."""
    out: list[tuple[str, Location]] = []
    seen: set[str] = set()

    def add(path: str, loc: Location) -> None:
        n = norm(path)
        if n not in seen and os.path.isdir(path):
            seen.add(n)
            out.append((path, loc))

    for loc in KEEP_SYSTEM_LOCATIONS:
        for p in _glob_segments(root, loc.rel):
            add(p, loc)
    for prof in profile_dirs(root):
        for loc in KEEP_PROFILE_LOCATIONS:
            for p in _glob_segments(prof, loc.rel):
                add(p, loc)
    for var in KEEP_ENV_VARS:
        for raw in (os.environ.get(var) or "").split(os.pathsep):
            raw = raw.strip().strip('"')
            if raw:
                add(os.path.abspath(raw), Location(raw, "models", Risk.KEEP,
                                                   f"Model store from %{var}%"))
    nroot = norm(root)
    return [(p, l) for p, l in out if norm(p).startswith(nroot)]


def is_model_store(path: str) -> bool:
    """True when `path` is inside a model store / engine directory (never deletable).

    Answers from the shape of the path, so it works without a scan: this is the
    cleaner's last line of defence, below the Risk.KEEP findings the scanner reports.
    """
    n = norm(path).replace(os.sep, "/").lower().rstrip("/")
    for var in KEEP_ENV_VARS:
        for raw in (os.environ.get(var) or "").split(os.pathsep):
            raw = raw.strip().strip('"')
            if raw:
                base = norm(raw).replace(os.sep, "/").lower().rstrip("/")
                if base and (n == base or n.startswith(base + "/")):
                    return True
    for loc in KEEP_PROFILE_LOCATIONS:
        tail = loc.rel.replace("\\", "/").strip("/").lower()
        if n.endswith("/" + tail) or ("/" + tail + "/") in n + "/":
            return True
    drive, rest = os.path.splitdrive(n)
    rest = rest.strip("/")
    for loc in KEEP_SYSTEM_LOCATIONS:
        tail = loc.rel.replace("\\", "/").strip("/").lower()
        if rest == tail or rest.startswith(tail + "/"):
            return True
    return False


def expand_locations(root: str) -> list[tuple[str, Location]]:
    """Resolve Location templates to concrete existing directories/files under root."""
    out: list[tuple[str, Location]] = []
    seen: set[str] = set()

    def add(path: str, loc: Location) -> None:
        n = norm(path)
        if n not in seen and os.path.exists(path):
            seen.add(n)
            out.append((path, loc))

    for loc in SYSTEM_LOCATIONS:
        for p in _glob_segments(root, loc.rel):
            add(p, loc)
    for prof in profile_dirs(root):
        for loc in PROFILE_LOCATIONS:
            for p in _glob_segments(prof, loc.rel):
                add(p, loc)
    # keep only things inside the scan root
    nroot = norm(root)
    return [(p, l) for p, l in out if norm(p).startswith(nroot)]


def _glob_segments(base: str, rel: str) -> list[str]:
    parts = rel.replace("\\", "/").split("/")
    cur = [base]
    for part in parts:
        nxt: list[str] = []
        if "*" in part or "?" in part:
            for c in cur:
                try:
                    for e in os.scandir(c):
                        if fnmatch.fnmatch(e.name.lower(), part.lower()):
                            nxt.append(e.path)
                except OSError:
                    pass
        else:
            for c in cur:
                p = os.path.join(c, part)
                if os.path.exists(p):
                    nxt.append(p)
        cur = nxt
        if not cur:
            break
    return cur


def is_cloud_path(path: str) -> bool:
    parts = norm(path).split(os.sep)
    for seg in parts[:-1]:
        s = seg.lower()
        for pat in CLOUD_DIR_PATTERNS:
            if s == pat or s.startswith(pat + " ") or s.startswith(pat + "-") or (pat == "onedrive" and s.startswith("onedrive")):
                return True
    return False


def in_appdata(path: str) -> bool:
    return f"{os.sep}appdata{os.sep}" in norm(path).lower()


# Folder names that mean "an application owns everything below here".
APP_OWNED_SEGMENTS = {
    "appdata", "anaconda3", "miniconda3", "site-packages", "node_modules", "program files",
    "program files (x86)", "programs", "windowsapps", "steamapps", "epic games", "riot games",
    "jetbrains", "microsoft", "google", "mozilla", ".git",
}


def is_app_owned(dir_path: str) -> bool:
    """True when files here belong to an installed program rather than to the user.

    Only temp/log/dump rules apply in such places; duplicates, backups, old downloads,
    dev leftovers and empty folders are ignored because the app expects them to be there.
    """
    parts = norm(dir_path).lower().strip(os.sep).split(os.sep)
    for i, seg in enumerate(parts):
        if seg in APP_OWNED_SEGMENTS:
            return True
        # profile-level dot folders (C:\Users\me\.vscode, ~/.local, ~/.lmstudio ...)
        if i >= 2 and parts[i - 2] == "users" and seg.startswith("."):
            return True
    return False


def is_leveldb_dir(entry_names: set[str]) -> bool:
    """LevelDB/RocksDB stores keep live data in *.log files - never treat those as logs."""
    return "current" in entry_names and ("lock" in entry_names or any(n.startswith("manifest-") for n in entry_names))


def is_downloads_top(path: str) -> bool:
    """True if the file sits directly (<=1 level deep) in a Downloads folder."""
    parts = norm(path).lower().split(os.sep)
    if "downloads" not in parts:
        return False
    i = parts.index("downloads")
    return len(parts) - 1 - i <= 2


def large_file_hint(ext: str) -> str:
    ext = ext.lower()
    for exts, hint in LARGE_FILE_HINTS:
        if ext in exts:
            return hint
    return ""


def dev_dir_matches(name: str, parent: str) -> tuple[Risk, str] | None:
    """Return (risk, reason) if `parent/name` looks like a developer leftover directory."""
    spec = DEV_DIRS.get(name)
    if spec is None:
        return None
    risk, reason, markers = spec
    if markers is None:
        return risk, reason
    for m in markers:
        if m.endswith("@"):  # marker must exist *inside* the dir
            if os.path.exists(os.path.join(parent, name, m[:-1])):
                return risk, reason
        elif "*" in m:
            try:
                for e in os.scandir(parent):
                    if fnmatch.fnmatch(e.name.lower(), m.lower()):
                        return risk, reason
            except OSError:
                return None
        elif os.path.exists(os.path.join(parent, m)):
            return risk, reason
    return None


def project_last_activity(parent: str, skip_name: str) -> float:
    """Newest modification time among the project's own top-level entries (shallow)."""
    newest = 0.0
    try:
        for e in os.scandir(parent):
            if e.name == skip_name or e.name in DEV_DIRS:
                continue
            try:
                newest = max(newest, e.stat(follow_symlinks=False).st_mtime)
            except OSError:
                pass
    except OSError:
        pass
    return newest


def days_old(mtime: float) -> float:
    return (time.time() - mtime) / 86400.0


def keeper_score(path: str, mtime: float, oldest_mtime: float) -> tuple:
    """Higher = better candidate to KEEP in a duplicate group."""
    low = norm(path).lower()
    parts = low.split(os.sep)
    name = os.path.splitext(parts[-1])[0]
    score = 0
    if "downloads" not in parts and "desktop" not in parts and "temp" not in parts and "tmp" not in parts:
        score += 3
    if not COPY_NAME_RE.search(name):
        score += 2
    if any(p in parts for p in ("documents", "pictures", "music", "videos", "projects", "work")):
        score += 1
    if is_cloud_path(path):
        score += 1
    if abs(mtime - oldest_mtime) < 2:
        score += 1
    # prefer shorter, cleaner paths as final tie-break
    return (score, -len(parts), -len(low))


def is_excluded(path: str, settings: Settings) -> bool:
    n = norm(path)
    for ex in settings.excluded_paths:
        if ex and n.startswith(norm(ex)):
            return True
    return False
