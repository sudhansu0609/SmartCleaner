from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field, fields

from . import APP_NAME


def app_data_dir() -> str:
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    d = os.path.join(base, APP_NAME)
    os.makedirs(d, exist_ok=True)
    return d


@dataclass
class Settings:
    # age thresholds (days)
    temp_age_days: int = 1
    log_age_days: int = 14
    dump_age_days: int = 7
    installer_age_days: int = 60
    old_download_days: int = 365
    stale_project_days: int = 90
    empty_folder_age_days: int = 7
    # size thresholds
    large_file_mb: int = 1024
    dupe_min_kb: int = 256
    hash_max_mb: int = 2048          # bigger files are not compared for duplicates
    # feature switches
    find_duplicates: bool = True
    find_large: bool = True
    find_dev_leftovers: bool = True
    find_empty_folders: bool = True
    # user-defined extra protection / exclusions (never scanned)
    excluded_paths: list[str] = field(default_factory=list)
    # behaviour
    use_recycle_bin: bool = True

    @classmethod
    def path(cls) -> str:
        return os.path.join(app_data_dir(), "settings.json")

    @classmethod
    def load(cls) -> "Settings":
        try:
            with open(cls.path(), "r", encoding="utf-8") as fh:
                data = json.load(fh)
            known = {f.name for f in fields(cls)}
            return cls(**{k: v for k, v in data.items() if k in known})
        except Exception:
            return cls()

    def save(self) -> None:
        with open(self.path(), "w", encoding="utf-8") as fh:
            json.dump(asdict(self), fh, indent=2)
