from __future__ import annotations

import threading
import traceback

from PySide6.QtCore import QThread, Signal

from ..cleaner import CleanReport, delete_findings
from ..model import Finding, ScanResult
from ..scanner import ScanCancelled, Scanner
from ..settings import Settings


class ScanWorker(QThread):
    progress = Signal(str, object, object)   # (status, files, bytes) - object avoids 32-bit int overflow
    finished_ok = Signal(object)      # ScanResult
    cancelled = Signal()
    failed = Signal(str)

    def __init__(self, root: str, settings: Settings, parent=None) -> None:
        super().__init__(parent)
        self.root = root
        self.settings = settings
        self.cancel = threading.Event()

    def run(self) -> None:  # noqa: D401
        try:
            scanner = Scanner(self.root, self.settings, self._progress, self.cancel)
            result: ScanResult = scanner.run()
            self.finished_ok.emit(result)
        except ScanCancelled:
            self.cancelled.emit()
        except Exception:  # noqa: BLE001
            self.failed.emit(traceback.format_exc())

    def _progress(self, status: str, files: int, nbytes: int) -> None:
        self.progress.emit(status, files, nbytes)

    def stop(self) -> None:
        self.cancel.set()


class CleanWorker(QThread):
    progress = Signal(str, int, int)
    finished_ok = Signal(object)      # CleanReport

    def __init__(self, findings: list[Finding], permanent: bool, parent=None) -> None:
        super().__init__(parent)
        self.findings = findings
        self.permanent = permanent
        self.cancel = threading.Event()

    def run(self) -> None:
        rep: CleanReport = delete_findings(self.findings, self.permanent, self._progress, self.cancel)
        self.finished_ok.emit(rep)

    def _progress(self, path: str, done: int, total: int) -> None:
        self.progress.emit(path, done, total)

    def stop(self) -> None:
        self.cancel.set()
