from __future__ import annotations

from dataclasses import asdict

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QCheckBox, QDialog, QDialogButtonBox, QFormLayout, QGroupBox, QHBoxLayout, QLabel,
                               QPlainTextEdit, QPushButton, QRadioButton, QSpinBox, QTabWidget, QTextEdit,
                               QVBoxLayout, QWidget)

from ..model import Finding, Risk, human_size
from ..settings import Settings


class SettingsDialog(QDialog):
    def __init__(self, settings: Settings, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("SmartCleaner settings")
        self.setMinimumWidth(520)
        self.settings = settings
        self._spins: dict[str, QSpinBox] = {}
        self._checks: dict[str, QCheckBox] = {}

        tabs = QTabWidget()
        tabs.addTab(self._rules_tab(), "Rules")
        tabs.addTab(self._exclusions_tab(), "Protected folders")

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel | QDialogButtonBox.RestoreDefaults)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        buttons.button(QDialogButtonBox.RestoreDefaults).clicked.connect(self._defaults)

        lay = QVBoxLayout(self)
        lay.addWidget(tabs)
        lay.addWidget(buttons)
        self._load(settings)

    def _spin(self, key: str, label: str, form: QFormLayout, suffix: str, maximum: int = 100000) -> None:
        sb = QSpinBox()
        sb.setRange(0, maximum)
        sb.setSuffix(" " + suffix)
        self._spins[key] = sb
        form.addRow(label, sb)

    def _check(self, key: str, label: str, lay) -> None:
        cb = QCheckBox(label)
        self._checks[key] = cb
        lay.addWidget(cb)

    def _rules_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        g1 = QGroupBox("Age thresholds (older than…)")
        f1 = QFormLayout(g1)
        self._spin("temp_age_days", "Temp files", f1, "days")
        self._spin("log_age_days", "Log files", f1, "days")
        self._spin("dump_age_days", "Crash dumps", f1, "days")
        self._spin("installer_age_days", "Installers in Downloads", f1, "days")
        self._spin("old_download_days", "Old downloads", f1, "days")
        self._spin("stale_project_days", "Project idle before dev leftovers are suggested", f1, "days")
        self._spin("empty_folder_age_days", "Empty folders", f1, "days")
        v.addWidget(g1)
        g2 = QGroupBox("Sizes")
        f2 = QFormLayout(g2)
        self._spin("large_file_mb", "Large file threshold", f2, "MB", 10_000_000)
        self._spin("dupe_min_kb", "Ignore duplicates smaller than", f2, "KB", 10_000_000)
        self._spin("hash_max_mb", "Skip duplicate check above (0 = no limit)", f2, "MB", 10_000_000)
        v.addWidget(g2)
        g3 = QGroupBox("What to look for")
        v3 = QVBoxLayout(g3)
        self._check("find_duplicates", "Duplicate files (needs to read file contents; slower)", v3)
        self._check("find_large", "Large files", v3)
        self._check("find_dev_leftovers", "Developer leftovers (node_modules, venv, build…)", v3)
        self._check("find_empty_folders", "Empty folders", v3)
        v.addWidget(g3)
        v.addStretch(1)
        return w

    def _exclusions_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        v.addWidget(QLabel("Folders listed here are never scanned and never suggested, one per line:"))
        self.excl = QPlainTextEdit()
        self.excl.setPlaceholderText("D:\\Photos\nC:\\Users\\me\\Documents\\Taxes")
        v.addWidget(self.excl)
        return w

    def _load(self, s: Settings) -> None:
        d = asdict(s)
        for k, sb in self._spins.items():
            sb.setValue(int(d[k]))
        for k, cb in self._checks.items():
            cb.setChecked(bool(d[k]))
        self.excl.setPlainText("\n".join(s.excluded_paths))

    def _defaults(self) -> None:
        self._load(Settings(excluded_paths=self.settings.excluded_paths))

    def result_settings(self) -> Settings:
        s = Settings(**asdict(self.settings))
        for k, sb in self._spins.items():
            setattr(s, k, sb.value())
        for k, cb in self._checks.items():
            setattr(s, k, cb.isChecked())
        s.excluded_paths = [ln.strip() for ln in self.excl.toPlainText().splitlines() if ln.strip()]
        return s


class ConfirmCleanDialog(QDialog):
    def __init__(self, findings: list[Finding], default_recycle: bool, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Confirm clean-up")
        self.setMinimumWidth(560)
        total = sum(f.size for f in findings)
        review = [f for f in findings if f.risk == Risk.REVIEW]
        dirs = sum(1 for f in findings if f.is_dir)

        lay = QVBoxLayout(self)
        head = QLabel(f"<b>{len(findings):,} items</b> ({dirs:,} folders) - <b>{human_size(total)}</b> will be removed.")
        head.setTextFormat(Qt.RichText)
        lay.addWidget(head)
        if review:
            warn = QLabel(f"<span style='color:#b26a00'>⚠ {len(review):,} of them are marked <b>Review</b> "
                          f"({human_size(sum(f.size for f in review))}). Make sure you looked at those.</span>")
            warn.setWordWrap(True)
            lay.addWidget(warn)

        self.rb_recycle = QRadioButton("Move to Recycle Bin (recommended - you can restore later)")
        self.rb_perm = QRadioButton("Delete permanently (faster, frees space immediately, no undo)")
        (self.rb_recycle if default_recycle else self.rb_perm).setChecked(True)
        lay.addWidget(self.rb_recycle)
        lay.addWidget(self.rb_perm)

        preview = QTextEdit()
        preview.setReadOnly(True)
        preview.setMaximumHeight(180)
        lines = [f"{human_size(f.size):>10}   {f.path}" for f in sorted(findings, key=lambda f: -f.size)[:400]]
        if len(findings) > 400:
            lines.append(f"… and {len(findings) - 400:,} more")
        preview.setPlainText("\n".join(lines))
        preview.setStyleSheet("font-family: Consolas, monospace; font-size: 9pt;")
        lay.addWidget(preview)

        btns = QDialogButtonBox()
        ok = QPushButton("Clean now")
        ok.setDefault(True)
        btns.addButton(ok, QDialogButtonBox.AcceptRole)
        btns.addButton(QDialogButtonBox.Cancel)
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        lay.addWidget(btns)

    @property
    def permanent(self) -> bool:
        return self.rb_perm.isChecked()


class ReportDialog(QDialog):
    def __init__(self, title: str, summary: str, details: list[str], parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumSize(560, 320)
        lay = QVBoxLayout(self)
        lbl = QLabel(summary)
        lbl.setTextFormat(Qt.RichText)
        lbl.setWordWrap(True)
        lay.addWidget(lbl)
        if details:
            box = QTextEdit()
            box.setReadOnly(True)
            box.setPlainText("\n".join(details))
            box.setStyleSheet("font-family: Consolas, monospace; font-size: 9pt;")
            lay.addWidget(box)
        h = QHBoxLayout()
        h.addStretch(1)
        b = QPushButton("Close")
        b.clicked.connect(self.accept)
        h.addWidget(b)
        lay.addLayout(h)
