from __future__ import annotations

import csv
import os
import time
from collections import defaultdict

from PySide6.QtCore import QSize, Qt, QTimer
from PySide6.QtGui import QAction, QBrush, QColor, QFont
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QComboBox, QFileDialog, QFrame, QGroupBox,
                               QHBoxLayout, QHeaderView, QLabel, QMainWindow, QMessageBox, QProgressBar,
                               QProgressDialog, QPushButton, QSizePolicy, QSplitter, QStatusBar, QTextBrowser, QToolBar,
                               QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget)

from .. import APP_NAME, __version__
from ..model import CATEGORIES, RISK_LABEL, Finding, Risk, ScanResult, human_size
from ..settings import Settings
from ..winutil import is_admin, list_drives, open_file, open_in_explorer, relaunch_as_admin
from .dialogs import ConfirmCleanDialog, ReportDialog, SettingsDialog
from .memory_dialog import MemoryDialog
from .suggestions import build_suggestions
from .workers import CleanWorker, ScanWorker

MAX_CHILDREN = 2000
MAX_GROUPS = 800
ROLE = Qt.UserRole

RISK_COLORS = {
    Risk.SAFE: QColor("#4caf50"),
    Risk.REVIEW: QColor("#ffb300"),
    Risk.KEEP: QColor("#64b5f6"),
    Risk.PROTECTED: QColor("#9e9e9e"),
}


def _age_text(mtime: float) -> str:
    days = (time.time() - mtime) / 86400
    if days < 1:
        return "today"
    if days < 60:
        return f"{days:.0f} d"
    if days < 730:
        return f"{days / 30:.0f} mo"
    return f"{days / 365:.1f} y"


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.settings = Settings.load()
        self.result: ScanResult | None = None
        self.findings: list[Finding] = []
        self.selected: set[int] = set()            # indices into self.findings
        self._cat_items: dict[str, QTreeWidgetItem] = {}
        self._by_cat: dict[str, list[int]] = defaultdict(list)
        self._by_group: dict[str, list[int]] = defaultdict(list)
        self._updating = False
        self.scan_worker: ScanWorker | None = None
        self.clean_worker: CleanWorker | None = None
        self._last_root: str = ""

        self.setWindowTitle(f"{APP_NAME} {__version__}" + ("  (Administrator)" if is_admin() else ""))
        self.resize(1360, 820)
        self._build_ui()
        self._refresh_drives()
        self._update_summary()

    # ------------------------------------------------------------------ UI construction
    def _build_ui(self) -> None:
        tb = QToolBar("Main")
        tb.setMovable(False)
        tb.setIconSize(QSize(18, 18))
        self.addToolBar(tb)

        tb.addWidget(QLabel("  Scan location: "))
        self.location = QComboBox()
        self.location.setEditable(True)
        self.location.setMinimumWidth(420)
        self.location.setInsertPolicy(QComboBox.NoInsert)
        tb.addWidget(self.location)
        browse = QAction("Browse folder…", self)
        browse.triggered.connect(self._browse)
        tb.addAction(browse)
        tb.addSeparator()
        self.act_scan = QAction("▶  Scan", self)
        self.act_scan.triggered.connect(self._start_scan)
        tb.addAction(self.act_scan)
        self.act_stop = QAction("■  Stop", self)
        self.act_stop.setEnabled(False)
        self.act_stop.triggered.connect(self._stop_scan)
        tb.addAction(self.act_stop)
        self.act_rescan = QAction("⟳  Rescan", self)
        self.act_rescan.setEnabled(False)
        self.act_rescan.setToolTip("Scan the same location again")
        self.act_rescan.triggered.connect(self._rescan)
        tb.addAction(self.act_rescan)
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        tb.addWidget(spacer)
        self.act_memory = QAction("🧠 Memory & caches", self)
        self.act_memory.setToolTip("Free RAM and VRAM, and clear DNS, thumbnail, Store and other live caches")
        self.act_memory.triggered.connect(self._open_memory)
        tb.addAction(self.act_memory)
        if not is_admin():
            adm = QAction("🛡 Restart as Administrator", self)
            adm.triggered.connect(self._elevate)
            tb.addAction(adm)
        act_settings = QAction("⚙ Settings", self)
        act_settings.triggered.connect(self._open_settings)
        tb.addAction(act_settings)

        # --- centre
        splitter = QSplitter(Qt.Horizontal)
        left = QWidget()
        lv = QVBoxLayout(left)
        lv.setContentsMargins(6, 6, 0, 6)

        self.disk_bar = QProgressBar()
        self.disk_bar.setTextVisible(True)
        self.disk_bar.setFormat("No scan yet")
        self.disk_bar.setFixedHeight(20)
        lv.addWidget(self.disk_bar)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Name", "Size", "Age", "Risk", "Why / details"])
        self.tree.setAlternatingRowColors(True)
        self.tree.setUniformRowHeights(True)
        self.tree.setSelectionMode(QAbstractItemView.ExtendedSelection)
        hdr = self.tree.header()
        hdr.setSectionResizeMode(0, QHeaderView.Interactive)
        hdr.resizeSection(0, 420)
        hdr.resizeSection(1, 90)
        hdr.resizeSection(2, 60)
        hdr.resizeSection(3, 80)
        hdr.setStretchLastSection(True)
        self.tree.itemChanged.connect(self._on_item_changed)
        self.tree.itemExpanded.connect(self._on_expanded)
        self.tree.currentItemChanged.connect(self._on_current_changed)
        self.tree.itemDoubleClicked.connect(lambda it, _c: self._open_location(it))
        lv.addWidget(self.tree, 1)

        selrow = QHBoxLayout()
        selrow.addWidget(QLabel("Select:"))
        for text, slot in (("Safe only", self._select_safe), ("Safe + suggested", self._select_suggested),
                           ("None", self._select_none)):
            b = QPushButton(text)
            b.setFlat(False)
            b.clicked.connect(slot)
            selrow.addWidget(b)
        selrow.addStretch(1)
        self.summary = QLabel("")
        self.summary.setStyleSheet("font-weight:600")
        selrow.addWidget(self.summary)
        lv.addLayout(selrow)

        btnrow = QHBoxLayout()
        self.btn_export = QPushButton("Export report (CSV)")
        self.btn_export.clicked.connect(self._export)
        btnrow.addWidget(self.btn_export)
        btnrow.addStretch(1)
        self.btn_recycle = QPushButton("🗑  Move selected to Recycle Bin")
        self.btn_recycle.setObjectName("primary")
        self.btn_recycle.clicked.connect(lambda: self._clean(permanent=False))
        btnrow.addWidget(self.btn_recycle)
        self.btn_perm = QPushButton("Delete permanently…")
        self.btn_perm.setObjectName("danger")
        self.btn_perm.clicked.connect(lambda: self._clean(permanent=True))
        btnrow.addWidget(self.btn_perm)
        lv.addLayout(btnrow)
        splitter.addWidget(left)

        right = QWidget()
        rv = QVBoxLayout(right)
        rv.setContentsMargins(0, 6, 6, 6)
        sug_box = QGroupBox("Suggestions")
        sv = QVBoxLayout(sug_box)
        self.suggestions = QTextBrowser()
        self.suggestions.setOpenExternalLinks(False)
        self.suggestions.setFrameShape(QFrame.NoFrame)
        sv.addWidget(self.suggestions)
        rv.addWidget(sug_box, 3)

        det_box = QGroupBox("Details")
        dv = QVBoxLayout(det_box)
        self.details = QLabel("Select an item to see why it was flagged.")
        self.details.setWordWrap(True)
        self.details.setTextFormat(Qt.RichText)
        self.details.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.details.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        dv.addWidget(self.details, 1)
        drow = QHBoxLayout()
        self.btn_open_loc = QPushButton("Open location")
        self.btn_open_loc.clicked.connect(lambda: self._open_location(self.tree.currentItem()))
        self.btn_open_file = QPushButton("Open file")
        self.btn_open_file.clicked.connect(self._open_current_file)
        self.btn_keep = QPushButton("Keep this one instead")
        self.btn_keep.clicked.connect(self._swap_keeper)
        self.btn_exclude = QPushButton("Protect this folder")
        self.btn_exclude.setToolTip("Add the containing folder to the never-scan list")
        self.btn_exclude.clicked.connect(self._protect_folder)
        for b in (self.btn_open_loc, self.btn_open_file, self.btn_keep, self.btn_exclude):
            drow.addWidget(b)
        dv.addLayout(drow)
        rv.addWidget(det_box, 2)
        splitter.addWidget(right)
        splitter.setSizes([880, 480])
        self.setCentralWidget(splitter)

        sb = QStatusBar()
        self.setStatusBar(sb)
        self.status_label = QLabel("Ready")
        sb.addWidget(self.status_label, 1)
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.setFixedWidth(220)
        self.progress.hide()
        sb.addPermanentWidget(self.progress)
        self.suggestions.setHtml(build_suggestions(None, self.settings))
        self._set_detail_buttons(None)

    # ------------------------------------------------------------------ drives / location
    def _refresh_drives(self) -> None:
        cur = self.location.currentText()
        self.location.clear()
        for root, label, total, free in list_drives():
            name = f"{root}  {label or 'Local Disk'}  -  {human_size(free)} free of {human_size(total)}"
            self.location.addItem(name, root)
        home = os.path.expanduser("~")
        for sub in ("Downloads", "Desktop", "Documents", ""):
            p = os.path.join(home, sub) if sub else home
            if os.path.isdir(p):
                self.location.addItem(p, p)
        if cur:
            self.location.setEditText(cur)

    def _current_root(self) -> str:
        idx = self.location.currentIndex()
        text = self.location.currentText().strip()
        if idx >= 0 and self.location.itemText(idx) == text:
            return self.location.itemData(idx)
        return text

    def _browse(self) -> None:
        d = QFileDialog.getExistingDirectory(self, "Choose a folder to scan", self._current_root() or "C:\\")
        if d:
            d = os.path.normpath(d)
            self.location.addItem(d, d)
            self.location.setCurrentIndex(self.location.count() - 1)

    def _elevate(self) -> None:
        if relaunch_as_admin():
            QApplication.quit()

    def _open_memory(self) -> None:
        MemoryDialog(self).exec()

    def _open_settings(self) -> None:
        dlg = SettingsDialog(self.settings, self)
        if dlg.exec():
            self.settings = dlg.result_settings()
            self.settings.save()
            if self.result:
                self.status_label.setText("Settings saved. Re-scan to apply the new rules.")

    # ------------------------------------------------------------------ scanning
    def _start_scan(self) -> None:
        root = self._current_root()
        if not root or not os.path.isdir(root):
            QMessageBox.warning(self, APP_NAME, f"'{root}' is not a folder I can open.")
            return
        self._clear_results()
        self._last_root = root
        self.act_scan.setEnabled(False)
        self.act_rescan.setEnabled(False)
        self.act_stop.setEnabled(True)
        self.progress.show()
        self.status_label.setText(f"Scanning {root} …")
        self.scan_worker = ScanWorker(root, self.settings, self)
        self.scan_worker.progress.connect(self._on_progress)
        self.scan_worker.finished_ok.connect(self._on_scan_done)
        self.scan_worker.cancelled.connect(self._on_scan_cancelled)
        self.scan_worker.failed.connect(self._on_scan_failed)
        self.scan_worker.start()

    def _rescan(self) -> None:
        if self._last_root and os.path.isdir(self._last_root) and self.scan_worker is None:
            self.location.setEditText(self._last_root)
            self._start_scan()

    def _stop_scan(self) -> None:
        if self.scan_worker:
            self.scan_worker.stop()
            self.status_label.setText("Stopping…")

    def _scan_finished_ui(self) -> None:
        self.act_scan.setEnabled(True)
        self.act_stop.setEnabled(False)
        self.act_rescan.setEnabled(bool(self._last_root))
        self.progress.hide()
        self.scan_worker = None

    def _refresh_disk_bar(self, root: str) -> None:
        """Show the real, current usage of the drive that holds `root`."""
        try:
            import shutil
            u = shutil.disk_usage(root)
        except OSError:
            self.disk_bar.setRange(0, 1)
            self.disk_bar.setValue(0)
            self.disk_bar.setFormat(root)
            return
        self.disk_bar.setRange(0, 100)
        self.disk_bar.setValue(int(u.used / u.total * 100) if u.total else 0)
        self.disk_bar.setFormat(f"{root}   {human_size(u.used)} used of {human_size(u.total)}  ({human_size(u.free)} free)")
        if self.result:
            self.result.disk_total, self.result.disk_used, self.result.disk_free = u.total, u.used, u.free

    def _on_progress(self, status: str, files: int, nbytes: int) -> None:
        self.status_label.setText(f"{files:,} files · {human_size(nbytes)}  |  {status}")

    def _on_scan_cancelled(self) -> None:
        self._scan_finished_ui()
        self.status_label.setText("Scan stopped.")

    def _on_scan_failed(self, tb: str) -> None:
        self._scan_finished_ui()
        self.status_label.setText("Scan failed.")
        ReportDialog("Scan failed", "The scan hit an unexpected error:", tb.splitlines(), self).exec()

    def _on_scan_done(self, result: ScanResult) -> None:
        self._scan_finished_ui()
        self.result = result
        self.findings = result.findings
        self._populate()
        self._select_safe()
        self.suggestions.setHtml(build_suggestions(result, self.settings))
        st = result.stats
        self.status_label.setText(
            f"Scanned {st.files_seen:,} files ({human_size(st.bytes_seen)}) in {st.seconds:.1f}s. "
            f"{len(self.findings):,} findings. {'Some folders were not readable.' if st.denied_paths else ''}")
        self._refresh_disk_bar(result.root)

    # ------------------------------------------------------------------ tree population
    def _clear_results(self) -> None:
        self._updating = True
        self.tree.clear()
        self._cat_items.clear()
        self._by_cat.clear()
        self._by_group.clear()
        self.selected.clear()
        self.result = None
        self.findings = []
        self._updating = False
        self.suggestions.setHtml(build_suggestions(None, self.settings))
        self.details.setText("Select an item to see why it was flagged.")
        self._update_summary()

    def _populate(self) -> None:
        self._updating = True
        self.tree.clear()
        self._cat_items.clear()
        self._by_cat.clear()
        self._by_group.clear()
        for i, f in enumerate(self.findings):
            self._by_cat[f.category].append(i)
            if f.group:
                self._by_group[f.group].append(i)
        bold = QFont()
        bold.setBold(True)
        for key, cat in sorted(CATEGORIES.items(), key=lambda kv: kv[1].order):
            idxs = self._by_cat.get(key)
            if not idxs:
                continue
            idxs.sort(key=lambda i: -self.findings[i].size)
            item = QTreeWidgetItem()
            item.setData(0, ROLE, ("cat", key))
            item.setFont(0, bold)
            item.setToolTip(0, cat.description)
            item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
            item.setCheckState(0, Qt.Unchecked)
            item.setChildIndicatorPolicy(QTreeWidgetItem.ShowIndicator)
            self.tree.addTopLevelItem(item)
            self._cat_items[key] = item
            self._refresh_cat_item(key)
        self._updating = False

    def _refresh_cat_item(self, key: str) -> None:
        item = self._cat_items.get(key)
        if item is None:
            return
        was = self._updating
        self._updating = True
        try:
            self._refresh_cat_item_inner(item, key)
        finally:
            self._updating = was

    def _refresh_cat_item_inner(self, item: QTreeWidgetItem, key: str) -> None:
        idxs = self._by_cat[key]
        cat = CATEGORIES[key]
        deletable = [i for i in idxs if self.findings[i].deletable]
        total = sum(self.findings[i].size for i in deletable)
        sel = [i for i in deletable if i in self.selected]
        sel_bytes = sum(self.findings[i].size for i in sel)
        item.setText(0, f"{cat.icon}  {cat.title}")
        item.setText(1, human_size(total))
        item.setTextAlignment(1, Qt.AlignRight | Qt.AlignVCenter)
        if key == "dupes":
            groups = len({self.findings[i].group for i in idxs})
            detail = f"{groups:,} groups · {len(deletable):,} removable copies"
        else:
            detail = f"{len(idxs):,} items"
        if sel:
            detail += f"  ·  selected {len(sel):,} ({human_size(sel_bytes)})"
        item.setText(4, detail)
        risks = {self.findings[i].risk for i in deletable}
        if not deletable:
            item.setText(3, "Info")
            item.setFlags(item.flags() & ~Qt.ItemIsUserCheckable)
        elif risks == {Risk.SAFE}:
            item.setText(3, "Safe")
            item.setForeground(3, QBrush(RISK_COLORS[Risk.SAFE]))
        else:
            item.setText(3, "Review")
            item.setForeground(3, QBrush(RISK_COLORS[Risk.REVIEW]))
        if deletable:
            state = Qt.Checked if len(sel) == len(deletable) else Qt.PartiallyChecked if sel else Qt.Unchecked
            item.setCheckState(0, state)

    def _make_file_item(self, idx: int, show_dir: bool) -> QTreeWidgetItem:
        f = self.findings[idx]
        it = QTreeWidgetItem()
        it.setData(0, ROLE, ("file", idx))
        it.setText(0, os.path.basename(f.path.rstrip("\\/")) or f.path)
        it.setToolTip(0, f.path)
        it.setText(1, human_size(f.size))
        it.setTextAlignment(1, Qt.AlignRight | Qt.AlignVCenter)
        it.setText(2, _age_text(f.mtime))
        it.setText(3, RISK_LABEL[f.risk] + (" ★" if f.suggested and f.risk == Risk.REVIEW else ""))
        it.setForeground(3, QBrush(RISK_COLORS[f.risk]))
        it.setText(4, (f.reason + ("   [" + os.path.dirname(f.path) + "]" if show_dir else "")))
        it.setToolTip(4, f.reason + ("\n" + f.note if f.note else ""))
        if f.deletable:
            it.setFlags(it.flags() | Qt.ItemIsUserCheckable)
            it.setCheckState(0, Qt.Checked if idx in self.selected else Qt.Unchecked)
        else:
            it.setFlags(it.flags() & ~Qt.ItemIsUserCheckable)
            grey = QBrush(QColor("#9e9e9e"))
            it.setForeground(0, grey)
            it.setForeground(4, grey)
        return it

    def _on_expanded(self, item: QTreeWidgetItem) -> None:
        data = item.data(0, ROLE)
        if not data or item.childCount() or data[0] != "cat":
            return
        key = data[1]
        idxs = self._by_cat[key]
        self._updating = True
        try:
            if key == "dupes":
                groups: dict[str, list[int]] = defaultdict(list)
                for i in idxs:
                    groups[self.findings[i].group].append(i)
                ordered = sorted(groups.items(),
                                 key=lambda kv: -sum(self.findings[i].size for i in kv[1] if self.findings[i].deletable))
                for gkey, members in ordered[:MAX_GROUPS]:
                    members.sort(key=lambda i: 0 if self.findings[i].risk == Risk.KEEP else 1)  # keeper first
                    f0 = self.findings[members[0]]
                    g = QTreeWidgetItem()
                    g.setData(0, ROLE, ("grp", gkey))
                    g.setText(0, f"{len(members)} × {os.path.basename(f0.path)}")
                    g.setText(1, human_size(f0.size * (len(members) - 1)))
                    g.setTextAlignment(1, Qt.AlignRight | Qt.AlignVCenter)
                    g.setText(3, "Review")
                    g.setForeground(3, QBrush(RISK_COLORS[Risk.REVIEW]))
                    g.setText(4, f"{human_size(f0.size)} each · {len(members) - 1} extra cop{'y' if len(members) == 2 else 'ies'}")
                    g.setFlags(g.flags() | Qt.ItemIsUserCheckable)
                    dele = [i for i in members if self.findings[i].deletable]
                    sel = [i for i in dele if i in self.selected]
                    g.setCheckState(0, Qt.Checked if dele and len(sel) == len(dele) else Qt.PartiallyChecked if sel else Qt.Unchecked)
                    for i in members:
                        g.addChild(self._make_file_item(i, show_dir=True))
                    item.addChild(g)
                if len(ordered) > MAX_GROUPS:
                    item.addChild(self._more_item(len(ordered) - MAX_GROUPS, "groups"))
            else:
                for i in idxs[:MAX_CHILDREN]:
                    item.addChild(self._make_file_item(i, show_dir=True))
                if len(idxs) > MAX_CHILDREN:
                    item.addChild(self._more_item(len(idxs) - MAX_CHILDREN, "items"))
        finally:
            self._updating = False

    def _more_item(self, n: int, what: str) -> QTreeWidgetItem:
        it = QTreeWidgetItem()
        it.setText(0, f"… {n:,} more {what} not listed (smaller ones). The category checkbox selects them too.")
        it.setFlags(Qt.ItemIsEnabled)
        it.setForeground(0, QBrush(QColor("#9e9e9e")))
        return it

    # ------------------------------------------------------------------ selection
    def _on_item_changed(self, item: QTreeWidgetItem, column: int) -> None:
        if self._updating or column != 0:
            return
        data = item.data(0, ROLE)
        if not data:
            return
        kind, val = data
        checked = item.checkState(0) == Qt.Checked
        self._updating = True
        try:
            if kind == "file":
                self._set_selected([val], checked)
                parent = item.parent()
                self._refresh_widget_states(parent)
            elif kind == "grp":
                idxs = [i for i in self._by_group[val] if self.findings[i].deletable]
                self._set_selected(idxs, checked)
                for c in range(item.childCount()):
                    self._sync_child(item.child(c))
                self._refresh_widget_states(item.parent())
            elif kind == "cat":
                idxs = [i for i in self._by_cat[val] if self.findings[i].deletable]
                self._set_selected(idxs, checked)
                self._sync_children(item)
        finally:
            self._updating = False
        self._update_summary()

    def _set_selected(self, idxs: list[int], on: bool) -> None:
        if on:
            self.selected.update(idxs)
        else:
            self.selected.difference_update(idxs)
        cats = {self.findings[i].category for i in idxs}
        for c in cats:
            self._refresh_cat_item(c)

    def _sync_child(self, it: QTreeWidgetItem) -> None:
        data = it.data(0, ROLE)
        if data and data[0] == "file" and self.findings[data[1]].deletable:
            it.setCheckState(0, Qt.Checked if data[1] in self.selected else Qt.Unchecked)
        elif data and data[0] == "grp":
            dele = [i for i in self._by_group[data[1]] if self.findings[i].deletable]
            sel = [i for i in dele if i in self.selected]
            it.setCheckState(0, Qt.Checked if dele and len(sel) == len(dele) else Qt.PartiallyChecked if sel else Qt.Unchecked)
            for c in range(it.childCount()):
                self._sync_child(it.child(c))

    def _sync_children(self, item: QTreeWidgetItem) -> None:
        for c in range(item.childCount()):
            self._sync_child(item.child(c))

    def _refresh_widget_states(self, item: QTreeWidgetItem | None) -> None:
        while item is not None:
            data = item.data(0, ROLE)
            if data and data[0] == "grp":
                self._sync_child(item)
            item = item.parent()

    def _select_by(self, pred) -> None:
        self._updating = True
        try:
            self.selected = {i for i, f in enumerate(self.findings) if f.deletable and pred(f)}
            for key in self._cat_items:
                self._refresh_cat_item(key)
                self._sync_children(self._cat_items[key])
        finally:
            self._updating = False
        self._update_summary()

    def _select_safe(self) -> None:
        self._select_by(lambda f: f.risk == Risk.SAFE)

    def _select_suggested(self) -> None:
        self._select_by(lambda f: f.risk == Risk.SAFE or f.suggested)

    def _select_none(self) -> None:
        self._select_by(lambda f: False)

    def _update_summary(self) -> None:
        n = len(self.selected)
        total = sum(self.findings[i].size for i in self.selected)
        self.summary.setText(f"Selected: {n:,} items · {human_size(total)}")
        has = n > 0 and self.scan_worker is None
        self.btn_recycle.setEnabled(has)
        self.btn_perm.setEnabled(has)
        self.btn_export.setEnabled(bool(self.findings))

    # ------------------------------------------------------------------ details
    def _current_finding(self) -> Finding | None:
        it = self.tree.currentItem()
        if not it:
            return None
        data = it.data(0, ROLE)
        if data and data[0] == "file":
            return self.findings[data[1]]
        return None

    def _on_current_changed(self, cur: QTreeWidgetItem | None, _prev) -> None:
        f = self._current_finding()
        self._set_detail_buttons(f)
        if f is None:
            data = cur.data(0, ROLE) if cur else None
            if data and data[0] == "cat":
                cat = CATEGORIES[data[1]]
                self.details.setText(f"<b>{cat.icon} {cat.title}</b><br>{cat.description}")
            elif data and data[0] == "grp":
                self.details.setText("A group of files with byte-identical content. Keep one, remove the rest.")
            return
        mt = time.strftime("%Y-%m-%d %H:%M", time.localtime(f.mtime))
        color = RISK_COLORS[f.risk].name()
        html = (f"<div style='font-size:105%'><b>{os.path.basename(f.path.rstrip('\\/'))}</b></div>"
                f"<div style='color:#888'>{f.path}</div><br>"
                f"<table cellpadding=2>"
                f"<tr><td><b>Size</b></td><td>{human_size(f.size)}</td></tr>"
                f"<tr><td><b>Modified</b></td><td>{mt} ({_age_text(f.mtime)} ago)</td></tr>"
                f"<tr><td><b>Risk</b></td><td style='color:{color}'><b>{RISK_LABEL[f.risk]}</b></td></tr>"
                f"<tr><td><b>Category</b></td><td>{CATEGORIES[f.category].title}</td></tr>"
                f"<tr><td valign=top><b>Why</b></td><td>{f.reason}</td></tr>"
                + (f"<tr><td valign=top><b>Note</b></td><td style='color:#ffb300'>{f.note}</td></tr>" if f.note else "")
                + "</table>")
        if f.risk == Risk.KEEP:
            html += "<p>This is the copy we suggest keeping, so it cannot be selected.</p>"
        elif f.risk == Risk.PROTECTED:
            html += "<p>Protected: shown for information only.</p>"
        self.details.setText(html)

    def _set_detail_buttons(self, f: Finding | None) -> None:
        self.btn_open_loc.setEnabled(f is not None)
        self.btn_open_file.setEnabled(f is not None and not f.is_dir and f.category != "recycle")
        self.btn_keep.setEnabled(f is not None and f.category == "dupes" and f.risk == Risk.REVIEW)
        self.btn_exclude.setEnabled(f is not None and f.category != "recycle")

    def _open_location(self, it: QTreeWidgetItem | None) -> None:
        if it is None:
            return
        data = it.data(0, ROLE)
        if data and data[0] == "file":
            open_in_explorer(self.findings[data[1]].path)

    def _open_current_file(self) -> None:
        f = self._current_finding()
        if f and not f.is_dir:
            open_file(f.path)

    def _swap_keeper(self) -> None:
        f = self._current_finding()
        if not f or f.category != "dupes" or not f.group:
            return
        idxs = self._by_group[f.group]
        for i in idxs:
            g = self.findings[i]
            if g.risk == Risk.KEEP:
                g.risk = Risk.REVIEW
                g.suggested = True
                g.reason = f"Identical to {os.path.basename(f.path)} ({len(idxs)} copies)"
            elif g is f:
                g.risk = Risk.KEEP
                g.suggested = False
                g.reason = f"Suggested original of {len(idxs)} identical copies"
                self.selected.discard(i)
        # rebuild that category's visible children
        cat_item = self._cat_items["dupes"]
        self._updating = True
        try:
            cat_item.takeChildren()
        finally:
            self._updating = False
        self._on_expanded(cat_item)
        self._refresh_cat_item("dupes")
        self._update_summary()

    def _protect_folder(self) -> None:
        f = self._current_finding()
        if not f:
            return
        folder = f.path if f.is_dir else os.path.dirname(f.path)
        if folder not in self.settings.excluded_paths:
            self.settings.excluded_paths.append(folder)
            self.settings.save()
        # drop findings inside that folder from the current view
        nf = os.path.normcase(folder)
        removed = {g.path for g in self.findings if os.path.normcase(g.path).startswith(nf)}
        self._drop_findings(removed)
        self._select_safe()
        self.status_label.setText(f"Protected {folder} - it will be skipped in future scans.")

    # ------------------------------------------------------------------ cleaning
    def _clean(self, permanent: bool) -> None:
        items = [self.findings[i] for i in sorted(self.selected) if self.findings[i].deletable]
        if not items:
            return
        dlg = ConfirmCleanDialog(items, not permanent, self)
        if not dlg.exec():
            return
        permanent = dlg.permanent
        if permanent:
            ans = QMessageBox.warning(
                self, "Delete permanently?",
                f"{len(items):,} items ({human_size(sum(f.size for f in items))}) will be deleted permanently.\n"
                "This cannot be undone. Continue?", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if ans != QMessageBox.Yes:
                return
        prog = QProgressDialog("Cleaning…", "Stop", 0, len(items), self)
        prog.setWindowTitle("Cleaning")
        prog.setWindowModality(Qt.WindowModal)
        prog.setMinimumDuration(0)
        prog.setAutoClose(False)
        prog.setAutoReset(False)
        self.clean_worker = CleanWorker(items, permanent, self)

        def on_prog(path: str, done: int, total: int) -> None:
            prog.setValue(done)
            prog.setLabelText(f"{done:,} / {total:,}\n{path[-90:]}")

        def on_done(rep) -> None:
            prog.close()
            self.clean_worker = None
            failed_paths = {p for p, _ in rep.failed}
            deleted = {f.path for f in items if f.path not in failed_paths}
            self._drop_findings(deleted)
            mode = "deleted permanently" if permanent else "moved to the Recycle Bin"
            summary = (f"<b>{rep.ok:,} items {mode}</b>, about <b>{human_size(rep.freed)}</b>."
                       + ("" if permanent else "<br>Space is only freed once the Recycle Bin is emptied; "
                          "the rescan will list it under <b>Recycle Bin</b>.")
                       + (f"<br><span style='color:#ffb300'>{len(rep.failed):,} could not be removed"
                          f" (in use, locked, or protected).</span>" if rep.failed else "")
                       + ("<br>Stopped early." if rep.cancelled else "")
                       + "<br><br>The location will be rescanned when you close this window.")
            ReportDialog("Clean-up finished", summary,
                         [f"{p}   —   {why}" for p, why in rep.failed], self).exec()
            self.status_label.setText(f"{rep.ok:,} items {mode}, {human_size(rep.freed)}. Rescanning…")
            if self.result:
                self.result.findings = self.findings
                self._refresh_disk_bar(self.result.root)
            # refresh: scan the same location again so the list and totals are current
            QTimer.singleShot(0, self._rescan)

        prog.canceled.connect(self.clean_worker.stop)
        self.clean_worker.progress.connect(on_prog)
        self.clean_worker.finished_ok.connect(on_done)
        self.clean_worker.start()

    def _drop_findings(self, paths: set[str]) -> None:
        keep = [f for f in self.findings if f.path not in paths]
        # if a duplicate group shrank to a single file, drop the lone KEEP entry too
        counts: dict[str, int] = defaultdict(int)
        for f in keep:
            if f.group:
                counts[f.group] += 1
        keep = [f for f in keep if not (f.group and counts[f.group] < 2)]
        self.findings = keep
        self.selected = set()
        self._populate()
        self._update_summary()

    # ------------------------------------------------------------------ export
    def _export(self) -> None:
        if not self.findings:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export report", os.path.join(os.path.expanduser("~"), "smartcleaner-report.csv"),
                                              "CSV files (*.csv)")
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8-sig") as fh:
            w = csv.writer(fh)
            w.writerow(["category", "risk", "selected", "size_bytes", "size", "modified", "path", "reason", "note", "group"])
            for i, f in enumerate(self.findings):
                w.writerow([CATEGORIES[f.category].title, RISK_LABEL[f.risk], "yes" if i in self.selected else "",
                            f.size, human_size(f.size), time.strftime("%Y-%m-%d", time.localtime(f.mtime)),
                            f.path, f.reason, f.note, f.group or ""])
        self.status_label.setText(f"Report written to {path}")

    # ------------------------------------------------------------------ lifecycle
    def closeEvent(self, ev) -> None:  # noqa: N802
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.stop()
            self.scan_worker.wait(3000)
        if self.clean_worker and self.clean_worker.isRunning():
            self.clean_worker.stop()
            self.clean_worker.wait(5000)
        super().closeEvent(ev)
