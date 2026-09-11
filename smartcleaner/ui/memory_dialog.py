"""Memory & caches window: live RAM / VRAM view, one-click clean-ups, and a process list."""
from __future__ import annotations

import html

from PySide6.QtCore import QThread, Qt, QTimer, Signal
from PySide6.QtGui import QBrush, QColor, QFont
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QCheckBox, QDialog, QFormLayout, QGridLayout,
                               QGroupBox, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMessageBox, QProgressBar,
                               QPushButton, QScrollArea, QSplitter, QTabWidget, QTextEdit, QTreeWidget,
                               QTreeWidgetItem, QVBoxLayout, QWidget)

from .. import sysclean
from ..model import human_size
from ..winutil import is_admin, relaunch_as_admin

ROLE = Qt.UserRole
NUM_ROLE = Qt.UserRole + 1


class _NumItem(QTreeWidgetItem):
    """Sorts size / pid columns by their numeric value instead of their text."""

    def __lt__(self, other: QTreeWidgetItem) -> bool:  # type: ignore[override]
        col = self.treeWidget().sortColumn() if self.treeWidget() else 0
        a, b = self.data(col, NUM_ROLE), other.data(col, NUM_ROLE)
        if a is not None and b is not None:
            return a < b
        return self.text(col).lower() < other.text(col).lower()


# --------------------------------------------------------------------------------------
# Workers
# --------------------------------------------------------------------------------------

class OpsWorker(QThread):
    step = Signal(object)          # OpResult
    started_op = Signal(str)       # title
    done = Signal(int)             # bytes freed (approx)

    def __init__(self, keys: list[str], parent=None) -> None:
        super().__init__(parent)
        self.keys = keys

    def run(self) -> None:
        freed = 0
        titles = {o.key: o.title for o in sysclean.OPERATIONS}
        for k in self.keys:
            self.started_op.emit(titles.get(k, k))
            res = sysclean.run_operation(k)
            freed += res.freed if res.ok else 0
            self.step.emit(res)
        self.done.emit(freed)


class StatusWorker(QThread):
    ready = Signal(object, object, object)   # MemoryStatus, [GpuInfo], [ProcInfo] | None

    def __init__(self, with_procs: bool, parent=None) -> None:
        super().__init__(parent)
        self.with_procs = with_procs

    def run(self) -> None:
        mem = sysclean.memory_status()
        gpus = sysclean.gpu_status()
        procs = sysclean.list_processes() if self.with_procs else None
        self.ready.emit(mem, gpus, procs)


# --------------------------------------------------------------------------------------
# Small widgets
# --------------------------------------------------------------------------------------

class _Meter(QWidget):
    """A labelled progress bar: title on the left, 'used of total' in the bar."""

    def __init__(self, title: str) -> None:
        super().__init__()
        h = QHBoxLayout(self)
        h.setContentsMargins(0, 0, 0, 0)
        self.label = QLabel(title)
        self.label.setMinimumWidth(150)
        self.bar = QProgressBar()
        self.bar.setRange(0, 1000)
        self.bar.setFixedHeight(18)
        self.bar.setTextVisible(True)
        h.addWidget(self.label)
        h.addWidget(self.bar, 1)

    def set(self, used: int, total: int, text: str | None = None) -> None:
        self.bar.setValue(int(used / total * 1000) if total else 0)
        self.bar.setFormat(text or (f"{human_size(used)} of {human_size(total)}" if total else human_size(used)))
        pct = used / total if total else 0
        color = "#c62828" if pct > 0.9 else "#ffb300" if pct > 0.75 else "#3d7bd9"
        self.bar.setStyleSheet(f"QProgressBar::chunk {{ background: {color}; }}")


# --------------------------------------------------------------------------------------
# Dialog
# --------------------------------------------------------------------------------------

class MemoryDialog(QDialog):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("Memory & caches" + ("  (Administrator)" if is_admin() else ""))
        self.resize(1080, 760)
        self.setWindowFlag(Qt.WindowMaximizeButtonHint, True)
        self._checks: dict[str, QCheckBox] = {}
        self._gpu_meters: list[_Meter] = []
        self._procs: list[sysclean.ProcInfo] = []
        self._status_worker: StatusWorker | None = None
        self._ops_worker: OpsWorker | None = None
        self._build()
        self._timer = QTimer(self)
        self._timer.setInterval(2500)
        self._timer.timeout.connect(self._refresh_status)
        self._timer.start()
        self._refresh_status()

    # ------------------------------------------------------------------ UI
    def _build(self) -> None:
        lay = QVBoxLayout(self)
        self.tabs = QTabWidget()
        self.tabs.addTab(self._clean_tab(), "Clean memory & caches")
        self.tabs.addTab(self._process_tab(), "Programs using memory")
        self.tabs.currentChanged.connect(lambda _i: self._refresh_status())
        lay.addWidget(self.tabs, 1)
        bottom = QHBoxLayout()
        if not is_admin():
            adm = QPushButton("🛡 Restart as Administrator")
            adm.setToolTip("Standby-list purge, system-wide trims and service caches need an elevated process.")
            adm.clicked.connect(self._elevate)
            bottom.addWidget(adm)
        bottom.addStretch(1)
        close = QPushButton("Close")
        close.clicked.connect(self.accept)
        bottom.addWidget(close)
        lay.addLayout(bottom)

    def _clean_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)

        # --- live status
        status_row = QHBoxLayout()
        ram_box = QGroupBox("RAM")
        rv = QVBoxLayout(ram_box)
        self.m_ram = _Meter("In use")
        self.m_commit = _Meter("Committed")
        rv.addWidget(self.m_ram)
        rv.addWidget(self.m_commit)
        self.ram_detail = QLabel("")
        self.ram_detail.setTextFormat(Qt.RichText)
        self.ram_detail.setWordWrap(True)
        rv.addWidget(self.ram_detail)
        status_row.addWidget(ram_box, 1)

        self.gpu_box = QGroupBox("VRAM")
        self.gpu_layout = QVBoxLayout(self.gpu_box)
        self.gpu_detail = QLabel("Reading graphics adapters…")
        self.gpu_detail.setTextFormat(Qt.RichText)
        self.gpu_detail.setWordWrap(True)
        self.gpu_layout.addWidget(self.gpu_detail)
        status_row.addWidget(self.gpu_box, 1)
        v.addLayout(status_row)

        # --- operations + log
        split = QSplitter(Qt.Horizontal)
        ops = QWidget()
        ov = QVBoxLayout(ops)
        ov.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.NoFrame)
        inner = QWidget()
        iv = QVBoxLayout(inner)
        iv.setContentsMargins(0, 0, 6, 0)
        for group, title in (("ram", "🧠  RAM"), ("vram", "🎮  VRAM (graphics memory)"), ("cache", "📦  Other caches")):
            gb = QGroupBox(title)
            gl = QGridLayout(gb)
            gl.setColumnStretch(1, 1)
            row = 0
            for op in [o for o in sysclean.OPERATIONS if o.group == group]:
                cb = QCheckBox(op.title)
                f = QFont()
                f.setBold(True)
                cb.setFont(f)
                cb.setChecked(op.default_on and (is_admin() or not op.needs_admin))
                if op.needs_admin and not is_admin():
                    cb.setEnabled(False)
                    cb.setChecked(False)
                    cb.setToolTip("Needs Administrator rights - use Restart as Administrator below.")
                self._checks[op.key] = cb
                gl.addWidget(cb, row, 0, 1, 2)
                desc = op.description
                if op.disruptive:
                    desc += f" <span style='color:#ffb300'>⚠ {html.escape(op.disruptive)}</span>"
                if op.needs_admin:
                    desc += " <span style='color:#64b5f6'>🛡 Administrator</span>"
                d = QLabel(desc)
                d.setTextFormat(Qt.RichText)
                d.setWordWrap(True)
                d.setStyleSheet("color:#aaa; margin-left:22px;")
                gl.addWidget(d, row + 1, 0, 1, 2)
                row += 2
            iv.addWidget(gb)
        iv.addStretch(1)
        scroll.setWidget(inner)
        ov.addWidget(scroll, 1)

        brow = QHBoxLayout()
        for text, keys in (("Quick: free RAM", ["trim", "standby", "dns", "thumbs"]),
                           ("All safe", [o.key for o in sysclean.OPERATIONS if not o.disruptive]),
                           ("None", [])):
            b = QPushButton(text)
            b.clicked.connect(lambda _c=False, k=keys: self._preset(k))
            brow.addWidget(b)
        brow.addStretch(1)
        self.btn_run = QPushButton("▶  Run selected")
        self.btn_run.setObjectName("primary")
        self.btn_run.clicked.connect(self._run_selected)
        brow.addWidget(self.btn_run)
        ov.addLayout(brow)
        split.addWidget(ops)

        log_box = QGroupBox("Results")
        lv = QVBoxLayout(log_box)
        self.log = QTextEdit()
        self.log.setReadOnly(True)
        self.log.setPlaceholderText("Pick the clean-ups you want on the left and press Run selected.\n\n"
                                    "Nothing here touches your files. RAM trims are reversible by design: "
                                    "programs simply reload what they need.")
        lv.addWidget(self.log, 1)
        self.log_summary = QLabel("")
        self.log_summary.setTextFormat(Qt.RichText)
        self.log_summary.setWordWrap(True)
        lv.addWidget(self.log_summary)
        split.addWidget(log_box)
        split.setSizes([640, 420])
        v.addWidget(split, 1)
        return w

    def _process_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        top = QHBoxLayout()
        top.addWidget(QLabel("Filter:"))
        self.filter = QLineEdit()
        self.filter.setPlaceholderText("process name…")
        self.filter.textChanged.connect(self._fill_processes)
        top.addWidget(self.filter, 1)
        self.lbl_proc_hint = QLabel(
            "<b>Committed</b> is what a program has reserved (RAM + pagefile). It only drops when the program "
            "frees memory or exits. <b>RAM</b> is what it holds right now and can be trimmed.")
        self.lbl_proc_hint.setTextFormat(Qt.RichText)
        self.lbl_proc_hint.setWordWrap(True)
        v.addLayout(top)
        v.addWidget(self.lbl_proc_hint)

        self.ptree = QTreeWidget()
        self.ptree.setHeaderLabels(["Program", "PID", "RAM (working set)", "Committed (private)", "VRAM dedicated",
                                    "VRAM shared", "Path"])
        self.ptree.setRootIsDecorated(False)
        self.ptree.setAlternatingRowColors(True)
        self.ptree.setUniformRowHeights(True)
        self.ptree.setSortingEnabled(True)
        self.ptree.sortByColumn(3, Qt.DescendingOrder)
        self.ptree.setSelectionMode(QAbstractItemView.ExtendedSelection)
        hdr = self.ptree.header()
        hdr.resizeSection(0, 260)
        for c in (1, 2, 3, 4, 5):
            hdr.resizeSection(c, 120)
        hdr.setSectionResizeMode(6, QHeaderView.Stretch)
        self.ptree.itemSelectionChanged.connect(self._proc_buttons)
        v.addWidget(self.ptree, 1)

        brow = QHBoxLayout()
        self.chk_live = QCheckBox("Auto-refresh")
        self.chk_live.setChecked(True)
        brow.addWidget(self.chk_live)
        b_ref = QPushButton("⟳ Refresh")
        b_ref.clicked.connect(self._refresh_status)
        brow.addWidget(b_ref)
        brow.addStretch(1)
        self.btn_trim_one = QPushButton("Trim RAM of selected")
        self.btn_trim_one.setToolTip("Push the program's unused pages out of RAM. It keeps running.")
        self.btn_trim_one.clicked.connect(self._trim_selected)
        brow.addWidget(self.btn_trim_one)
        self.btn_kill = QPushButton("End selected program…")
        self.btn_kill.setObjectName("danger")
        self.btn_kill.setToolTip("Terminates the program. Only way to release its committed memory and VRAM.")
        self.btn_kill.clicked.connect(self._end_selected)
        brow.addWidget(self.btn_kill)
        v.addLayout(brow)
        self._proc_buttons()
        return w

    # ------------------------------------------------------------------ status refresh
    def _refresh_status(self) -> None:
        if self._status_worker is not None and self._status_worker.isRunning():
            return
        want_procs = self.tabs.currentIndex() == 1 and (self.chk_live.isChecked() or not self._procs)
        self._status_worker = StatusWorker(want_procs, self)
        self._status_worker.ready.connect(self._on_status)
        self._status_worker.finished.connect(self._status_finished)
        self._status_worker.start()

    def _status_finished(self) -> None:
        w = self._status_worker
        self._status_worker = None
        if w is not None:
            w.deleteLater()

    def _on_status(self, mem: sysclean.MemoryStatus, gpus: list[sysclean.GpuInfo], procs) -> None:
        self.m_ram.set(mem.used, mem.total)
        self.m_commit.set(mem.commit_total, mem.commit_limit)
        standby = f"<b>Cached (standby):</b> {human_size(mem.standby)}" if mem.standby else \
            f"<b>System cache:</b> {human_size(mem.system_cache)}"
        self.ram_detail.setText(
            f"<b>Available:</b> {human_size(mem.available)} &nbsp; <b>Free:</b> {human_size(mem.free_zero)} &nbsp; "
            f"{standby} &nbsp; <b>Modified:</b> {human_size(mem.modified)}<br>"
            f"<b>Pagefile in use:</b> {human_size(mem.pagefile_used)} &nbsp; "
            f"<b>Commit peak:</b> {human_size(mem.commit_peak)}")

        # (re)build GPU meters when the adapter set changes
        if len(self._gpu_meters) != len(gpus):
            for m in self._gpu_meters:
                self.gpu_layout.removeWidget(m)
                m.deleteLater()
            self._gpu_meters = []
            for g in gpus:
                m = _Meter(g.name)
                self.gpu_layout.insertWidget(len(self._gpu_meters), m)
                self._gpu_meters.append(m)
        if not gpus:
            self.gpu_detail.setText("No GPU memory counters available on this system.")
        else:
            lines = []
            for g, m in zip(gpus, self._gpu_meters):
                m.label.setText(g.name if len(g.name) < 34 else g.name[:32] + "…")
                m.label.setToolTip(g.name)
                if g.dedicated_total:
                    m.set(g.dedicated_used, g.dedicated_total)
                else:
                    m.set(g.dedicated_used, 0, f"{human_size(g.dedicated_used)} dedicated in use")
                lines.append(f"<b>{html.escape(g.name)}</b>: {human_size(g.dedicated_used)} dedicated"
                             + (f" of {human_size(g.dedicated_total)}" if g.dedicated_total else "")
                             + f", {human_size(g.shared_used)} shared system RAM")
            self.gpu_detail.setText("<br>".join(lines)
                                    + "<br><span style='color:#888'>Per-program VRAM is on the "
                                      "<i>Programs using memory</i> tab.</span>")
        if procs is not None:
            self._procs = procs
            self._fill_processes()

    def _fill_processes(self) -> None:
        flt = self.filter.text().strip().lower()
        selected = {it.data(1, ROLE) for it in self.ptree.selectedItems()}
        self.ptree.setSortingEnabled(False)
        self.ptree.clear()
        crit = QBrush(QColor("#9e9e9e"))
        for p in self._procs:
            if flt and flt not in p.name.lower():
                continue
            it = _NumItem()
            it.setText(0, p.name)
            it.setData(1, ROLE, p.pid)
            it.setData(1, NUM_ROLE, p.pid)
            it.setText(1, str(p.pid))
            for col, val in ((2, p.working_set), (3, p.private), (4, p.gpu_dedicated), (5, p.gpu_shared)):
                it.setText(col, human_size(val) if val else "")
                it.setData(col, NUM_ROLE, val)
                it.setTextAlignment(col, Qt.AlignRight | Qt.AlignVCenter)
            it.setTextAlignment(1, Qt.AlignRight | Qt.AlignVCenter)
            it.setText(6, p.exe)
            it.setToolTip(0, p.exe or p.name)
            if sysclean.is_critical(p):
                it.setForeground(0, crit)
                it.setToolTip(0, "Part of Windows - shown for information, cannot be ended from here.")
            self.ptree.addTopLevelItem(it)
            if p.pid in selected:
                it.setSelected(True)
        self.ptree.setSortingEnabled(True)
        self._proc_buttons()

    def _selected_procs(self) -> list[sysclean.ProcInfo]:
        pids = {it.data(1, ROLE) for it in self.ptree.selectedItems()}
        return [p for p in self._procs if p.pid in pids]

    def _proc_buttons(self) -> None:
        sel = self._selected_procs()
        self.btn_trim_one.setEnabled(bool(sel))
        self.btn_kill.setEnabled(bool(sel) and not all(sysclean.is_critical(p) for p in sel))

    # ------------------------------------------------------------------ actions
    def _preset(self, keys: list[str]) -> None:
        for k, cb in self._checks.items():
            cb.setChecked(cb.isEnabled() and k in keys)

    def _elevate(self) -> None:
        if relaunch_as_admin():
            QApplication.quit()

    def _run_selected(self) -> None:
        keys = [o.key for o in sysclean.OPERATIONS if self._checks[o.key].isChecked()]
        if not keys:
            QMessageBox.information(self, "Nothing selected", "Tick at least one clean-up first.")
            return
        warn = [o for o in sysclean.OPERATIONS if o.key in keys and o.disruptive]
        if warn:
            text = "\n".join(f"• {o.title}: {o.disruptive}" for o in warn)
            ans = QMessageBox.warning(self, "These will be noticeable",
                                      f"{text}\n\nContinue?", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if ans != QMessageBox.Yes:
                return
        self.log.clear()
        self.log_summary.setText("")
        self._set_busy(True)
        self._before = sysclean.memory_status()
        self._ops_worker = OpsWorker(keys, self)
        self._ops_worker.started_op.connect(lambda t: self._append(f"<span style='color:#888'>… {html.escape(t)}</span>"))
        self._ops_worker.step.connect(self._on_step)
        self._ops_worker.done.connect(self._on_done)
        self._ops_worker.start()

    def _set_busy(self, busy: bool) -> None:
        self.btn_run.setEnabled(not busy)
        self.btn_run.setText("Working…" if busy else "▶  Run selected")

    def _append(self, html_line: str) -> None:
        self.log.append(html_line)

    def _on_step(self, r: sysclean.OpResult) -> None:
        color = "#4caf50" if r.ok else "#64b5f6" if r.needs_admin else "#ffb300"
        mark = "✔" if r.ok else "🛡" if r.needs_admin else "✖"
        extra = f" <b>({human_size(r.freed)})</b>" if r.ok and r.freed else ""
        self._append(f"<span style='color:{color}'>{mark} <b>{html.escape(r.title)}</b></span>{extra}"
                     f"<br>&nbsp;&nbsp;&nbsp;{html.escape(r.message)}"
                     + "".join(f"<br>&nbsp;&nbsp;&nbsp;<span style='color:#888'>{html.escape(d)}</span>" for d in r.details[:8]))

    def _on_done(self, freed: int) -> None:
        self._set_busy(False)
        self._ops_worker = None
        after = sysclean.memory_status()
        b = self._before
        delta_avail = after.available - b.available
        delta_commit = b.commit_total - after.commit_total
        self.log_summary.setText(
            f"<b>Available RAM:</b> {human_size(b.available)} → {human_size(after.available)} "
            f"({'+' if delta_avail >= 0 else '−'}{human_size(abs(delta_avail))})"
            f" &nbsp;·&nbsp; <b>Committed:</b> {human_size(b.commit_total)} → {human_size(after.commit_total)}"
            + (f" ({'−' if delta_commit >= 0 else '+'}{human_size(abs(delta_commit))})" if delta_commit else "")
            + (f" &nbsp;·&nbsp; <b>Freed by steps:</b> ~{human_size(freed)}" if freed else ""))
        self._refresh_status()

    def _trim_selected(self) -> None:
        sel = self._selected_procs()
        if not sel:
            return
        freed = 0
        fails: list[str] = []
        for p in sel:
            r = sysclean.trim_process(p.pid)
            if r.ok:
                freed += r.freed
            else:
                fails.append(f"{p.name}: {r.message}")
        msg = f"Released about {human_size(freed)} of RAM from {len(sel) - len(fails)} program(s)."
        if fails:
            msg += "\n\nNot possible for:\n" + "\n".join(fails[:10])
            if not is_admin():
                msg += "\n\nRestart as Administrator to reach services and other users' programs."
        QMessageBox.information(self, "Trim RAM", msg)
        self._refresh_status()

    def _end_selected(self) -> None:
        sel = [p for p in self._selected_procs() if not sysclean.is_critical(p)]
        if not sel:
            return
        names = "\n".join(f"• {p.name} (PID {p.pid}) - {human_size(p.private)} committed, "
                          f"{human_size(p.gpu_dedicated)} VRAM" for p in sel[:12])
        ans = QMessageBox.warning(
            self, "End program?",
            f"The following will be closed immediately. Unsaved work in them is lost.\n\n{names}\n\nContinue?",
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if ans != QMessageBox.Yes:
            return
        lines = []
        for p in sel:
            r = sysclean.end_process(p.pid, p.name)
            lines.append(("✔ " if r.ok else "✖ ") + r.message)
        QMessageBox.information(self, "End program", "\n".join(lines))
        self._procs = [p for p in self._procs if p.pid not in {q.pid for q in sel}]
        self._fill_processes()
        QTimer.singleShot(800, self._refresh_status)

    # ------------------------------------------------------------------ lifecycle
    def closeEvent(self, ev) -> None:  # noqa: N802
        self._timer.stop()
        if self._ops_worker and self._ops_worker.isRunning():
            self._ops_worker.wait(15000)
        if self._status_worker and self._status_worker.isRunning():
            self._status_worker.wait(3000)
        super().closeEvent(ev)

    def accept(self) -> None:
        self._timer.stop()
        if self._ops_worker and self._ops_worker.isRunning():
            QMessageBox.information(self, "Still working", "Please wait for the current clean-up to finish.")
            self._timer.start()
            return
        super().accept()
