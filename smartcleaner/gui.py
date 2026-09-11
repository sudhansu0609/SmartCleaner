"""The PySide6 window: created only when SmartCleaner runs with a display.

Split out of ``__main__`` so ``python -m smartcleaner --headless`` never imports Qt.
"""
from __future__ import annotations

import sys

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QApplication

from . import APP_NAME
from .ui.main_window import MainWindow

STYLE = """
QToolBar { spacing: 6px; padding: 4px; }
QTreeWidget { font-size: 10pt; }
QTreeWidget::item { height: 22px; }
QPushButton { padding: 6px 12px; border-radius: 4px; }
QPushButton#primary { background: #2e7d32; color: white; font-weight: 600; }
QPushButton#primary:hover { background: #388e3c; }
QPushButton#primary:disabled { background: #37474f; color: #90a4ae; }
QPushButton#danger { background: #7f1d1d; color: white; }
QPushButton#danger:hover { background: #991b1b; }
QPushButton#danger:disabled { background: #37474f; color: #90a4ae; }
QGroupBox { font-weight: 600; margin-top: 10px; }
QGroupBox::title { subcontrol-origin: margin; left: 8px; padding: 0 4px; }
QProgressBar { text-align: center; }
"""


def dark_palette() -> QPalette:
    p = QPalette()
    bg, base, alt, text, hi = QColor("#1e1f22"), QColor("#26282b"), QColor("#2b2d31"), QColor("#e6e6e6"), QColor("#3d7bd9")
    p.setColor(QPalette.Window, bg)
    p.setColor(QPalette.WindowText, text)
    p.setColor(QPalette.Base, base)
    p.setColor(QPalette.AlternateBase, alt)
    p.setColor(QPalette.ToolTipBase, QColor("#333"))
    p.setColor(QPalette.ToolTipText, text)
    p.setColor(QPalette.Text, text)
    p.setColor(QPalette.Button, QColor("#2f3136"))
    p.setColor(QPalette.ButtonText, text)
    p.setColor(QPalette.BrightText, Qt.red)
    p.setColor(QPalette.Highlight, hi)
    p.setColor(QPalette.HighlightedText, Qt.white)
    p.setColor(QPalette.Link, QColor("#64b5f6"))
    p.setColor(QPalette.PlaceholderText, QColor("#888"))
    for role in (QPalette.WindowText, QPalette.Text, QPalette.ButtonText):
        p.setColor(QPalette.Disabled, role, QColor("#7a7a7a"))
    return p


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setStyle("Fusion")
    app.setPalette(dark_palette())
    app.setStyleSheet(STYLE)
    win = MainWindow()
    win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
