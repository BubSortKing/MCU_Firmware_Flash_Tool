"""LogViewer — real-time scrolling log display."""

import datetime
import logging

from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QCheckBox,
    QGroupBox,
    QHBoxLayout,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
)

logger = logging.getLogger(__name__)


class LogViewer(QGroupBox):
    """Read-only, timestamped log viewer with auto-scroll.

    Uses QPlainTextEdit for performance — it does not parse rich text,
    making it suitable for high-throughput logging during TransferData.
    """

    def __init__(self, parent=None) -> None:
        super().__init__("Log", parent)
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)

        # Log text area
        self._log_area = QPlainTextEdit()
        self._log_area.setReadOnly(True)
        self._log_area.setMaximumBlockCount(5000)
        self._log_area.setFont(QFont("Consolas", 9))
        layout.addWidget(self._log_area)

        # Bottom toolbar
        toolbar = QHBoxLayout()

        self._clear_btn = QPushButton("Clear")
        self._clear_btn.clicked.connect(self._log_area.clear)
        toolbar.addWidget(self._clear_btn)

        toolbar.addStretch()

        self._auto_scroll_cb = QCheckBox("Auto-scroll")
        self._auto_scroll_cb.setChecked(True)
        toolbar.addWidget(self._auto_scroll_cb)

        layout.addLayout(toolbar)

    # ------------------------------------------------------------------
    # Public slot
    # ------------------------------------------------------------------

    def append_log(self, message: str) -> None:
        """Append a timestamped line to the log."""
        timestamp = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        self._log_area.appendPlainText(f"[{timestamp}] {message}")

        if self._auto_scroll_cb.isChecked():
            scrollbar = self._log_area.verticalScrollBar()
            scrollbar.setValue(scrollbar.maximum())
