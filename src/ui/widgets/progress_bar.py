"""FlashProgressBar — progress display with Start/Abort controls."""

import logging

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
)

from flash.flasher import FlashState

logger = logging.getLogger(__name__)


class FlashProgressBar(QGroupBox):
    """Flash progress bar with state label and Start/Abort buttons.

    Signals:
        start_requested: Emitted when the user clicks "Start Flash".
        abort_requested: Emitted when the user clicks "Abort".
    """

    start_requested = Signal()
    abort_requested = Signal()

    def __init__(self, parent=None) -> None:
        super().__init__("Flash Progress", parent)
        self._setup_ui()

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)

        # Progress bar
        self._progress_bar = QProgressBar()
        self._progress_bar.setRange(0, 100)
        self._progress_bar.setValue(0)
        self._progress_bar.setTextVisible(True)
        self._progress_bar.setFormat("%p%")
        layout.addWidget(self._progress_bar)

        # State label
        self._state_label = QLabel("Ready")
        self._state_label.setAlignment(Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(self._state_label)

        # Buttons
        btn_layout = QHBoxLayout()

        self._start_btn = QPushButton("Start Flash")
        self._start_btn.setEnabled(False)
        self._start_btn.clicked.connect(self.start_requested.emit)
        btn_layout.addWidget(self._start_btn)

        btn_layout.addStretch()

        self._abort_btn = QPushButton("Abort")
        self._abort_btn.setEnabled(False)
        self._abort_btn.clicked.connect(self.abort_requested.emit)
        btn_layout.addWidget(self._abort_btn)

        layout.addLayout(btn_layout)

    # ------------------------------------------------------------------
    # Public slots
    # ------------------------------------------------------------------

    def update_progress(self, percent: int, message: str) -> None:
        """Update the progress bar value and state description."""
        self._progress_bar.setValue(percent)
        self._state_label.setText(message)

    def update_state(self, state: FlashState) -> None:
        """Update the state label from a FlashState enum."""
        _STATE_NAMES = {
            FlashState.IDLE: "Ready",
            FlashState.DONE: "Flash Complete!",
            FlashState.ABORTED: "Aborted",
            FlashState.ERROR: "Error",
        }
        text = _STATE_NAMES.get(state, state.name.replace("_", " ").title())
        self._state_label.setText(text)

    def set_flashing_state(self, flashing: bool) -> None:
        """Toggle button states for flashing / not-flashing."""
        self._start_btn.setEnabled(not flashing)
        self._abort_btn.setEnabled(flashing)

    def set_start_enabled(self, enabled: bool) -> None:
        """Explicitly control the Start button (used by MainWindow)."""
        self._start_btn.setEnabled(enabled)

    def reset(self) -> None:
        """Reset to initial state."""
        self._progress_bar.setValue(0)
        self._state_label.setText("Ready")
