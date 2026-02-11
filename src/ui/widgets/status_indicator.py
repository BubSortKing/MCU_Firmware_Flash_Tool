"""StatusIndicator — compact connection/flash status for the status bar."""

import logging

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel, QWidget

from flash.flasher import FlashState

logger = logging.getLogger(__name__)


class StatusIndicator(QWidget):
    """Compact status widget designed for QMainWindow.statusBar().

    Shows three pieces of information separated by vertical lines:
    connection state, flash state, and a free-form message.
    """

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._setup_ui()
        self.set_connected(False)
        self.set_flash_state(FlashState.IDLE)

    def _setup_ui(self) -> None:
        layout = QHBoxLayout(self)
        layout.setContentsMargins(4, 0, 4, 0)

        # Connection status
        self._conn_icon = QLabel()
        self._conn_label = QLabel()
        layout.addWidget(self._conn_icon)
        layout.addWidget(self._conn_label)

        layout.addWidget(self._make_separator())

        # Flash state
        self._flash_state_label = QLabel()
        layout.addWidget(self._flash_state_label)

        layout.addWidget(self._make_separator())

        # Free-form message
        self._message_label = QLabel("Ready")
        layout.addWidget(self._message_label)

    @staticmethod
    def _make_separator() -> QFrame:
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.VLine)
        sep.setFrameShadow(QFrame.Shadow.Sunken)
        return sep

    # ------------------------------------------------------------------
    # Public slots
    # ------------------------------------------------------------------

    def set_connected(self, connected: bool) -> None:
        """Update the connection indicator."""
        if connected:
            self._conn_icon.setText("\u25CF")  # filled circle
            self._conn_icon.setStyleSheet("color: green;")
            self._conn_label.setText("Connected")
            self._conn_label.setStyleSheet("color: green; font-weight: bold;")
        else:
            self._conn_icon.setText("\u25CB")  # empty circle
            self._conn_icon.setStyleSheet("color: red;")
            self._conn_label.setText("Disconnected")
            self._conn_label.setStyleSheet("color: red; font-weight: bold;")

    def set_flash_state(self, state: FlashState) -> None:
        """Update the flash state label with colour coding."""
        text = state.name.replace("_", " ").title()
        self._flash_state_label.setText(text)

        color_map = {
            FlashState.IDLE: "gray",
            FlashState.DONE: "green",
            FlashState.ERROR: "red",
            FlashState.ABORTED: "orange",
        }
        color = color_map.get(state, "#0078D4")  # blue for active steps
        self._flash_state_label.setStyleSheet(
            f"color: {color}; font-weight: bold;"
        )

    def set_message(self, text: str) -> None:
        """Update the free-form message."""
        self._message_label.setText(text)
