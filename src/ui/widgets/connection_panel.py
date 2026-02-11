"""ConnectionPanel — CAN bus connection settings and connect/disconnect."""

import logging

from PySide6.QtCore import QRegularExpression, Signal
from PySide6.QtGui import QRegularExpressionValidator
from PySide6.QtWidgets import (
    QComboBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLineEdit,
    QMessageBox,
    QPushButton,
)

from config.settings import CANSettings

logger = logging.getLogger(__name__)

# Hex validator: optional 0x prefix + 1-3 hex digits
_HEX_ID_PATTERN = QRegularExpression(r"^(0[xX])?[0-9A-Fa-f]{1,3}$")


class ConnectionPanel(QGroupBox):
    """CAN connection configuration panel.

    Signals:
        connect_requested: Emitted with a populated CANSettings when
            the user clicks Connect.
        disconnect_requested: Emitted when the user clicks Disconnect.
    """

    connect_requested = Signal(object)     # CANSettings
    disconnect_requested = Signal()

    def __init__(self, parent=None) -> None:
        super().__init__("CAN Connection", parent)
        self._defaults = CANSettings()
        self._setup_ui()

    def _setup_ui(self) -> None:
        form = QFormLayout(self)

        # Channel
        self._channel_combo = QComboBox()
        self._channel_combo.addItems(self._defaults.PCAN_CHANNELS)
        self._channel_combo.setCurrentText(self._defaults.channel)
        form.addRow("Channel:", self._channel_combo)

        # Arbitration bitrate
        self._bitrate_combo = QComboBox()
        self._bitrate_combo.addItems(list(self._defaults.BITRATES.keys()))
        self._bitrate_combo.setCurrentText("500 kbit/s")
        form.addRow("Bitrate:", self._bitrate_combo)

        # Data bitrate (CAN FD)
        self._data_bitrate_combo = QComboBox()
        self._data_bitrate_combo.addItems(list(self._defaults.DATA_BITRATES.keys()))
        self._data_bitrate_combo.setCurrentText("2 Mbit/s")
        form.addRow("Data Bitrate:", self._data_bitrate_combo)

        # TX ID
        hex_validator = QRegularExpressionValidator(_HEX_ID_PATTERN)
        self._tx_id_edit = QLineEdit(f"0x{self._defaults.tx_id:03X}")
        self._tx_id_edit.setValidator(hex_validator)
        form.addRow("TX ID:", self._tx_id_edit)

        # RX ID
        self._rx_id_edit = QLineEdit(f"0x{self._defaults.rx_id:03X}")
        self._rx_id_edit.setValidator(QRegularExpressionValidator(_HEX_ID_PATTERN))
        form.addRow("RX ID:", self._rx_id_edit)

        # Buttons
        btn_layout = QHBoxLayout()
        self._connect_btn = QPushButton("Connect")
        self._connect_btn.clicked.connect(self._on_connect_clicked)
        btn_layout.addWidget(self._connect_btn)

        self._disconnect_btn = QPushButton("Disconnect")
        self._disconnect_btn.setEnabled(False)
        self._disconnect_btn.clicked.connect(self.disconnect_requested.emit)
        btn_layout.addWidget(self._disconnect_btn)

        form.addRow(btn_layout)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_hex_id(text: str) -> int:
        """Parse '7A2' or '0x7A2' to int, validating 11-bit CAN ID range."""
        cleaned = text.strip().replace("0x", "").replace("0X", "")
        if not cleaned:
            raise ValueError("CAN ID is empty")
        value = int(cleaned, 16)
        if not 0x000 <= value <= 0x7FF:
            raise ValueError(f"CAN ID 0x{value:03X} out of range (0x000-0x7FF)")
        return value

    def _build_settings(self) -> CANSettings:
        """Read widget values and build a CANSettings dataclass."""
        settings = CANSettings()
        settings.channel = self._channel_combo.currentText()
        settings.bitrate = self._defaults.BITRATES[self._bitrate_combo.currentText()]
        settings.data_bitrate = self._defaults.DATA_BITRATES[self._data_bitrate_combo.currentText()]
        settings.tx_id = self._parse_hex_id(self._tx_id_edit.text())
        settings.rx_id = self._parse_hex_id(self._rx_id_edit.text())
        return settings

    def _on_connect_clicked(self) -> None:
        try:
            settings = self._build_settings()
        except (ValueError, KeyError) as exc:
            QMessageBox.warning(self, "Invalid Settings", str(exc))
            return
        self.connect_requested.emit(settings)

    # ------------------------------------------------------------------
    # Public state management
    # ------------------------------------------------------------------

    def set_connected_state(self, connected: bool) -> None:
        """Enable/disable widgets based on connection state."""
        self._connect_btn.setEnabled(not connected)
        self._disconnect_btn.setEnabled(connected)
        for widget in (
            self._channel_combo,
            self._bitrate_combo,
            self._data_bitrate_combo,
            self._tx_id_edit,
            self._rx_id_edit,
        ):
            widget.setEnabled(not connected)

    def set_flashing_state(self, flashing: bool) -> None:
        """During flashing, disable all controls including disconnect."""
        for widget in (
            self._connect_btn,
            self._disconnect_btn,
            self._channel_combo,
            self._bitrate_combo,
            self._data_bitrate_combo,
            self._tx_id_edit,
            self._rx_id_edit,
        ):
            widget.setEnabled(False)
        if not flashing:
            # Restore to connected state (still connected after flash)
            self.set_connected_state(True)
