"""FileSelector — firmware file picker with metadata display."""

import logging
from pathlib import Path
from typing import Optional

from PySide6.QtCore import QRegularExpression, Signal
from PySide6.QtGui import QRegularExpressionValidator
from PySide6.QtWidgets import (
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
)

from flash.hex_parser import FirmwareImage, FirmwareParseError, FirmwareParser

logger = logging.getLogger(__name__)

# Hex validator for base address: optional 0x prefix + 1-8 hex digits
_HEX_ADDR_PATTERN = QRegularExpression(r"^(0[xX])?[0-9A-Fa-f]{1,8}$")

_FILE_FILTER = "Firmware Files (*.hex *.ihex *.s19 *.srec *.s *.bin);;All Files (*)"


class FileSelector(QGroupBox):
    """Firmware file picker with automatic parsing and info display.

    Signals:
        firmware_loaded: Emitted with the FirmwareImage on successful parse.
        firmware_cleared: Emitted when the file is cleared or parse fails.
    """

    firmware_loaded = Signal(object)    # FirmwareImage
    firmware_cleared = Signal()

    def __init__(self, parent=None) -> None:
        super().__init__("Firmware File", parent)
        self._firmware: Optional[FirmwareImage] = None
        self._setup_ui()

    def _setup_ui(self) -> None:
        form = QFormLayout(self)

        # File path row
        file_row = QHBoxLayout()
        self._file_path_edit = QLineEdit()
        self._file_path_edit.setReadOnly(True)
        self._file_path_edit.setPlaceholderText("Select firmware file...")
        file_row.addWidget(self._file_path_edit)

        self._browse_btn = QPushButton("Browse...")
        self._browse_btn.clicked.connect(self._on_browse)
        file_row.addWidget(self._browse_btn)

        form.addRow("File:", file_row)

        # Base address (visible only for .bin files)
        self._base_addr_label = QLabel("Base Address:")
        self._base_addr_edit = QLineEdit("0x00040000")
        self._base_addr_edit.setValidator(
            QRegularExpressionValidator(_HEX_ADDR_PATTERN)
        )
        self._base_addr_edit.textChanged.connect(self._on_base_addr_changed)
        form.addRow(self._base_addr_label, self._base_addr_edit)
        self._base_addr_label.setVisible(False)
        self._base_addr_edit.setVisible(False)

        # Info display
        self._info_label = QLabel()
        self._info_label.setWordWrap(True)
        form.addRow("Info:", self._info_label)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _on_browse(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Firmware File", "", _FILE_FILTER,
        )
        if path:
            self._load_file(path)

    def _load_file(self, path: str) -> None:
        ext = Path(path).suffix.lower()

        # Show/hide base address for .bin files
        is_bin = ext == ".bin"
        self._base_addr_label.setVisible(is_bin)
        self._base_addr_edit.setVisible(is_bin)

        self._file_path_edit.setText(path)
        self._try_parse()

    def _on_base_addr_changed(self) -> None:
        """Re-parse when the base address changes (for .bin files)."""
        if self._file_path_edit.text():
            self._try_parse()

    def _parse_base_address(self) -> int:
        text = self._base_addr_edit.text().strip().replace("0x", "").replace("0X", "")
        if not text:
            return 0
        return int(text, 16)

    def _try_parse(self) -> None:
        """Parse the selected firmware file and update the info label."""
        path = self._file_path_edit.text()
        if not path:
            return

        ext = Path(path).suffix.lower()
        base_addr = 0
        if ext == ".bin":
            try:
                base_addr = self._parse_base_address()
            except ValueError:
                self._info_label.setText("Error: invalid base address")
                self._firmware = None
                self.firmware_cleared.emit()
                return

        parser = FirmwareParser()
        try:
            image = parser.parse(path, base_address=base_addr)
            self._firmware = image
            self._update_info(image)
            self.firmware_loaded.emit(image)
        except FirmwareParseError as exc:
            self._firmware = None
            self._info_label.setText(f"Error: {exc}")
            self.firmware_cleared.emit()

    def _update_info(self, image: FirmwareImage) -> None:
        lines = [
            f"Format: {Path(image.file_path).suffix.upper()}",
            f"Segments: {len(image.segments)}",
            f"Address: 0x{image.start_address:08X} .. 0x{image.end_address:08X}",
            f"Size: {image.total_size:,} bytes",
            f"CRC32: 0x{image.crc32():08X}",
        ]
        self._info_label.setText("\n".join(lines))

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    @property
    def firmware(self) -> Optional[FirmwareImage]:
        """Return the currently loaded firmware image, or None."""
        return self._firmware

    def set_enabled_state(self, enabled: bool) -> None:
        """Enable/disable the file selector (during flashing)."""
        self._browse_btn.setEnabled(enabled)
        self._base_addr_edit.setEnabled(enabled)
