"""FileSelector — firmware file picker with metadata display."""

import logging
from pathlib import Path
from typing import Optional

from PySide6.QtCore import QRegularExpression, QSettings, Signal
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

    _SETTINGS_KEY = "ui/last_browse_dir"

    def __init__(
        self,
        title: str = "Firmware File",
        default_address: int = 0x00040000,
        parent=None,
    ) -> None:
        super().__init__(title, parent)
        self._firmware: Optional[FirmwareImage] = None
        self._is_bin: bool = False
        self._default_address = default_address
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

        # Download address — always shown once a file is loaded
        self._base_addr_label = QLabel("Download Address:")
        self._base_addr_edit = QLineEdit(f"0x{self._default_address:08X}")
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
        current = self._file_path_edit.text()
        if current:
            start_dir = str(Path(current).parent)
        else:
            qs = QSettings("MCUFlashTool", "MCUFlashTool")
            saved = qs.value(FileSelector._SETTINGS_KEY, "", str)
            start_dir = saved if Path(saved).is_dir() else ""
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Firmware File", start_dir, _FILE_FILTER,
        )
        if path:
            qs = QSettings("MCUFlashTool", "MCUFlashTool")
            qs.setValue(FileSelector._SETTINGS_KEY, str(Path(path).parent))
            self._load_file(path)

    def _load_file(self, path: str) -> None:
        ext = Path(path).suffix.lower()
        self._is_bin = (ext == ".bin")

        # Always show the download address field once a file is selected
        self._base_addr_label.setVisible(True)
        self._base_addr_edit.setVisible(True)

        self._file_path_edit.setText(path)
        self._try_parse()

    def _on_base_addr_changed(self) -> None:
        """Handle download address edits.

        For .bin files: re-parse so the segment is placed at the new address.
        For .hex/.s19 files: update download_address on the existing image
        without re-parsing (the firmware data stays at the embedded address).
        """
        if not self._file_path_edit.text():
            return
        if self._is_bin:
            self._try_parse()
        elif self._firmware is not None:
            try:
                addr = self._parse_base_address()
                self._firmware.download_address = addr
                self._update_info(self._firmware)
            except ValueError:
                self._info_label.setText("Error: invalid download address")

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
            if not self._is_bin:
                # Auto-fill the address field from the file's embedded address,
                # without triggering a re-parse
                self._base_addr_edit.blockSignals(True)
                self._base_addr_edit.setText(f"0x{image.start_address:08X}")
                self._base_addr_edit.blockSignals(False)
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

    def reload(self) -> bool:
        """Re-parse the currently selected file from disk.

        Call this just before flashing to ensure the latest on-disk bytes are
        used, even if the file was rebuilt after it was first selected.

        Emits firmware_loaded on success or firmware_cleared on failure.

        Returns:
            True if the file was successfully re-parsed, False otherwise.
        """
        if not self._file_path_edit.text():
            return False
        self._try_parse()
        return self._firmware is not None

    @property
    def firmware(self) -> Optional[FirmwareImage]:
        """Return the currently loaded firmware image, or None."""
        return self._firmware

    def set_enabled_state(self, enabled: bool) -> None:
        """Enable/disable the file selector (during flashing)."""
        self._browse_btn.setEnabled(enabled)
        self._base_addr_edit.setEnabled(enabled)
