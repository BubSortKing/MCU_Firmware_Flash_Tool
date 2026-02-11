"""Main application window — integrates all UI widgets and backend layers."""

import logging
from pathlib import Path
from typing import Optional

from PySide6.QtWidgets import (
    QHBoxLayout,
    QMainWindow,
    QMessageBox,
    QVBoxLayout,
    QWidget,
)

from canbus.pcan_driver import PCANDriver, PCANDriverError
from config.settings import CANSettings
from flash.flasher import Flasher, FlashState
from flash.hex_parser import FirmwareImage
from ui.flash_worker import FlashWorker
from ui.widgets import (
    ConnectionPanel,
    FileSelector,
    FlashProgressBar,
    LogViewer,
    StatusIndicator,
)

logger = logging.getLogger(__name__)


class MainWindow(QMainWindow):
    """Main window of the MCU Flash Tool application.

    Layout::

        +------------------------------------------+
        | ConnectionPanel  |  FileSelector          |
        +------------------------------------------+
        | FlashProgressBar                          |
        +------------------------------------------+
        | LogViewer (expanding)                     |
        +------------------------------------------+
        | StatusIndicator (status bar)              |
        +------------------------------------------+
    """

    def __init__(self) -> None:
        super().__init__()
        self._driver: Optional[PCANDriver] = None
        self._firmware: Optional[FirmwareImage] = None
        self._worker: Optional[FlashWorker] = None

        self._setup_ui()
        self._connect_signals()
        self._update_start_button()

        logger.info("MainWindow initialized")

    # ------------------------------------------------------------------
    # UI setup
    # ------------------------------------------------------------------

    def _setup_ui(self) -> None:
        self.setWindowTitle("MCU Flash Tool")
        self.setMinimumSize(1000, 700)

        # Widgets
        self._connection_panel = ConnectionPanel()
        self._file_selector = FileSelector()
        self._progress_bar = FlashProgressBar()
        self._log_viewer = LogViewer()
        self._status_indicator = StatusIndicator()

        # Central layout
        central = QWidget()
        main_layout = QVBoxLayout(central)

        # Top row: connection + file selector side by side
        top_row = QHBoxLayout()
        top_row.addWidget(self._connection_panel)
        top_row.addWidget(self._file_selector)
        main_layout.addLayout(top_row)

        # Middle: progress bar
        main_layout.addWidget(self._progress_bar)

        # Bottom: log viewer (expanding)
        main_layout.addWidget(self._log_viewer, stretch=1)

        self.setCentralWidget(central)

        # Status bar
        self.statusBar().addPermanentWidget(self._status_indicator)

    def _connect_signals(self) -> None:
        # Connection panel
        self._connection_panel.connect_requested.connect(self._on_connect)
        self._connection_panel.disconnect_requested.connect(self._on_disconnect)

        # File selector
        self._file_selector.firmware_loaded.connect(self._on_firmware_loaded)
        self._file_selector.firmware_cleared.connect(self._on_firmware_cleared)

        # Progress bar buttons
        self._progress_bar.start_requested.connect(self._on_start_flash)
        self._progress_bar.abort_requested.connect(self._on_abort_flash)

    # ------------------------------------------------------------------
    # Connection handling
    # ------------------------------------------------------------------

    def _on_connect(self, settings: CANSettings) -> None:
        try:
            self._driver = PCANDriver(settings)
            self._driver.connect()
        except PCANDriverError as exc:
            self._driver = None
            QMessageBox.critical(self, "Connection Error", str(exc))
            self._log_viewer.append_log(f"Connection failed: {exc}")
            return

        self._connection_panel.set_connected_state(True)
        self._status_indicator.set_connected(True)
        self._status_indicator.set_message(f"Connected to {settings.channel}")
        self._progress_bar.reset()
        self._log_viewer.append_log(
            f"Connected to {settings.channel} @ {settings.bitrate} bit/s"
        )
        self._update_start_button()

    def _on_disconnect(self) -> None:
        if self._driver:
            self._driver.disconnect()
            self._driver = None

        self._connection_panel.set_connected_state(False)
        self._status_indicator.set_connected(False)
        self._status_indicator.set_message("Disconnected")
        self._progress_bar.reset()
        self._log_viewer.append_log("Disconnected")
        self._update_start_button()

    # ------------------------------------------------------------------
    # Firmware handling
    # ------------------------------------------------------------------

    def _on_firmware_loaded(self, image: FirmwareImage) -> None:
        self._firmware = image
        self._log_viewer.append_log(
            f"Firmware loaded: {Path(image.file_path).name}, "
            f"{image.total_size:,} bytes"
        )
        self._update_start_button()

    def _on_firmware_cleared(self) -> None:
        self._firmware = None
        self._update_start_button()

    # ------------------------------------------------------------------
    # Flash orchestration
    # ------------------------------------------------------------------

    def _update_start_button(self) -> None:
        """Enable Start Flash only when connected, firmware loaded, and idle."""
        can_start = (
            self._driver is not None
            and self._driver.is_connected
            and self._firmware is not None
            and self._worker is None
        )
        self._progress_bar.set_start_enabled(can_start)

    def _on_start_flash(self) -> None:
        if not self._driver or not self._firmware:
            return

        # Build Flasher
        flasher = Flasher(
            driver=self._driver,
            firmware=self._firmware,
            can_settings=self._driver.settings,
        )

        # Create and wire worker thread
        self._worker = FlashWorker(flasher, parent=self)
        self._worker.progress.connect(self._progress_bar.update_progress)
        self._worker.state_changed.connect(self._progress_bar.update_state)
        self._worker.state_changed.connect(self._status_indicator.set_flash_state)
        self._worker.log_message.connect(self._log_viewer.append_log)
        self._worker.finished_ok.connect(self._on_flash_finished)
        self._worker.finished_error.connect(self._on_flash_error)

        # Lock down UI
        self._connection_panel.set_flashing_state(True)
        self._file_selector.set_enabled_state(False)
        self._progress_bar.set_flashing_state(True)
        self._progress_bar.reset()

        # Go
        self._log_viewer.append_log("=== Flash started ===")
        self._worker.start()

    def _on_abort_flash(self) -> None:
        if self._worker:
            self._worker.abort()
            self._log_viewer.append_log("Abort requested...")

    def _on_flash_finished(self) -> None:
        self._log_viewer.append_log("=== Flash completed successfully ===")
        self._progress_bar.update_progress(100, "Flash Complete!")
        self._status_indicator.set_message("Flash completed successfully")
        self._cleanup_after_flash()

    def _on_flash_error(self, error_msg: str) -> None:
        self._log_viewer.append_log(f"=== Flash failed: {error_msg} ===")
        self._status_indicator.set_message(f"Error: {error_msg}")
        self._cleanup_after_flash()
        QMessageBox.critical(self, "Flash Error", error_msg)

    def _cleanup_after_flash(self) -> None:
        """Re-enable UI after flash completes/fails/aborts."""
        self._worker = None
        self._connection_panel.set_flashing_state(False)
        self._file_selector.set_enabled_state(True)
        self._progress_bar.set_flashing_state(False)
        self._update_start_button()

    # ------------------------------------------------------------------
    # Window close
    # ------------------------------------------------------------------

    def closeEvent(self, event) -> None:
        """Clean up resources on window close."""
        if self._worker and self._worker.isRunning():
            self._worker.abort()
            self._worker.wait(5000)
        if self._driver and self._driver.is_connected:
            self._driver.disconnect()
        event.accept()
