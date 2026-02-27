"""Main application window — integrates all UI widgets and backend layers."""

import logging
from pathlib import Path
from typing import Optional, Union

from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from canbus.pcan_driver import PCANDriver, PCANDriverError
from config.settings import CANSettings
from flash.boot_flasher import BootFlasher
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

_BOOT_PASSWORD = "Gpal7853!"


class MainWindow(QMainWindow):
    """Main window of the MCU Flash Tool application.

    Layout::

        +-----------------------------------------------+
        | ConnectionPanel | QTabWidget                       |
        |                 |  [Flash App] [Flash Config] [Flash Boot] |
        |                 |  (App: C0 + C1 FileSelector)     |
        |                 |  (Config: single FileSelector)   |
        |                 |  (Boot: single FileSelector)     |
        +-----------------------------------------------+
        | FlashProgressBar                               |
        +-----------------------------------------------+
        | LogViewer (expanding)                          |
        +-----------------------------------------------+
        | StatusIndicator (status bar)                   |
        +-----------------------------------------------+
    """

    def __init__(self) -> None:
        super().__init__()
        self._driver:          Optional[PCANDriver]    = None
        self._firmware0:       Optional[FirmwareImage] = None  # Core 0
        self._firmware1:       Optional[FirmwareImage] = None  # Core 1
        self._firmware_config: Optional[FirmwareImage] = None  # Config
        self._firmware_boot:   Optional[FirmwareImage] = None  # Bootloader
        self._worker:          Optional[FlashWorker]   = None
        self._boot_tab_unlocked: bool = False

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

        # Shared widgets
        self._connection_panel = ConnectionPanel()
        self._progress_bar     = FlashProgressBar()
        self._log_viewer       = LogViewer()
        self._status_indicator = StatusIndicator()

        # --- Tab 0: Flash App (Core 0 + Core 1) ---
        self._file_selector_c0 = FileSelector("Core 0 Firmware", default_address=0x00040000)
        self._file_selector_c1 = FileSelector("Core 1 Firmware", default_address=0x00120000)
        app_tab = QWidget()
        app_layout = QVBoxLayout(app_tab)
        app_layout.setContentsMargins(0, 4, 0, 0)
        app_layout.addWidget(self._file_selector_c0)
        app_layout.addWidget(self._file_selector_c1)
        app_layout.addStretch()

        # --- Tab 1: Flash Config (single file, app-layer protocol) ---
        self._config_file_selector = FileSelector("Config Firmware", default_address=0x0026C000)
        config_tab = QWidget()
        config_layout = QVBoxLayout(config_tab)
        config_layout.setContentsMargins(0, 4, 0, 0)
        config_layout.addWidget(self._config_file_selector)
        config_layout.addStretch()

        # --- Tab 2: Flash Bootloader (single file) ---
        self._boot_file_selector = FileSelector("Bootloader Firmware", default_address=0x00010000)
        boot_tab = QWidget()
        boot_layout = QVBoxLayout(boot_tab)
        boot_layout.setContentsMargins(0, 4, 0, 0)
        boot_layout.addWidget(self._boot_file_selector)
        boot_layout.addStretch()

        # Tab widget
        self._boot_tab = boot_tab  # stored for unlock; not added to tab widget at startup

        self._tab_widget = QTabWidget()
        self._tab_widget.addTab(app_tab,    "Flash App")
        self._tab_widget.addTab(config_tab, "Flash Config")

        # Central layout
        central = QWidget()
        main_layout = QVBoxLayout(central)

        # Top row: connection panel + tab widget
        top_row = QHBoxLayout()
        top_row.addWidget(self._connection_panel)
        top_row.addWidget(self._tab_widget, stretch=1)
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

        # Tab switching
        self._tab_widget.currentChanged.connect(self._on_tab_changed)
        self._tab_widget.tabBar().tabBarDoubleClicked.connect(self._on_tab_double_clicked)

        # App tab file selectors
        self._file_selector_c0.firmware_loaded.connect(self._on_firmware0_loaded)
        self._file_selector_c0.firmware_cleared.connect(self._on_firmware0_cleared)
        self._file_selector_c1.firmware_loaded.connect(self._on_firmware1_loaded)
        self._file_selector_c1.firmware_cleared.connect(self._on_firmware1_cleared)

        # Config tab file selector
        self._config_file_selector.firmware_loaded.connect(self._on_config_firmware_loaded)
        self._config_file_selector.firmware_cleared.connect(self._on_config_firmware_cleared)

        # Boot tab file selector
        self._boot_file_selector.firmware_loaded.connect(self._on_boot_firmware_loaded)
        self._boot_file_selector.firmware_cleared.connect(self._on_boot_firmware_cleared)

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
    # Tab handling
    # ------------------------------------------------------------------

    def _on_tab_changed(self, index: int) -> None:
        self._update_start_button()

    def _on_tab_double_clicked(self, index: int) -> None:
        """Unlock the hidden bootloader tab via password dialog with show/hide toggle."""
        if self._boot_tab_unlocked:
            return

        # --- Build custom dialog ---
        dialog = QDialog(self)
        dialog.setWindowTitle("LastResort")
        layout = QVBoxLayout(dialog)

        layout.addWidget(QLabel("Enter password:"))

        row = QHBoxLayout()
        pwd_edit = QLineEdit()
        pwd_edit.setEchoMode(QLineEdit.EchoMode.Password)
        row.addWidget(pwd_edit)

        eye_btn = QPushButton("\U0001F441")   # 👁 eye character
        eye_btn.setCheckable(True)
        eye_btn.setFixedWidth(32)
        eye_btn.setToolTip("Show / hide password")
        eye_btn.toggled.connect(
            lambda checked: pwd_edit.setEchoMode(
                QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password
            )
        )
        row.addWidget(eye_btn)
        layout.addLayout(row)

        # Error hint — hidden until a wrong attempt
        error_label = QLabel("Incorrect password. Please try again.")
        error_label.setStyleSheet("color: red;")
        error_label.hide()
        layout.addWidget(error_label)

        btn_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )

        def _try_accept() -> None:
            if pwd_edit.text() == _BOOT_PASSWORD:
                dialog.accept()
            else:
                error_label.show()
                dialog.adjustSize()
                pwd_edit.clear()
                pwd_edit.setFocus()

        btn_box.accepted.connect(_try_accept)
        btn_box.rejected.connect(dialog.reject)
        layout.addWidget(btn_box)

        # Let Enter key submit the dialog
        pwd_edit.returnPressed.connect(_try_accept)
        # ---

        if dialog.exec() == QDialog.DialogCode.Accepted:
            self._boot_tab_unlocked = True
            self._tab_widget.addTab(self._boot_tab, "LastResort")
            self._tab_widget.setCurrentIndex(self._tab_widget.count() - 1)
            self._log_viewer.append_log("Bootloader tab unlocked.")
            self._update_start_button()

    # ------------------------------------------------------------------
    # Firmware handling — app tab
    # ------------------------------------------------------------------

    def _on_firmware0_loaded(self, image: FirmwareImage) -> None:
        self._firmware0 = image
        self._log_viewer.append_log(
            f"Core0 firmware loaded: {Path(image.file_path).name}, "
            f"{image.total_size:,} bytes"
        )
        self._update_start_button()

    def _on_firmware0_cleared(self) -> None:
        self._firmware0 = None
        self._update_start_button()

    def _on_firmware1_loaded(self, image: FirmwareImage) -> None:
        self._firmware1 = image
        self._log_viewer.append_log(
            f"Core1 firmware loaded: {Path(image.file_path).name}, "
            f"{image.total_size:,} bytes"
        )
        self._update_start_button()

    def _on_firmware1_cleared(self) -> None:
        self._firmware1 = None
        self._update_start_button()

    # ------------------------------------------------------------------
    # Firmware handling — config tab
    # ------------------------------------------------------------------

    def _on_config_firmware_loaded(self, image: FirmwareImage) -> None:
        self._firmware_config = image
        self._log_viewer.append_log(
            f"Config firmware loaded: {Path(image.file_path).name}, "
            f"{image.total_size:,} bytes"
        )
        self._update_start_button()

    def _on_config_firmware_cleared(self) -> None:
        self._firmware_config = None
        self._update_start_button()

    # ------------------------------------------------------------------
    # Firmware handling — boot tab
    # ------------------------------------------------------------------

    def _on_boot_firmware_loaded(self, image: FirmwareImage) -> None:
        self._firmware_boot = image
        self._log_viewer.append_log(
            f"Bootloader firmware loaded: {Path(image.file_path).name}, "
            f"{image.total_size:,} bytes"
        )
        self._update_start_button()

    def _on_boot_firmware_cleared(self) -> None:
        self._firmware_boot = None
        self._update_start_button()

    # ------------------------------------------------------------------
    # Flash orchestration
    # ------------------------------------------------------------------

    def _update_start_button(self) -> None:
        """Enable Start Flash only when prerequisites are met and idle."""
        driver_ok = self._driver is not None and self._driver.is_connected
        idle      = self._worker is None
        tab       = self._tab_widget.currentIndex()

        if tab == 0:    # Flash App
            can_start = (
                driver_ok
                and (self._firmware0 is not None or self._firmware1 is not None)
                and idle
            )
        elif tab == 1:  # Flash Config
            can_start = (
                driver_ok
                and self._firmware_config is not None
                and idle
            )
        else:           # Flash Bootloader
            can_start = (
                driver_ok
                and self._firmware_boot is not None
                and idle
            )

        self._progress_bar.set_start_enabled(can_start)

    def _on_start_flash(self) -> None:
        tab = self._tab_widget.currentIndex()

        if tab == 0:
            if not self._driver or (self._firmware0 is None and self._firmware1 is None):
                return
            # Re-read from disk so the latest build is always flashed
            if self._firmware0 is not None and not self._file_selector_c0.reload():
                QMessageBox.critical(self, "Firmware Error",
                                     "Failed to reload Core 0 firmware from disk.")
                return
            if self._firmware1 is not None and not self._file_selector_c1.reload():
                QMessageBox.critical(self, "Firmware Error",
                                     "Failed to reload Core 1 firmware from disk.")
                return
            flasher: Union[Flasher, BootFlasher] = Flasher(
                driver=self._driver,
                firmware_core0=self._firmware0,
                firmware_core1=self._firmware1,
                can_settings=self._driver.settings,
            )
            if self._firmware0 and self._firmware1:
                start_msg = "=== Dual-core app flash started ==="
            elif self._firmware0:
                start_msg = "=== Core0-only flash started ==="
            else:
                start_msg = "=== Core1-only flash started ==="
        elif tab == 1:
            if not self._driver or not self._firmware_config:
                return
            if not self._config_file_selector.reload():
                QMessageBox.critical(self, "Firmware Error",
                                     "Failed to reload config firmware from disk.")
                return
            flasher = Flasher(
                driver=self._driver,
                firmware_core0=self._firmware_config,
                firmware_core1=None,
                can_settings=self._driver.settings,
            )
            start_msg = "=== Config flash started ==="
        else:
            if not self._driver or not self._firmware_boot:
                return
            if not self._boot_file_selector.reload():
                QMessageBox.critical(self, "Firmware Error",
                                     "Failed to reload bootloader firmware from disk.")
                return
            flasher = BootFlasher(
                driver=self._driver,
                firmware=self._firmware_boot,
                can_settings=self._driver.settings,
            )
            start_msg = "=== Bootloader flash started ==="

        # Create and wire worker thread
        self._worker = FlashWorker(flasher, parent=self)
        self._worker.progress.connect(self._progress_bar.update_progress)
        self._worker.state_changed.connect(self._progress_bar.update_state)
        self._worker.state_changed.connect(self._status_indicator.set_flash_state)
        self._worker.log_message.connect(self._log_viewer.append_log)
        self._worker.finished_ok.connect(self._on_flash_finished)
        self._worker.finished_error.connect(self._on_flash_error)

        # Lock down UI (disable tab switching during flash)
        self._tab_widget.setEnabled(False)
        self._connection_panel.set_flashing_state(True)
        self._file_selector_c0.set_enabled_state(False)
        self._file_selector_c1.set_enabled_state(False)
        self._config_file_selector.set_enabled_state(False)
        self._boot_file_selector.set_enabled_state(False)
        self._progress_bar.set_flashing_state(True)
        self._progress_bar.reset()

        self._log_viewer.append_log(start_msg)
        self._worker.start()

    def _on_abort_flash(self) -> None:
        if self._worker:
            self._worker.abort()
            self._log_viewer.append_log("Abort requested...")

    def _on_flash_finished(self) -> None:
        tab = self._tab_widget.currentIndex()
        if tab == 0:
            msg = "=== App flash completed successfully ==="
        elif tab == 1:
            msg = "=== Config flash completed successfully ==="
        else:
            msg = "=== Bootloader flash completed successfully ==="
        self._log_viewer.append_log(msg)
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
        self._tab_widget.setEnabled(True)
        self._connection_panel.set_flashing_state(False)
        self._file_selector_c0.set_enabled_state(True)
        self._file_selector_c1.set_enabled_state(True)
        self._config_file_selector.set_enabled_state(True)
        self._boot_file_selector.set_enabled_state(True)
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
