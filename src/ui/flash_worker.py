"""FlashWorker — runs Flasher.execute() in a QThread with Qt signal bridging."""

import logging
from typing import Union

from PySide6.QtCore import QThread, Signal

from flash.boot_flasher import BootFlasher
from flash.flasher import Flasher, FlashError

logger = logging.getLogger(__name__)


class FlashWorker(QThread):
    """Background thread that executes the flash workflow.

    Bridges the three Flasher callbacks (on_progress, on_state_changed,
    on_log) to Qt signals so that the UI can update safely from the
    main thread.

    Usage::

        worker = FlashWorker(flasher)
        worker.progress.connect(on_progress_slot)
        worker.log_message.connect(on_log_slot)
        worker.start()
    """

    progress = Signal(int, str)        # (percent, message)
    state_changed = Signal(object)     # FlashState enum value
    log_message = Signal(str)          # log text line
    finished_ok = Signal()             # flash completed successfully
    finished_error = Signal(str)       # flash failed with error message

    def __init__(self, flasher: Union[Flasher, BootFlasher], parent=None) -> None:
        super().__init__(parent)
        self._flasher = flasher

    def run(self) -> None:
        """Execute the flash sequence (called by QThread.start)."""
        self._flasher.on_progress = self.progress.emit
        self._flasher.on_state_changed = self.state_changed.emit
        self._flasher.on_log = self.log_message.emit

        try:
            self._flasher.execute()
            self.finished_ok.emit()
        except FlashError as exc:
            logger.error("Flash failed: %s", exc)
            self.finished_error.emit(str(exc))
        except Exception as exc:
            logger.exception("Unexpected error during flash")
            self.finished_error.emit(f"Unexpected error: {exc}")

    def abort(self) -> None:
        """Request the flasher to abort at the next safe point."""
        self._flasher.abort()
