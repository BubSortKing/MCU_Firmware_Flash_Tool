"""MCU Flash Tool — application entry point."""

import sys
import logging

from PySide6.QtWidgets import QApplication

from ui.main_window import MainWindow


def setup_logging() -> None:
    """Configure root logger."""
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def main() -> int:
    """Launch the application."""
    setup_logging()
    logger = logging.getLogger(__name__)
    logger.info("Starting MCU Flash Tool")

    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()

    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
