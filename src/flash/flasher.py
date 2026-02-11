"""Flash workflow controller — orchestrates the 14-step OEM flash sequence.

Manages the complete firmware flashing process from session entry to ECU
reset, with abort support and progress reporting via callbacks.

The Flasher is designed to run in a worker thread (QThread) so that the
GUI remains responsive.  Progress and status updates are delivered through
callback functions that the caller provides (typically connected to Qt
signals).

Usage::

    flasher = Flasher(driver, firmware_image)
    flasher.on_progress = lambda pct, msg: print(f"{pct}% {msg}")
    flasher.on_log = lambda msg: print(msg)
    flasher.execute()
"""

import logging
import struct
import time
from enum import Enum, auto
from typing import Callable, Optional

from canbus.pcan_driver import PCANDriver
from canbus.transport import IsoTpTransport
from config.constants import (
    DEFAULT_RX_ID,
    DEFAULT_TX_ID,
    DiagnosticSession,
    ECUResetType,
    ROUTINE_CRC_CHECKSUM,
    ROUTINE_CHECK_DEPENDENCIES,
    ROUTINE_ERASE_MEMORY,
    ROUTINE_PRE_PROGRAMMING_CHECK,
    RoutineControlType,
)
from config.settings import CANSettings, FlashSettings, IsoTpSettings, UDSSettings
from flash.hex_parser import FirmwareImage
from uds.security import SecurityManager
from uds.services import UDSClient, UDSError

logger = logging.getLogger(__name__)


# =============================================================================
# Flash state and exceptions
# =============================================================================


class FlashState(Enum):
    """Current state of the flash workflow."""
    IDLE = auto()
    EXTENDED_SESSION = auto()
    SECURITY_UNLOCK_EXTENDED = auto()
    PRE_PROGRAMMING_CHECK = auto()
    PROGRAMMING_SESSION = auto()
    SECURITY_UNLOCK_PROGRAMMING = auto()
    ERASING = auto()
    REQUESTING_DOWNLOAD = auto()
    TRANSFERRING = auto()
    TRANSFER_EXIT = auto()
    CHECKSUM = auto()
    CHECK_DEPENDENCIES = auto()
    ECU_RESET = auto()
    DONE = auto()
    ABORTED = auto()
    ERROR = auto()


class FlashError(Exception):
    """Raised when the flash workflow encounters an unrecoverable error."""


# Step descriptions for progress reporting
_STEP_DESCRIPTIONS = {
    FlashState.EXTENDED_SESSION: "Entering extended session",
    FlashState.SECURITY_UNLOCK_EXTENDED: "Security unlock (extended)",
    FlashState.PRE_PROGRAMMING_CHECK: "Pre-programming check",
    FlashState.PROGRAMMING_SESSION: "Switching to programming session",
    FlashState.SECURITY_UNLOCK_PROGRAMMING: "Security unlock (programming)",
    FlashState.ERASING: "Erasing flash memory",
    FlashState.REQUESTING_DOWNLOAD: "Requesting download",
    FlashState.TRANSFERRING: "Transferring firmware data",
    FlashState.TRANSFER_EXIT: "Completing transfer",
    FlashState.CHECKSUM: "Verifying checksum",
    FlashState.CHECK_DEPENDENCIES: "Checking dependencies",
    FlashState.ECU_RESET: "Resetting ECU",
}

# Approximate time-based weights for each step.
# TransferData dominates real wall-clock time; erase and checksum are
# a few seconds each; all other steps are near-instant UDS exchanges.
_STEP_WEIGHTS = {
    FlashState.EXTENDED_SESSION: 1,
    FlashState.SECURITY_UNLOCK_EXTENDED: 1,
    FlashState.PRE_PROGRAMMING_CHECK: 1,
    FlashState.PROGRAMMING_SESSION: 1,
    FlashState.SECURITY_UNLOCK_PROGRAMMING: 1,
    FlashState.ERASING: 8,
    FlashState.REQUESTING_DOWNLOAD: 1,
    FlashState.TRANSFERRING: 70,
    FlashState.TRANSFER_EXIT: 1,
    FlashState.CHECKSUM: 8,
    FlashState.CHECK_DEPENDENCIES: 1,
    FlashState.ECU_RESET: 1,
}


class Flasher:
    """Orchestrate the OEM 14-step flash sequence.

    Args:
        driver:   An open PCANDriver instance.
        firmware: A parsed FirmwareImage to flash.
        can_settings:   CAN bus configuration.
        flash_settings: Flash parameters.
        uds_settings:   UDS timing parameters.
        isotp_settings: ISO-TP transport parameters.
    """

    def __init__(
        self,
        driver: PCANDriver,
        firmware: FirmwareImage,
        can_settings: Optional[CANSettings] = None,
        flash_settings: Optional[FlashSettings] = None,
        uds_settings: Optional[UDSSettings] = None,
        isotp_settings: Optional[IsoTpSettings] = None,
    ) -> None:
        self._driver = driver
        self._firmware = firmware
        self._can = can_settings or CANSettings()
        self._flash = flash_settings or FlashSettings()
        self._uds_settings = uds_settings or UDSSettings()
        self._isotp_settings = isotp_settings or IsoTpSettings()

        self._state = FlashState.IDLE
        self._abort_requested = False

        # Build transport and UDS client
        self._transport = IsoTpTransport(
            driver,
            tx_id=self._can.tx_id,
            rx_id=self._can.rx_id,
            settings=self._isotp_settings,
        )
        self._uds = UDSClient(self._transport, self._uds_settings)
        self._security = SecurityManager()

        # Callbacks — set by the caller (e.g. GUI worker)
        self.on_progress: Optional[Callable[[int, str], None]] = None
        self.on_state_changed: Optional[Callable[[FlashState], None]] = None
        self.on_log: Optional[Callable[[str], None]] = None

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def state(self) -> FlashState:
        return self._state

    @property
    def firmware(self) -> FirmwareImage:
        return self._firmware

    # ------------------------------------------------------------------
    # Abort
    # ------------------------------------------------------------------

    def abort(self) -> None:
        """Request the flash process to abort at the next safe point."""
        self._abort_requested = True
        self._log("Abort requested")

    def _check_abort(self) -> None:
        """Raise FlashError if abort was requested."""
        if self._abort_requested:
            self._set_state(FlashState.ABORTED)
            raise FlashError("Flash aborted by user")

    # ------------------------------------------------------------------
    # Progress / logging helpers
    # ------------------------------------------------------------------

    def _set_state(self, state: FlashState) -> None:
        self._state = state
        if self.on_state_changed:
            self.on_state_changed(state)

    def _progress(self, percent: int, message: str) -> None:
        logger.info("Flash %d%%: %s", percent, message)
        if self.on_progress:
            self.on_progress(percent, message)

    def _log(self, message: str) -> None:
        logger.info("Flash: %s", message)
        if self.on_log:
            self.on_log(message)

    # ------------------------------------------------------------------
    # Main execution
    # ------------------------------------------------------------------

    def execute(self) -> None:
        """Run the complete 14-step flash sequence.

        Raises:
            FlashError: On abort, UDS failure, or any unrecoverable error.
        """
        self._abort_requested = False

        steps = [
            (FlashState.EXTENDED_SESSION, self._step_extended_session),
            (FlashState.SECURITY_UNLOCK_EXTENDED, self._step_security_extended),
            (FlashState.PRE_PROGRAMMING_CHECK, self._step_pre_check),
            (FlashState.PROGRAMMING_SESSION, self._step_programming_session),
            (FlashState.SECURITY_UNLOCK_PROGRAMMING, self._step_security_programming),
            (FlashState.ERASING, self._step_erase),
            (FlashState.REQUESTING_DOWNLOAD, self._step_request_download),
            (FlashState.TRANSFERRING, self._step_transfer_data),
            (FlashState.TRANSFER_EXIT, self._step_transfer_exit),
            (FlashState.CHECKSUM, self._step_checksum),
            (FlashState.CHECK_DEPENDENCIES, self._step_check_dependencies),
            (FlashState.ECU_RESET, self._step_ecu_reset),
        ]

        # Build cumulative progress ranges from weights.
        # Each step occupies [start_pct, end_pct) within 0-99%.
        total_weight = sum(_STEP_WEIGHTS[s] for s, _ in steps)
        cumulative = 0.0
        step_ranges: list[tuple[int, int]] = []
        for state, _ in steps:
            w = _STEP_WEIGHTS[state]
            start_pct = int(cumulative / total_weight * 99)
            cumulative += w
            end_pct = int(cumulative / total_weight * 99)
            step_ranges.append((start_pct, end_pct))

        try:
            for (state, step_func), (start_pct, end_pct) in zip(steps, step_ranges):
                self._check_abort()
                self._set_state(state)
                desc = _STEP_DESCRIPTIONS.get(state, state.name)
                if state == FlashState.TRANSFERRING:
                    # Transfer step reports its own per-block progress
                    self._transfer_pct_range = (start_pct, end_pct)
                else:
                    self._progress(start_pct, desc)
                step_func()

            self._set_state(FlashState.DONE)
            self._progress(100, "Flash complete")

        except FlashError:
            raise
        except UDSError as exc:
            self._set_state(FlashState.ERROR)
            raise FlashError(f"UDS error: {exc}") from exc
        except Exception as exc:
            self._set_state(FlashState.ERROR)
            raise FlashError(f"Unexpected error: {exc}") from exc

    # ------------------------------------------------------------------
    # Individual steps
    # ------------------------------------------------------------------

    def _step_extended_session(self) -> None:
        """Step 1: Enter extended diagnostic session."""
        resp = self._uds.diagnostic_session_control(DiagnosticSession.EXTENDED)
        self._log(
            f"Extended session active (P2={resp.p2_timeout_ms}ms, "
            f"P2*={resp.p2_star_timeout_ms}ms)"
        )

    def _step_security_extended(self) -> None:
        """Steps 2-3: Security access for extended session (Level 1/2)."""
        seed = self._uds.security_access_request_seed(0x01)
        if seed == b"\x00" * len(seed):
            self._log("Security already unlocked (zero seed)")
            return
        key = self._security.compute_key(seed, 0x01)
        self._uds.security_access_send_key(0x02, key)
        self._log("Extended session security unlocked")

    def _step_pre_check(self) -> None:
        """Step 4: Pre-programming condition check."""
        self._uds.routine_control(
            RoutineControlType.START,
            ROUTINE_PRE_PROGRAMMING_CHECK,
        )
        self._log("Pre-programming check passed")

    def _step_programming_session(self) -> None:
        """Step 5: Switch to programming session."""
        resp = self._uds.diagnostic_session_control(DiagnosticSession.PROGRAMMING)
        self._log(
            f"Programming session active (P2={resp.p2_timeout_ms}ms, "
            f"P2*={resp.p2_star_timeout_ms}ms)"
        )
        # ECU needs time to reconfigure after session transition
        time.sleep(0.1)

    def _step_security_programming(self) -> None:
        """Steps 6-7: Security access for programming session (Level 3/4)."""
        seed = self._uds.security_access_request_seed(0x03)
        if seed == b"\x00" * len(seed):
            self._log("Programming security already unlocked (zero seed)")
            return
        key = self._security.compute_key(seed, 0x03)
        self._uds.security_access_send_key(0x04, key)
        self._log("Programming session security unlocked")

    def _step_erase(self) -> None:
        """Step 8: Erase flash memory."""
        fmt = self._flash.address_length_format
        addr_len = fmt & 0x0F
        size_len = (fmt >> 4) & 0x0F

        option_record = (
            bytes([fmt])
            + self._firmware.start_address.to_bytes(addr_len, "big")
            + self._firmware.total_size.to_bytes(size_len, "big")
        )

        self._log(
            f"Erasing 0x{self._firmware.start_address:08X}..+"
            f"0x{self._firmware.total_size:X}"
        )
        self._uds.routine_control(
            RoutineControlType.START,
            ROUTINE_ERASE_MEMORY,
            option_record,
        )
        self._log("Erase complete")

    def _step_request_download(self) -> None:
        """Step 9: Request download."""
        resp = self._uds.request_download(
            memory_address=self._firmware.start_address,
            memory_size=self._firmware.total_size,
            data_format=self._flash.data_format,
            address_length_format=self._flash.address_length_format,
        )
        # ECU-reported max block length = max data bytes per TransferData
        # (does NOT include SID + blockSequenceCounter)
        self._max_data_per_block = resp.max_block_length
        self._log(
            f"Download accepted, max data per block={self._max_data_per_block} bytes"
        )

    def _step_transfer_data(self) -> None:
        """Step 10: Transfer firmware data block by block."""
        total_size = self._firmware.total_size
        blocks = list(self._firmware.iter_blocks(self._max_data_per_block))
        total_blocks = len(blocks)
        block_counter = 1  # starts at 1, wraps 0x00-0xFF

        self._log(f"Transferring {total_size} bytes in {total_blocks} blocks")

        pct_start, pct_end = self._transfer_pct_range
        bytes_sent = 0
        for i, block_data in enumerate(blocks):
            self._check_abort()

            self._uds.transfer_data(block_counter, block_data)

            bytes_sent += len(block_data)
            block_counter = (block_counter + 1) & 0xFF

            # Interpolate within the weighted range for this step
            transfer_pct = pct_start + int(
                (bytes_sent / total_size) * (pct_end - pct_start)
            )
            self._progress(
                transfer_pct,
                f"Transferring: {bytes_sent}/{total_size} bytes "
                f"(block {i + 1}/{total_blocks})",
            )

        self._log(f"Transfer complete: {bytes_sent} bytes in {total_blocks} blocks")

    def _step_transfer_exit(self) -> None:
        """Step 11: Request transfer exit."""
        self._uds.request_transfer_exit()
        self._log("Transfer exit acknowledged")

    def _step_checksum(self) -> None:
        """Step 12: CRC/checksum verification."""
        crc = self._firmware.crc32()
        crc_bytes = struct.pack(">I", crc)

        self._log(f"Requesting checksum verification (CRC32=0x{crc:08X})")
        self._uds.routine_control(
            RoutineControlType.START,
            ROUTINE_CRC_CHECKSUM,
            crc_bytes,
        )
        self._log("Checksum verification passed")

    def _step_check_dependencies(self) -> None:
        """Step 13: Check programming dependencies."""
        self._uds.routine_control(
            RoutineControlType.START,
            ROUTINE_CHECK_DEPENDENCIES,
        )
        self._log("Dependency check passed")

    def _step_ecu_reset(self) -> None:
        """Step 14: Hard reset ECU."""
        self._uds.ecu_reset(ECUResetType.HARD_RESET)
        self._log("ECU reset complete")
