"""Flash workflow controller — orchestrates the 18-step dual-core flash sequence.

Manages the complete firmware flashing process for a dual-core ECU: a shared
session setup (steps 1-5), followed by the Core0 flash cycle (steps 6-11),
the Core1 flash cycle (steps 12-17), and a final ECU reset (step 18).

Abort support and progress reporting are delivered through callback functions
that the caller provides (typically connected to Qt signals).

Usage::

    flasher = Flasher(driver, firmware_core0, firmware_core1)
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
    """Current state of the dual-core flash workflow."""
    # Control / terminal
    IDLE = auto()
    DONE = auto()
    ABORTED = auto()
    ERROR = auto()

    # Session setup — shared, run once (steps 1-5)
    EXTENDED_SESSION = auto()
    SECURITY_UNLOCK_EXTENDED = auto()
    PRE_PROGRAMMING_CHECK = auto()
    PROGRAMMING_SESSION = auto()
    SECURITY_UNLOCK_PROGRAMMING = auto()

    # Core 0 flash (steps 6-11)
    CORE0_ERASING = auto()
    CORE0_REQUESTING_DOWNLOAD = auto()
    CORE0_TRANSFERRING = auto()
    CORE0_TRANSFER_EXIT = auto()
    CORE0_CHECKSUM = auto()
    CORE0_CHECK_DEPENDENCIES = auto()

    # Core 1 flash (steps 12-17)
    CORE1_ERASING = auto()
    CORE1_REQUESTING_DOWNLOAD = auto()
    CORE1_TRANSFERRING = auto()
    CORE1_TRANSFER_EXIT = auto()
    CORE1_CHECKSUM = auto()
    CORE1_CHECK_DEPENDENCIES = auto()

    # Finalize (step 18)
    ECU_RESET = auto()


class FlashError(Exception):
    """Raised when the flash workflow encounters an unrecoverable error."""


# Step descriptions for progress reporting
_STEP_DESCRIPTIONS = {
    FlashState.EXTENDED_SESSION:             "Entering extended session",
    FlashState.SECURITY_UNLOCK_EXTENDED:     "Security unlock (extended)",
    FlashState.PRE_PROGRAMMING_CHECK:        "Pre-programming check",
    FlashState.PROGRAMMING_SESSION:          "Switching to programming session",
    FlashState.SECURITY_UNLOCK_PROGRAMMING:  "Security unlock (programming)",
    FlashState.CORE0_ERASING:                "Erasing Core0 flash memory",
    FlashState.CORE0_REQUESTING_DOWNLOAD:    "Core0: requesting download",
    FlashState.CORE0_TRANSFERRING:           "Transferring Core0 firmware",
    FlashState.CORE0_TRANSFER_EXIT:          "Core0: completing transfer",
    FlashState.CORE0_CHECKSUM:               "Core0: verifying checksum",
    FlashState.CORE0_CHECK_DEPENDENCIES:     "Core0: checking dependencies",
    FlashState.CORE1_ERASING:                "Erasing Core1 flash memory",
    FlashState.CORE1_REQUESTING_DOWNLOAD:    "Core1: requesting download",
    FlashState.CORE1_TRANSFERRING:           "Transferring Core1 firmware",
    FlashState.CORE1_TRANSFER_EXIT:          "Core1: completing transfer",
    FlashState.CORE1_CHECKSUM:               "Core1: verifying checksum",
    FlashState.CORE1_CHECK_DEPENDENCIES:     "Core1: checking dependencies",
    FlashState.ECU_RESET:                    "Resetting ECU",
}

# Approximate time-based weights for each step.
# Each TransferData step dominates real wall-clock time; erase and checksum
# are a few seconds each; all other steps are near-instant UDS exchanges.
# Grand total = 5 + 89 + 89 + 1 = 184
_STEP_WEIGHTS = {
    # Session setup (5 × 1)
    FlashState.EXTENDED_SESSION:             1,
    FlashState.SECURITY_UNLOCK_EXTENDED:     1,
    FlashState.PRE_PROGRAMMING_CHECK:        1,
    FlashState.PROGRAMMING_SESSION:          1,
    FlashState.SECURITY_UNLOCK_PROGRAMMING:  1,
    # Core 0 (8 + 1 + 70 + 1 + 8 + 1 = 89)
    FlashState.CORE0_ERASING:                8,
    FlashState.CORE0_REQUESTING_DOWNLOAD:    1,
    FlashState.CORE0_TRANSFERRING:           70,
    FlashState.CORE0_TRANSFER_EXIT:          1,
    FlashState.CORE0_CHECKSUM:               8,
    FlashState.CORE0_CHECK_DEPENDENCIES:     1,
    # Core 1 (8 + 1 + 70 + 1 + 8 + 1 = 89)
    FlashState.CORE1_ERASING:                8,
    FlashState.CORE1_REQUESTING_DOWNLOAD:    1,
    FlashState.CORE1_TRANSFERRING:           70,
    FlashState.CORE1_TRANSFER_EXIT:          1,
    FlashState.CORE1_CHECKSUM:               8,
    FlashState.CORE1_CHECK_DEPENDENCIES:     1,
    # Finalize (1)
    FlashState.ECU_RESET:                    1,
}

# States that perform per-block progress injection inside _step_transfer_data
_TRANSFER_STATES = {FlashState.CORE0_TRANSFERRING, FlashState.CORE1_TRANSFERRING}


class Flasher:
    """Orchestrate the dual-core flash sequence (up to 18 steps).

    Either or both core firmwares may be provided.  The session setup
    (steps 1-5) and ECU reset (step 18) always run; Core 0 (steps 6-11)
    and Core 1 (steps 12-17) are included only when the corresponding
    firmware is supplied.

    Args:
        driver:           An open PCANDriver instance.
        firmware_core0:   Parsed FirmwareImage for Core 0, or None to skip.
        firmware_core1:   Parsed FirmwareImage for Core 1, or None to skip.
        can_settings:     CAN bus configuration.
        flash_settings:   (core0_settings, core1_settings) tuple; defaults to
                          (FlashSettings(), FlashSettings()) if omitted.
        uds_settings:     UDS timing parameters.
        isotp_settings:   ISO-TP transport parameters.
    """

    def __init__(
        self,
        driver: PCANDriver,
        firmware_core0: Optional[FirmwareImage] = None,
        firmware_core1: Optional[FirmwareImage] = None,
        can_settings: Optional[CANSettings] = None,
        flash_settings: Optional[tuple[FlashSettings, FlashSettings]] = None,
        uds_settings: Optional[UDSSettings] = None,
        isotp_settings: Optional[IsoTpSettings] = None,
    ) -> None:
        if firmware_core0 is None and firmware_core1 is None:
            raise ValueError("At least one core firmware must be provided")
        self._driver = driver
        self._firmware_core0 = firmware_core0
        self._firmware_core1 = firmware_core1

        self._can = can_settings or CANSettings()
        self._uds_settings = uds_settings or UDSSettings()
        self._isotp_settings = isotp_settings or IsoTpSettings()

        if flash_settings is None:
            self._flash_core0 = FlashSettings()
            self._flash_core1 = FlashSettings()
        else:
            self._flash_core0, self._flash_core1 = flash_settings

        self._state = FlashState.IDLE
        self._abort_requested = False

        # Per-core max data bytes per TransferData block (set at RequestDownload)
        self._max_data_per_block_c0: int = 0
        self._max_data_per_block_c1: int = 0

        # Side-channel for inject per-block progress from execute() into _step_transfer_data
        self._transfer_pct_range: tuple[int, int] = (0, 0)

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
    def firmware_core0(self) -> Optional[FirmwareImage]:
        return self._firmware_core0

    @property
    def firmware_core1(self) -> Optional[FirmwareImage]:
        return self._firmware_core1

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
        """Run the flash sequence for whichever cores have firmware loaded.

        Always runs session setup (steps 1-5) and ECU reset (step 18).
        Core 0 (steps 6-11) and Core 1 (steps 12-17) are included only
        when the corresponding firmware was provided.

        Raises:
            FlashError: On abort, UDS failure, or any unrecoverable error.
        """
        self._abort_requested = False

        steps: list[tuple[FlashState, Callable[[], None]]] = []

        # Session setup — always run (steps 1-5)
        steps += [
            (FlashState.EXTENDED_SESSION,             self._step_extended_session),
            (FlashState.SECURITY_UNLOCK_EXTENDED,     self._step_security_extended),
            (FlashState.PRE_PROGRAMMING_CHECK,        self._step_pre_check),
            (FlashState.PROGRAMMING_SESSION,          self._step_programming_session),
            (FlashState.SECURITY_UNLOCK_PROGRAMMING,  self._step_security_programming),
        ]

        # Core 0 — only if firmware provided (steps 6-11)
        if self._firmware_core0 is not None:
            steps += [
                (FlashState.CORE0_ERASING,                lambda: self._step_erase(0)),
                (FlashState.CORE0_REQUESTING_DOWNLOAD,    lambda: self._step_request_download(0)),
                (FlashState.CORE0_TRANSFERRING,           lambda: self._step_transfer_data(0)),
                (FlashState.CORE0_TRANSFER_EXIT,          self._step_transfer_exit),
                (FlashState.CORE0_CHECKSUM,               lambda: self._step_checksum(0)),
                (FlashState.CORE0_CHECK_DEPENDENCIES,     self._step_check_dependencies),
            ]

        # Core 1 — only if firmware provided (steps 12-17)
        if self._firmware_core1 is not None:
            steps += [
                (FlashState.CORE1_ERASING,                lambda: self._step_erase(1)),
                (FlashState.CORE1_REQUESTING_DOWNLOAD,    lambda: self._step_request_download(1)),
                (FlashState.CORE1_TRANSFERRING,           lambda: self._step_transfer_data(1)),
                (FlashState.CORE1_TRANSFER_EXIT,          self._step_transfer_exit),
                (FlashState.CORE1_CHECKSUM,               lambda: self._step_checksum(1)),
                (FlashState.CORE1_CHECK_DEPENDENCIES,     self._step_check_dependencies),
            ]

        # Finalize — always (step 18)
        steps.append((FlashState.ECU_RESET, self._step_ecu_reset))

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
                desc = _STEP_DESCRIPTIONS.get(state, state.name.replace("_", " ").title())
                if state in _TRANSFER_STATES:
                    self._transfer_pct_range = (start_pct, end_pct)
                else:
                    self._progress(start_pct, desc)
                step_func()

            self._set_state(FlashState.DONE)
            if self._firmware_core0 and self._firmware_core1:
                done_msg = "Dual-core flash complete"
            elif self._firmware_core0:
                done_msg = "Core0-only flash complete"
            else:
                done_msg = "Core1-only flash complete"
            self._progress(100, done_msg)

        except FlashError:
            raise
        except UDSError as exc:
            self._set_state(FlashState.ERROR)
            raise FlashError(f"UDS error: {exc}") from exc
        except Exception as exc:
            self._set_state(FlashState.ERROR)
            raise FlashError(f"Unexpected error: {exc}") from exc

    # ------------------------------------------------------------------
    # Session setup steps (shared, run once)
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
        """Step 3: Pre-programming condition check."""
        self._uds.routine_control(
            RoutineControlType.START,
            ROUTINE_PRE_PROGRAMMING_CHECK,
        )
        self._log("Pre-programming check passed")

    def _step_programming_session(self) -> None:
        """Step 4: Switch to programming session."""
        resp = self._uds.diagnostic_session_control(DiagnosticSession.PROGRAMMING)
        self._log(
            f"Programming session active (P2={resp.p2_timeout_ms}ms, "
            f"P2*={resp.p2_star_timeout_ms}ms)"
        )
        # ECU needs time to reconfigure after session transition
        time.sleep(0.1)

    def _step_security_programming(self) -> None:
        """Steps 5-6: Security access for programming session (Level 3/4)."""
        seed = self._uds.security_access_request_seed(0x03)
        if seed == b"\x00" * len(seed):
            self._log("Programming security already unlocked (zero seed)")
            return
        key = self._security.compute_key(seed, 0x03)
        self._uds.security_access_send_key(0x04, key)
        self._log("Programming session security unlocked")

    # ------------------------------------------------------------------
    # Per-core steps (core_index: 0 = Core0, 1 = Core1)
    # ------------------------------------------------------------------

    def _step_erase(self, core_index: int) -> None:
        """Erase the target core's flash memory."""
        firmware = self._firmware_core0 if core_index == 0 else self._firmware_core1
        flash    = self._flash_core0    if core_index == 0 else self._flash_core1
        label    = f"Core{core_index}"

        fmt      = flash.address_length_format
        addr_len = fmt & 0x0F
        size_len = (fmt >> 4) & 0x0F

        option_record = (
            bytes([fmt])
            + firmware.download_address.to_bytes(addr_len, "big")
            + firmware.total_size.to_bytes(size_len, "big")
        )
        self._log(
            f"{label}: erasing 0x{firmware.download_address:08X}..+"
            f"0x{firmware.total_size:X}"
        )
        self._uds.routine_control(
            RoutineControlType.START,
            ROUTINE_ERASE_MEMORY,
            option_record,
        )
        self._log(f"{label}: erase complete")

    def _step_request_download(self, core_index: int) -> None:
        """Request download for the target core."""
        firmware = self._firmware_core0 if core_index == 0 else self._firmware_core1
        flash    = self._flash_core0    if core_index == 0 else self._flash_core1

        resp = self._uds.request_download(
            memory_address=firmware.download_address,
            memory_size=firmware.total_size,
            data_format=flash.data_format,
            address_length_format=flash.address_length_format,
        )
        if core_index == 0:
            self._max_data_per_block_c0 = resp.max_block_length
        else:
            self._max_data_per_block_c1 = resp.max_block_length

        self._log(
            f"Core{core_index}: download accepted, "
            f"max data per block={resp.max_block_length} bytes"
        )

    def _step_transfer_data(self, core_index: int) -> None:
        """Transfer firmware data for the target core block by block."""
        firmware     = self._firmware_core0 if core_index == 0 else self._firmware_core1
        max_block    = (self._max_data_per_block_c0 if core_index == 0
                        else self._max_data_per_block_c1)
        label        = f"Core{core_index}"
        total_size   = firmware.total_size
        blocks       = list(firmware.iter_blocks(max_block))
        total_blocks = len(blocks)
        block_counter = 1  # starts at 1, wraps 0x00-0xFF

        self._log(f"{label}: transferring {total_size} bytes in {total_blocks} blocks")

        pct_start, pct_end = self._transfer_pct_range
        bytes_sent = 0
        for i, block_data in enumerate(blocks):
            self._check_abort()
            self._uds.transfer_data(block_counter, block_data)
            bytes_sent    += len(block_data)
            block_counter  = (block_counter + 1) & 0xFF

            transfer_pct = pct_start + int(
                (bytes_sent / total_size) * (pct_end - pct_start)
            )
            self._progress(
                transfer_pct,
                f"{label} transfer: {bytes_sent}/{total_size} bytes "
                f"(block {i + 1}/{total_blocks})",
            )

        self._log(f"{label}: transfer complete ({bytes_sent} bytes, {total_blocks} blocks)")

    def _step_transfer_exit(self) -> None:
        """Request transfer exit (shared by Core0 and Core1)."""
        self._uds.request_transfer_exit()
        self._log("Transfer exit acknowledged")

    def _step_checksum(self, core_index: int) -> None:
        """SHA-256 + CRC32 verification for the target core.

        The tester sends the CRC32 of the firmware in the RoutineControl
        option record. The MCU independently verifies both the CRC32 and
        the SHA-256 hash it computed over the received TransferData bytes.
        """
        firmware  = self._firmware_core0 if core_index == 0 else self._firmware_core1
        crc       = firmware.crc32()
        crc_bytes = struct.pack(">I", crc)

        self._log(
            f"Core{core_index}: requesting checksum verification "
            f"(CRC32=0x{crc:08X})"
        )
        self._uds.routine_control(
            RoutineControlType.START,
            ROUTINE_CRC_CHECKSUM,
            crc_bytes,
        )
        self._log(f"Core{core_index}: checksum verification passed")

    def _step_check_dependencies(self) -> None:
        """Check programming dependencies (shared by Core0 and Core1)."""
        self._uds.routine_control(
            RoutineControlType.START,
            ROUTINE_CHECK_DEPENDENCIES,
        )
        self._log("Dependency check passed")

    # ------------------------------------------------------------------
    # Finalize
    # ------------------------------------------------------------------

    def _step_ecu_reset(self) -> None:
        """Step 18: Hard reset ECU."""
        self._uds.ecu_reset(ECUResetType.HARD_RESET)
        self._log("ECU reset complete")
