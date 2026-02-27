"""Bootloader flash controller — 9-step app-layer protocol.

Flashes the ECU bootloader from the application layer using a different
UDS session sequence than the standard dual-core app flash.  The protocol
was decoded from FlashBootLog.trc.

Key differences from the main Flasher:
- Opens with supplier-specific session 0x60 (no programming session switch)
- Only SecurityAccess Level 3/4 (no initial Level 1/2)
- Erase routine 0x0204 instead of 0xFF00
- Checksum routine 0x0205 with empty option record (no CRC bytes)
- RequestDownload 0x74 response may carry no maxBlockLength byte;
  falls back to FlashSettings.max_block_size (default 512)
- TransferData block size default is 512 bytes (app default is 2048)

Usage::

    boot_flasher = BootFlasher(driver, firmware_image)
    boot_flasher.on_progress = lambda pct, msg: print(f"{pct}% {msg}")
    boot_flasher.on_log = lambda msg: print(msg)
    boot_flasher.execute()
"""

import logging
import time
from enum import Enum, auto
from typing import Callable, Optional

from canbus.pcan_driver import PCANDriver
from canbus.transport import IsoTpTransport
from config.constants import (
    ECUResetType,
    ROUTINE_BOOT_CHECKSUM,
    ROUTINE_BOOT_ERASE,
    RoutineControlType,
)
from config.settings import CANSettings, FlashSettings, IsoTpSettings, UDSSettings
from flash.flasher import FlashError
from flash.hex_parser import FirmwareImage
from uds.security import SecurityManager
from uds.services import UDSClient, UDSError

logger = logging.getLogger(__name__)


# =============================================================================
# Boot flash state
# =============================================================================


class BootFlashState(Enum):
    """Current state of the bootloader flash workflow."""
    # Terminal / control
    IDLE = auto()
    DONE = auto()
    ABORTED = auto()
    ERROR = auto()

    # Active steps (9)
    BOOT_INIT_SESSION        = auto()   # step 1 — DSC 0x60
    BOOT_PROGRAMMING_SESSION = auto()   # step 2 — DSC 0x03
    BOOT_SECURITY_UNLOCK     = auto()   # step 3 — SA L3/L4
    BOOT_ERASING             = auto()   # step 4 — RC 0x0204
    BOOT_REQUESTING_DOWNLOAD = auto()   # step 5 — RD
    BOOT_TRANSFERRING        = auto()   # step 6 — TD
    BOOT_TRANSFER_EXIT       = auto()   # step 7 — RTE
    BOOT_CHECKSUM            = auto()   # step 8 — RC 0x0205
    BOOT_ECU_RESET           = auto()   # step 9 — ECUReset


# Step descriptions for progress reporting
_STEP_DESCRIPTIONS = {
    BootFlashState.BOOT_INIT_SESSION:        "Entering supplier session (0x60)",
    BootFlashState.BOOT_PROGRAMMING_SESSION: "Entering extended session",
    BootFlashState.BOOT_SECURITY_UNLOCK:     "Security unlock (Level 3/4)",
    BootFlashState.BOOT_ERASING:             "Erasing bootloader flash memory",
    BootFlashState.BOOT_REQUESTING_DOWNLOAD: "Requesting download",
    BootFlashState.BOOT_TRANSFERRING:        "Transferring bootloader firmware",
    BootFlashState.BOOT_TRANSFER_EXIT:       "Completing transfer",
    BootFlashState.BOOT_CHECKSUM:            "Verifying checksum",
    BootFlashState.BOOT_ECU_RESET:           "Resetting ECU",
}

# Time-based weights. Erase and checksum take a few seconds each;
# transfer dominates; all others are near-instant. Total = 91.
_STEP_WEIGHTS = {
    BootFlashState.BOOT_INIT_SESSION:        1,
    BootFlashState.BOOT_PROGRAMMING_SESSION: 1,
    BootFlashState.BOOT_SECURITY_UNLOCK:     1,
    BootFlashState.BOOT_ERASING:             8,
    BootFlashState.BOOT_REQUESTING_DOWNLOAD: 1,
    BootFlashState.BOOT_TRANSFERRING:        70,
    BootFlashState.BOOT_TRANSFER_EXIT:       1,
    BootFlashState.BOOT_CHECKSUM:            8,
    BootFlashState.BOOT_ECU_RESET:           1,
}


class BootFlasher:
    """Orchestrate the 9-step bootloader flash sequence.

    Args:
        driver:          An open PCANDriver instance.
        firmware:        Parsed FirmwareImage for the bootloader binary.
        can_settings:    CAN bus configuration.
        flash_settings:  Flash parameters; defaults to FlashSettings(max_block_size=512).
        uds_settings:    UDS timing parameters.
        isotp_settings:  ISO-TP transport parameters.
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
        self._uds_settings = uds_settings or UDSSettings()
        self._isotp_settings = isotp_settings or IsoTpSettings()
        # Boot default block size is 512, not the app default of 2048
        self._flash = flash_settings or FlashSettings(max_block_size=512)

        self._state = BootFlashState.IDLE
        self._abort_requested = False

        # Set by _step_request_download; may fall back to _flash.max_block_size
        self._max_data_per_block: int = self._flash.max_block_size

        # Side-channel for per-block progress injection
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

        # Callbacks — assigned by the caller (typically FlashWorker)
        self.on_progress: Optional[Callable[[int, str], None]] = None
        self.on_state_changed: Optional[Callable[[BootFlashState], None]] = None
        self.on_log: Optional[Callable[[str], None]] = None

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def state(self) -> BootFlashState:
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
        if self._abort_requested:
            self._set_state(BootFlashState.ABORTED)
            raise FlashError("Boot flash aborted by user")

    # ------------------------------------------------------------------
    # Progress / logging helpers
    # ------------------------------------------------------------------

    def _set_state(self, state: BootFlashState) -> None:
        self._state = state
        if self.on_state_changed:
            self.on_state_changed(state)

    def _progress(self, percent: int, message: str) -> None:
        logger.info("BootFlash %d%%: %s", percent, message)
        if self.on_progress:
            self.on_progress(percent, message)

    def _log(self, message: str) -> None:
        logger.info("BootFlash: %s", message)
        if self.on_log:
            self.on_log(message)

    # ------------------------------------------------------------------
    # Main execution
    # ------------------------------------------------------------------

    def execute(self) -> None:
        """Run the complete 9-step bootloader flash sequence.

        Raises:
            FlashError: On abort, UDS failure, or any unrecoverable error.
        """
        self._abort_requested = False

        steps: list[tuple[BootFlashState, Callable[[], None]]] = [
            (BootFlashState.BOOT_INIT_SESSION,        self._step_init_session),
            (BootFlashState.BOOT_PROGRAMMING_SESSION, self._step_programming_session),
            (BootFlashState.BOOT_SECURITY_UNLOCK,     self._step_security_unlock),
            (BootFlashState.BOOT_ERASING,             self._step_erase),
            (BootFlashState.BOOT_REQUESTING_DOWNLOAD, self._step_request_download),
            (BootFlashState.BOOT_TRANSFERRING,        self._step_transfer_data),
            (BootFlashState.BOOT_TRANSFER_EXIT,       self._step_transfer_exit),
            (BootFlashState.BOOT_CHECKSUM,            self._step_checksum),
            (BootFlashState.BOOT_ECU_RESET,           self._step_ecu_reset),
        ]

        # Build cumulative progress ranges (0-99%)
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
                if state is BootFlashState.BOOT_TRANSFERRING:
                    self._transfer_pct_range = (start_pct, end_pct)
                else:
                    self._progress(start_pct, desc)
                step_func()

            self._set_state(BootFlashState.DONE)
            self._progress(100, "Bootloader flash complete")

        except FlashError:
            raise
        except UDSError as exc:
            self._set_state(BootFlashState.ERROR)
            raise FlashError(f"UDS error: {exc}") from exc
        except Exception as exc:
            self._set_state(BootFlashState.ERROR)
            raise FlashError(f"Unexpected error: {exc}") from exc

    # ------------------------------------------------------------------
    # Step implementations
    # ------------------------------------------------------------------

    def _step_init_session(self) -> None:
        """Step 1: Enter supplier-specific session 0x60."""
        resp = self._uds.diagnostic_session_control(0x60)
        self._log(
            f"Supplier session active (P2={resp.p2_timeout_ms}ms, "
            f"P2*={resp.p2_star_timeout_ms}ms)"
        )

    def _step_programming_session(self) -> None:
        """Step 2: Enter extended session (0x03)."""
        resp = self._uds.diagnostic_session_control(0x03)
        self._log(
            f"Extended session active (P2={resp.p2_timeout_ms}ms, "
            f"P2*={resp.p2_star_timeout_ms}ms)"
        )
        time.sleep(0.1)

    def _step_security_unlock(self) -> None:
        """Step 3: SecurityAccess Level 3/4."""
        seed = self._uds.security_access_request_seed(0x03)
        if seed == b"\x00" * len(seed):
            self._log("Security already unlocked (zero seed)")
            return
        # Bootloader SA uses sub-functions 0x03/0x04 on the wire, but the MCU
        # expects the Level 1/2 TEA key set (k=[0x11,0x22,0x33,0x44]) for key
        # computation — same algorithm as the app-flash 0x27 01/02 exchange.
        key = self._security.compute_key(seed, 0x01)
        self._uds.security_access_send_key(0x04, key)
        self._log("Security unlocked (Level 3/4)")

    def _step_erase(self) -> None:
        """Step 4: Erase bootloader memory via routine 0x0204."""
        fmt      = self._flash.address_length_format
        addr_len = fmt & 0x0F
        size_len = (fmt >> 4) & 0x0F

        option_record = (
            bytes([fmt])
            + self._firmware.download_address.to_bytes(addr_len, "big")
            + self._firmware.total_size.to_bytes(size_len, "big")
        )
        self._log(
            f"Erasing 0x{self._firmware.download_address:08X}..+"
            f"0x{self._firmware.total_size:X}"
        )
        self._uds.routine_control(
            RoutineControlType.START,
            ROUTINE_BOOT_ERASE,
            option_record,
        )
        self._log("Erase complete")

    def _step_request_download(self) -> None:
        """Step 5: RequestDownload.

        The ECU 0x74 response for boot flash carries only one byte (74),
        so max_block_length == 0.  In that case fall back to
        FlashSettings.max_block_size.
        """
        resp = self._uds.request_download(
            memory_address=self._firmware.download_address,
            memory_size=self._firmware.total_size,
            data_format=self._flash.data_format,
            address_length_format=self._flash.address_length_format,
        )
        if resp.max_block_length == 0:
            self._max_data_per_block = self._flash.max_block_size
            self._log(
                f"Download accepted (no maxBlockLength in response), "
                f"using default {self._max_data_per_block} bytes/block"
            )
        else:
            self._max_data_per_block = resp.max_block_length
            self._log(
                f"Download accepted, max data per block={self._max_data_per_block} bytes"
            )

    def _step_transfer_data(self) -> None:
        """Step 6: Transfer firmware data block by block."""
        total_size    = self._firmware.total_size
        blocks        = list(self._firmware.iter_blocks(self._max_data_per_block))
        total_blocks  = len(blocks)
        block_counter = 1  # starts at 1, wraps 0xFF → 0x00

        self._log(
            f"Transferring {total_size} bytes in {total_blocks} blocks "
            f"({self._max_data_per_block} bytes/block)"
        )

        pct_start, pct_end = self._transfer_pct_range
        bytes_sent = 0
        for i, block_data in enumerate(blocks):
            self._check_abort()
            self._uds.transfer_data(block_counter, block_data)
            bytes_sent   += len(block_data)
            block_counter = (block_counter + 1) & 0xFF

            transfer_pct = pct_start + int(
                (bytes_sent / total_size) * (pct_end - pct_start)
            )
            self._progress(
                transfer_pct,
                f"Boot transfer: {bytes_sent}/{total_size} bytes "
                f"(block {i + 1}/{total_blocks})",
            )

        self._log(f"Transfer complete ({bytes_sent} bytes, {total_blocks} blocks)")

    def _step_transfer_exit(self) -> None:
        """Step 7: RequestTransferExit."""
        self._uds.request_transfer_exit()
        self._log("Transfer exit acknowledged")

    def _step_checksum(self) -> None:
        """Step 8: Checksum routine 0x0205 with empty option record."""
        self._log("Requesting checksum verification")
        self._uds.routine_control(
            RoutineControlType.START,
            ROUTINE_BOOT_CHECKSUM,
            b"",
        )
        self._log("Checksum verification passed")

    def _step_ecu_reset(self) -> None:
        """Step 9: Hard reset ECU."""
        self._uds.ecu_reset(ECUResetType.HARD_RESET)
        self._log("ECU reset complete")
