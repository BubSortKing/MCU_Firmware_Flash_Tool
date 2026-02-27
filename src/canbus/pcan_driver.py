"""PCAN USB hardware interface — wraps python-can for PEAK-System adapters."""

import logging
from typing import Optional

import can

from config.settings import CANSettings

logger = logging.getLogger(__name__)


class PCANDriverError(Exception):
    """Raised when a PCAN driver operation fails."""


class PCANDriver:
    """Manage CAN bus connection through a PCAN USB adapter.

    Wraps the ``python-can`` library to provide a simplified interface
    for connecting, disconnecting, sending, and receiving CAN frames.

    Usage::

        driver = PCANDriver()
        driver.connect()
        driver.send(0x7E0, b'\\x10\\x03')
        msg = driver.receive(timeout=1.0)
        driver.disconnect()
    """

    def __init__(self, settings: Optional[CANSettings] = None) -> None:
        self._settings = settings or CANSettings()
        self._bus: Optional[can.Bus] = None

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def is_connected(self) -> bool:
        """Return True if the CAN bus is currently open."""
        return self._bus is not None

    @property
    def settings(self) -> CANSettings:
        """Return current CAN settings."""
        return self._settings

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def connect(self, settings: Optional[CANSettings] = None) -> None:
        """Open the CAN bus connection.

        Args:
            settings: Optional new settings to apply before connecting.

        Raises:
            PCANDriverError: If the connection fails or is already open.
        """
        if self._bus is not None:
            raise PCANDriverError("Already connected — disconnect first")

        if settings is not None:
            self._settings = settings

        s = self._settings
        if s.fd:
            logger.info(
                "Connecting to %s on %s @ %d/%d bit/s (CAN FD)",
                s.interface, s.channel, s.bitrate, s.data_bitrate,
            )
        else:
            logger.info(
                "Connecting to %s on %s @ %d bit/s",
                s.interface, s.channel, s.bitrate,
            )

        try:
            # Always call PCAN_InitializeFD() (fd=True) so the explicit nom_*
            # timing parameters are honoured by the PCAN driver.  When fd=False
            # (classic CAN, the default), python-can would call the legacy
            # PCAN_Initialize() API which hard-codes the sample point to ~87.5%
            # and silently ignores all nom_* kwargs — causing Form Errors
            # because the MCU expects 80%.  The PCAN USB FD hardware is fully
            # backward-compatible: classic CAN frames (is_fd=False) are sent
            # and received normally on an FD-initialised channel.
            bus_kwargs = dict(
                interface=s.interface,
                channel=s.channel,
                bitrate=s.bitrate,
                fd=True,            # forces PCAN_InitializeFD() → nom_* used
                f_clock_mhz=s.f_clock_mhz,
                nom_brp=s.nom_brp,
                nom_tseg1=s.nom_tseg1,
                nom_tseg2=s.nom_tseg2,
                nom_sjw=s.nom_sjw,
                data_brp=s.data_brp,
                data_tseg1=s.data_tseg1,
                data_tseg2=s.data_tseg2,
                data_sjw=s.data_sjw,
            )
            self._bus = can.Bus(**bus_kwargs)
        except can.CanError as exc:
            logger.error("CAN connection failed: %s", exc)
            self._bus = None
            raise PCANDriverError(f"Failed to connect: {exc}") from exc

        logger.info("CAN bus connected successfully")

    def disconnect(self) -> None:
        """Close the CAN bus connection.

        Safe to call even if not connected.
        """
        if self._bus is None:
            return

        try:
            self._bus.shutdown()
            logger.info("CAN bus disconnected")
        except can.CanError as exc:
            logger.warning("Error during CAN shutdown: %s", exc)
        finally:
            self._bus = None

    # ------------------------------------------------------------------
    # Send / Receive
    # ------------------------------------------------------------------

    def send(self, arb_id: int, data: bytes) -> None:
        """Send a single CAN frame.

        Args:
            arb_id: 11-bit CAN arbitration ID.
            data:   Payload bytes (max 8 for CAN 2.0).

        Raises:
            PCANDriverError: If not connected or the send fails.
        """
        if self._bus is None:
            raise PCANDriverError("Not connected")

        msg = can.Message(
            arbitration_id=arb_id,
            data=data,
            is_extended_id=False,
            is_fd=self._settings.fd,
            bitrate_switch=self._settings.fd,
        )

        try:
            self._bus.send(msg)
            logger.debug("TX [0x%03X] %s", arb_id, data.hex(' ').upper())
        except can.CanError as exc:
            logger.error("CAN send failed: %s", exc)
            raise PCANDriverError(f"Send failed: {exc}") from exc

    def receive(self, timeout: float = 1.0) -> Optional[can.Message]:
        """Wait for a single CAN frame.

        Args:
            timeout: Max seconds to wait. ``None`` blocks indefinitely.

        Returns:
            The received ``can.Message``, or ``None`` on timeout.

        Raises:
            PCANDriverError: If not connected or a bus error occurs.
        """
        if self._bus is None:
            raise PCANDriverError("Not connected")

        try:
            msg = self._bus.recv(timeout=timeout)
        except can.CanError as exc:
            logger.error("CAN receive error: %s", exc)
            raise PCANDriverError(f"Receive failed: {exc}") from exc

        if msg is not None:
            logger.debug(
                "RX [0x%03X] %s",
                msg.arbitration_id,
                bytes(msg.data).hex(' ').upper(),
            )
        return msg

    def receive_filtered(
        self,
        arb_id: int,
        timeout: float = 1.0,
    ) -> Optional[can.Message]:
        """Wait for a CAN frame with a specific arbitration ID.

        Frames with non-matching IDs are silently discarded until a
        matching frame arrives or the timeout expires.

        Args:
            arb_id:  Expected arbitration ID.
            timeout: Max seconds to wait in total.

        Returns:
            The matching ``can.Message``, or ``None`` on timeout.
        """
        import time
        deadline = time.monotonic() + timeout

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None

            msg = self.receive(timeout=remaining)
            if msg is None:
                return None
            if msg.arbitration_id == arb_id:
                return msg
            # Discard non-matching frame and keep waiting

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "PCANDriver":
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.disconnect()
