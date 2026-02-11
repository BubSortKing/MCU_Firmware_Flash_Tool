"""ISO 15765-2 CAN Transport Protocol implementation.

Provides segmentation (TX) and reassembly (RX) of UDS messages that
exceed a single CAN frame.  Handles Single Frame, First Frame,
Consecutive Frame, and Flow Control frame types.

Reference: ISO 15765-2:2016 (Road vehicles — Diagnostic communication
over Controller Area Network).
"""

import logging
import time
from dataclasses import dataclass
from typing import Optional

import can as _can
from can import Message as CANMessage

from canbus.pcan_driver import PCANDriver, PCANDriverError
from config.constants import (
    CAN_CF_MAX_DATA,
    CAN_FF_FIRST_DATA,
    CAN_FRAME_MAX_DATA,
    CAN_SF_MAX_DATA,
    FlowStatus,
    ISOTP_MAX_CF_WAIT_COUNT,
    IsoTpFrameType,
)
from config.settings import IsoTpSettings

logger = logging.getLogger(__name__)


# =============================================================================
# Exceptions
# =============================================================================


class IsoTpError(Exception):
    """Base exception for ISO-TP transport errors."""


class IsoTpTimeoutError(IsoTpError):
    """Raised when an expected frame is not received within timeout."""


class IsoTpOverflowError(IsoTpError):
    """Raised when the receiver signals overflow in Flow Control."""


class IsoTpProtocolError(IsoTpError):
    """Raised on unexpected or malformed frames."""


# =============================================================================
# Data classes for parsed frames
# =============================================================================


@dataclass
class SingleFrame:
    """Parsed Single Frame."""
    data_length: int
    data: bytes


@dataclass
class FirstFrame:
    """Parsed First Frame."""
    data_length: int
    data: bytes


@dataclass
class ConsecutiveFrame:
    """Parsed Consecutive Frame."""
    sequence_number: int
    data: bytes


@dataclass
class FlowControlFrame:
    """Parsed Flow Control Frame."""
    flow_status: FlowStatus
    block_size: int
    st_min: int  # separation time in milliseconds


# =============================================================================
# Frame construction helpers
# =============================================================================


def _build_single_frame(payload: bytes, padding: int, pad: bool) -> bytes:
    """Build a Single Frame from a payload (<= 7 bytes).

    Layout: [0x0L | data...]   where L = data length (1-7).
    """
    pci = (IsoTpFrameType.SINGLE_FRAME << 4) | (len(payload) & 0x0F)
    frame = bytes([pci]) + payload
    if pad and len(frame) < CAN_FRAME_MAX_DATA:
        frame += bytes([padding]) * (CAN_FRAME_MAX_DATA - len(frame))
    return frame


def _build_first_frame(total_length: int, first_data: bytes) -> bytes:
    """Build a First Frame.

    Layout: [0x1H 0xLL | data...]
      H = high nibble of total_length (4 bits)
      LL = low byte of total_length (8 bits)
      → supports total_length up to 4095 bytes.
    """
    if total_length > 4095:
        raise IsoTpError(f"Payload too large for standard FF: {total_length}")
    pci_byte0 = (IsoTpFrameType.FIRST_FRAME << 4) | ((total_length >> 8) & 0x0F)
    pci_byte1 = total_length & 0xFF
    return bytes([pci_byte0, pci_byte1]) + first_data[:CAN_FF_FIRST_DATA]


def _build_consecutive_frame(
    seq: int, chunk: bytes, padding: int, pad: bool,
) -> bytes:
    """Build a Consecutive Frame.

    Layout: [0x2N | data...]   where N = sequence number (0-F, wraps).
    """
    pci = (IsoTpFrameType.CONSECUTIVE_FRAME << 4) | (seq & 0x0F)
    frame = bytes([pci]) + chunk
    if pad and len(frame) < CAN_FRAME_MAX_DATA:
        frame += bytes([padding]) * (CAN_FRAME_MAX_DATA - len(frame))
    return frame


def _build_flow_control(
    status: FlowStatus, block_size: int, st_min_ms: int,
) -> bytes:
    """Build a Flow Control Frame.

    Layout: [0x3S BS STmin 0xCC 0xCC 0xCC 0xCC 0xCC]
      S = flow status, BS = block size, STmin = separation time.
    """
    pci = (IsoTpFrameType.FLOW_CONTROL << 4) | (status & 0x0F)
    st_byte = _encode_st_min(st_min_ms)
    frame = bytes([pci, block_size & 0xFF, st_byte])
    # Pad FC to 8 bytes
    frame += bytes([0xCC]) * (CAN_FRAME_MAX_DATA - len(frame))
    return frame


def _encode_st_min(ms: int) -> int:
    """Encode STmin value per ISO 15765-2.

    0x00-0x7F → 0-127 ms
    0xF1-0xF9 → 100-900 µs (not used in this implementation)
    """
    if ms < 0:
        return 0x00
    if ms > 127:
        return 0x7F
    return ms


def _decode_st_min(raw: int) -> float:
    """Decode STmin byte to milliseconds.

    0x00-0x7F → 0-127 ms
    0xF1-0xF9 → 0.1-0.9 ms
    Others    → treat as 127 ms (reserved / unknown)
    """
    if raw <= 0x7F:
        return float(raw)
    if 0xF1 <= raw <= 0xF9:
        return (raw - 0xF0) * 0.1
    return 127.0  # reserved value → conservative fallback


# =============================================================================
# Frame parsing helpers
# =============================================================================


def _parse_frame(msg: CANMessage):
    """Parse a raw CAN message into one of the ISO-TP frame types.

    Returns:
        SingleFrame | FirstFrame | ConsecutiveFrame | FlowControlFrame

    Raises:
        IsoTpProtocolError: If the frame type is unrecognised or malformed.
    """
    raw = bytes(msg.data)
    if len(raw) < 1:
        raise IsoTpProtocolError("Empty CAN frame")

    frame_type = (raw[0] >> 4) & 0x0F

    if frame_type == IsoTpFrameType.SINGLE_FRAME:
        dl = raw[0] & 0x0F
        if dl == 0 or dl > CAN_SF_MAX_DATA:
            raise IsoTpProtocolError(f"Invalid SF data length: {dl}")
        return SingleFrame(data_length=dl, data=raw[1:1 + dl])

    if frame_type == IsoTpFrameType.FIRST_FRAME:
        if len(raw) < 2:
            raise IsoTpProtocolError("FF too short")
        dl = ((raw[0] & 0x0F) << 8) | raw[1]
        if dl < 8:
            raise IsoTpProtocolError(f"FF data length too small: {dl}")
        return FirstFrame(data_length=dl, data=raw[2:2 + CAN_FF_FIRST_DATA])

    if frame_type == IsoTpFrameType.CONSECUTIVE_FRAME:
        sn = raw[0] & 0x0F
        return ConsecutiveFrame(sequence_number=sn, data=raw[1:])

    if frame_type == IsoTpFrameType.FLOW_CONTROL:
        if len(raw) < 3:
            raise IsoTpProtocolError("FC too short")
        fs = raw[0] & 0x0F
        bs = raw[1]
        st = raw[2]
        try:
            flow_status = FlowStatus(fs)
        except ValueError:
            raise IsoTpProtocolError(f"Unknown FC flow status: {fs}")
        return FlowControlFrame(
            flow_status=flow_status,
            block_size=bs,
            st_min=_decode_st_min(st),
        )

    raise IsoTpProtocolError(f"Unknown frame type nibble: 0x{frame_type:X}")


# =============================================================================
# IsoTpTransport — main class
# =============================================================================


class IsoTpTransport:
    """ISO 15765-2 transport layer over a PCANDriver.

    Provides ``send()`` and ``receive()`` for UDS-level payloads,
    automatically handling segmentation, flow control, and reassembly.

    Args:
        driver:  An open PCANDriver instance.
        tx_id:   CAN arbitration ID for outgoing frames.
        rx_id:   CAN arbitration ID for incoming frames.
        settings: ISO-TP timing parameters.

    Usage::

        transport = IsoTpTransport(driver, tx_id=0x7E0, rx_id=0x7E8)
        transport.send(b'\\x10\\x03')               # Single Frame
        response = transport.receive(timeout=2.0)   # blocking
    """

    def __init__(
        self,
        driver: PCANDriver,
        tx_id: int = 0x7E0,
        rx_id: int = 0x7E8,
        settings: Optional[IsoTpSettings] = None,
    ) -> None:
        self._driver = driver
        self._tx_id = tx_id
        self._rx_id = rx_id
        self._settings = settings or IsoTpSettings()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def send(self, payload: bytes) -> None:
        """Send a UDS payload, segmenting into ISO-TP frames as needed.

        - Payloads <= 7 bytes → Single Frame.
        - Payloads > 7 bytes  → First Frame + Consecutive Frames
          (with Flow Control handshake from the receiver).

        Args:
            payload: The raw UDS message bytes.

        Raises:
            IsoTpError: On framing, timeout, or overflow errors.
            PCANDriverError: On CAN bus errors.
        """
        if not payload:
            raise IsoTpError("Cannot send empty payload")

        if len(payload) <= CAN_SF_MAX_DATA:
            self._send_single_frame(payload)
        else:
            self._send_multi_frame(payload)

    def receive(self, timeout: float = 2.0) -> bytes:
        """Receive and reassemble one complete ISO-TP message.

        Waits for a Single Frame or First Frame from ``rx_id``, then
        performs FC/CF handshake for multi-frame messages.

        Args:
            timeout: Max seconds to wait for the initial frame.

        Returns:
            The reassembled UDS payload bytes.

        Raises:
            IsoTpTimeoutError: If no frame arrives within timeout.
            IsoTpProtocolError: On unexpected frame type or sequence error.
            PCANDriverError: On CAN bus errors.
        """
        # Wait for the first frame from the ECU
        msg = self._receive_frame(timeout)
        if msg is None:
            raise IsoTpTimeoutError("No response from ECU")

        parsed = _parse_frame(msg)

        if isinstance(parsed, SingleFrame):
            return parsed.data

        if isinstance(parsed, FirstFrame):
            return self._receive_multi_frame(parsed)

        raise IsoTpProtocolError(
            f"Expected SF or FF, got {type(parsed).__name__}"
        )

    def send_and_receive(
        self,
        payload: bytes,
        timeout: float = 2.0,
    ) -> bytes:
        """Send a request and wait for the complete response.

        Convenience wrapper combining ``send()`` and ``receive()``.
        """
        self.send(payload)
        return self.receive(timeout=timeout)

    # ------------------------------------------------------------------
    # Single Frame TX
    # ------------------------------------------------------------------

    def _send_single_frame(self, payload: bytes) -> None:
        """Transmit a payload as a Single Frame."""
        frame = _build_single_frame(
            payload,
            self._settings.padding_byte,
            self._settings.padding_enabled,
        )
        logger.debug("TX SF [%d bytes]: %s", len(payload), payload.hex(' '))
        self._send_frame(frame)

    # ------------------------------------------------------------------
    # Multi-Frame TX (FF + wait-for-FC + CF loop)
    # ------------------------------------------------------------------

    def _send_multi_frame(self, payload: bytes) -> None:
        """Transmit a payload as First Frame + Consecutive Frames."""
        total = len(payload)
        logger.debug("TX multi-frame [%d bytes total]", total)

        # 1. Send First Frame (first 6 data bytes)
        first_data = payload[:CAN_FF_FIRST_DATA]
        ff = _build_first_frame(total, first_data)
        self._send_frame(ff)
        offset = CAN_FF_FIRST_DATA

        # 2. Wait for Flow Control from receiver
        fc = self._wait_for_flow_control()
        block_size = fc.block_size
        st_min_sec = fc.st_min / 1000.0  # convert ms → s

        # 3. Send Consecutive Frames
        seq = 1
        block_count = 0

        while offset < total:
            # Respect separation time between CFs
            if st_min_sec > 0:
                time.sleep(st_min_sec)

            chunk = payload[offset:offset + CAN_CF_MAX_DATA]
            cf = _build_consecutive_frame(
                seq, chunk,
                self._settings.padding_byte,
                self._settings.padding_enabled,
            )
            self._send_frame(cf)

            offset += len(chunk)
            seq = (seq + 1) & 0x0F  # wrap 0-15
            block_count += 1

            # If block_size > 0, wait for FC after each block
            if block_size > 0 and block_count >= block_size and offset < total:
                fc = self._wait_for_flow_control()
                block_size = fc.block_size
                st_min_sec = fc.st_min / 1000.0
                block_count = 0

        logger.debug("TX multi-frame complete (%d bytes sent)", total)

    def _wait_for_flow_control(self) -> FlowControlFrame:
        """Wait for a Flow Control frame from the receiver.

        Handles FC.Wait by re-waiting (up to ISOTP_MAX_CF_WAIT_COUNT).

        Raises:
            IsoTpTimeoutError: If no FC is received.
            IsoTpOverflowError: If FC indicates overflow.
            IsoTpProtocolError: On unexpected frame types.
        """
        wait_count = 0

        while True:
            msg = self._receive_frame(self._settings.fc_timeout / 1000.0)
            if msg is None:
                raise IsoTpTimeoutError(
                    "Timeout waiting for Flow Control frame"
                )

            parsed = _parse_frame(msg)
            if not isinstance(parsed, FlowControlFrame):
                raise IsoTpProtocolError(
                    f"Expected FC frame, got {type(parsed).__name__}"
                )

            if parsed.flow_status == FlowStatus.CONTINUE_TO_SEND:
                logger.debug(
                    "RX FC: CTS, BS=%d, STmin=%d ms",
                    parsed.block_size, parsed.st_min,
                )
                return parsed

            if parsed.flow_status == FlowStatus.WAIT:
                wait_count += 1
                if wait_count > ISOTP_MAX_CF_WAIT_COUNT:
                    raise IsoTpTimeoutError(
                        f"Exceeded max FC.Wait count ({ISOTP_MAX_CF_WAIT_COUNT})"
                    )
                logger.debug("RX FC: WAIT (%d/%d)", wait_count, ISOTP_MAX_CF_WAIT_COUNT)
                continue

            if parsed.flow_status == FlowStatus.OVERFLOW:
                raise IsoTpOverflowError("Receiver signaled buffer overflow")

    # ------------------------------------------------------------------
    # Multi-Frame RX (send-FC + reassemble-CF loop)
    # ------------------------------------------------------------------

    def _receive_multi_frame(self, ff: FirstFrame) -> bytes:
        """Reassemble a multi-frame message after receiving a First Frame.

        Sends a Flow Control (CTS) to the sender, then collects
        Consecutive Frames until the full payload is assembled.
        """
        total_length = ff.data_length
        buffer = bytearray(ff.data)
        expected_seq = 1

        logger.debug(
            "RX FF: %d bytes total, got first %d",
            total_length, len(ff.data),
        )

        # Send our Flow Control: Continue To Send
        fc_frame = _build_flow_control(
            FlowStatus.CONTINUE_TO_SEND,
            self._settings.block_size,
            self._settings.st_min,
        )
        self._send_frame(fc_frame)

        block_count = 0

        while len(buffer) < total_length:
            msg = self._receive_frame(self._settings.cf_timeout / 1000.0)
            if msg is None:
                raise IsoTpTimeoutError(
                    f"Timeout waiting for CF (have {len(buffer)}/{total_length} bytes)"
                )

            parsed = _parse_frame(msg)
            if not isinstance(parsed, ConsecutiveFrame):
                raise IsoTpProtocolError(
                    f"Expected CF, got {type(parsed).__name__}"
                )

            if parsed.sequence_number != expected_seq:
                raise IsoTpProtocolError(
                    f"CF sequence error: expected {expected_seq}, "
                    f"got {parsed.sequence_number}"
                )

            # Calculate how many bytes we still need
            remaining = total_length - len(buffer)
            data_to_append = parsed.data[:remaining]
            buffer.extend(data_to_append)

            expected_seq = (expected_seq + 1) & 0x0F
            block_count += 1

            # If we configured a block size, send FC after each block
            if (
                self._settings.block_size > 0
                and block_count >= self._settings.block_size
                and len(buffer) < total_length
            ):
                fc_frame = _build_flow_control(
                    FlowStatus.CONTINUE_TO_SEND,
                    self._settings.block_size,
                    self._settings.st_min,
                )
                self._send_frame(fc_frame)
                block_count = 0

        result = bytes(buffer)
        logger.debug("RX multi-frame complete (%d bytes)", len(result))
        return result

    # ------------------------------------------------------------------
    # Low-level CAN frame I/O
    # ------------------------------------------------------------------

    def _send_frame(self, data: bytes) -> None:
        """Send raw frame bytes on the TX arbitration ID."""
        self._driver.send(self._tx_id, data)

    def _receive_frame(self, timeout: float) -> Optional[CANMessage]:
        """Wait for a CAN frame from the expected RX arbitration ID."""
        return self._driver.receive_filtered(self._rx_id, timeout=timeout)
