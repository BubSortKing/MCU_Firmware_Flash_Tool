"""UDS (Unified Diagnostic Services) client — ISO 14229.

Provides a high-level API for the 7 UDS services used in the OEM flash
workflow.  Each method builds the raw request bytes, sends them via the
ISO-TP transport layer, and parses the response (handling negative
responses and the ResponsePending NRC 0x78 loop).

Usage::

    client = UDSClient(transport)
    client.diagnostic_session_control(DiagnosticSession.EXTENDED)
    seed = client.security_access_request_seed(level=0x01)
    client.security_access_send_key(level=0x02, key=computed_key)
"""

import logging
import struct
import time
from dataclasses import dataclass
from typing import Optional

from canbus.transport import IsoTpTransport
from config.constants import (
    NRC,
    UDS_NEGATIVE_RESPONSE,
    UDS_POSITIVE_RESPONSE_OFFSET,
    UDSServiceID,
)
from config.settings import UDSSettings

logger = logging.getLogger(__name__)


# =============================================================================
# Exceptions
# =============================================================================


class UDSError(Exception):
    """Base UDS error."""


class UDSNegativeResponseError(UDSError):
    """Raised when the ECU returns a negative response (0x7F)."""

    def __init__(self, service_id: int, nrc_code: int) -> None:
        self.service_id = service_id
        self.nrc_code = nrc_code
        desc = NRC.get_description(nrc_code)
        super().__init__(
            f"Negative response for service 0x{service_id:02X}: "
            f"NRC 0x{nrc_code:02X} — {desc}"
        )


class UDSTimeoutError(UDSError):
    """Raised when the ECU does not respond within the allowed time."""


# =============================================================================
# Response data classes
# =============================================================================


@dataclass
class SessionResponse:
    """Parsed DiagnosticSessionControl positive response."""
    session_type: int
    p2_timeout_ms: int
    p2_star_timeout_ms: int


@dataclass
class DownloadResponse:
    """Parsed RequestDownload positive response."""
    max_block_length: int


# =============================================================================
# UDS Client
# =============================================================================


class UDSClient:
    """High-level UDS client over an ISO-TP transport.

    Args:
        transport: An initialised IsoTpTransport instance.
        settings:  UDS timing parameters.
    """

    def __init__(
        self,
        transport: IsoTpTransport,
        settings: Optional[UDSSettings] = None,
    ) -> None:
        self._tp = transport
        self._settings = settings or UDSSettings()

    # ------------------------------------------------------------------
    # Core send / receive with NRC 0x78 handling
    # ------------------------------------------------------------------

    def _send_request(self, payload: bytes, timeout: Optional[float] = None) -> bytes:
        """Send a UDS request and return the positive-response payload.

        Automatically retries on NRC 0x78 (ResponsePending) up to
        ``max_response_pending`` times, using the P2* timeout for
        subsequent waits.

        Args:
            payload: Raw UDS request bytes (SID + sub-function + data).
            timeout: Initial response timeout in seconds.  Defaults to
                     P2 timeout from settings.

        Returns:
            The full positive-response payload (including response SID).

        Raises:
            UDSNegativeResponseError: On a non-0x78 negative response.
            UDSTimeoutError: If ResponsePending count exceeded.
        """
        service_id = payload[0]
        p2_sec = (timeout or self._settings.p2_timeout) / 1000.0
        p2_star_sec = self._settings.p2_star_timeout / 1000.0

        self._tp.send(payload)

        pending_count = 0
        current_timeout = p2_sec

        while True:
            response = self._tp.receive(timeout=current_timeout)
            logger.debug(
                "UDS RX [0x%02X]: %s", service_id, response.hex(" ").upper(),
            )

            # --- Positive response ---
            if response[0] == service_id + UDS_POSITIVE_RESPONSE_OFFSET:
                return response

            # --- Negative response ---
            if response[0] == UDS_NEGATIVE_RESPONSE and len(response) >= 3:
                nrc = response[2]

                if nrc == NRC.REQUEST_CORRECTLY_RECEIVED_RESPONSE_PENDING:
                    pending_count += 1
                    if pending_count > self._settings.max_response_pending:
                        raise UDSTimeoutError(
                            f"Exceeded max ResponsePending count "
                            f"({self._settings.max_response_pending})"
                        )
                    logger.debug(
                        "ResponsePending (%d/%d), waiting %.1fs",
                        pending_count,
                        self._settings.max_response_pending,
                        p2_star_sec,
                    )
                    current_timeout = p2_star_sec
                    continue

                raise UDSNegativeResponseError(service_id, nrc)

            # --- Unexpected response ---
            raise UDSError(
                f"Unexpected response for service 0x{service_id:02X}: "
                f"{response.hex(' ')}"
            )

    # ------------------------------------------------------------------
    # DiagnosticSessionControl (0x10)
    # ------------------------------------------------------------------

    def diagnostic_session_control(self, session_type: int) -> SessionResponse:
        """Switch the ECU diagnostic session.

        Args:
            session_type: Target session (0x01 default, 0x02 programming,
                          0x03 extended).

        Returns:
            SessionResponse with P2 and P2* timing from the ECU.
        """
        request = bytes([UDSServiceID.DIAGNOSTIC_SESSION_CONTROL, session_type])
        resp = self._send_request(request)

        # Response: 50 <session> <P2_hi> <P2_lo> <P2*_hi> <P2*_lo>
        session = resp[1]
        p2 = (resp[2] << 8) | resp[3] if len(resp) >= 4 else 0
        p2_star = ((resp[4] << 8) | resp[5]) * 10 if len(resp) >= 6 else 0

        logger.info(
            "Session 0x%02X active (P2=%dms, P2*=%dms)", session, p2, p2_star,
        )
        return SessionResponse(session, p2, p2_star)

    # ------------------------------------------------------------------
    # ECUReset (0x11)
    # ------------------------------------------------------------------

    def ecu_reset(self, reset_type: int) -> None:
        """Request an ECU reset.

        Args:
            reset_type: 0x01 hard, 0x02 key-off-on, 0x03 soft.
        """
        request = bytes([UDSServiceID.ECU_RESET, reset_type])
        self._send_request(request)
        logger.info("ECU reset (type 0x%02X) acknowledged", reset_type)

    # ------------------------------------------------------------------
    # SecurityAccess (0x27)
    # ------------------------------------------------------------------

    def security_access_request_seed(self, level: int) -> bytes:
        """Request a security seed from the ECU.

        Args:
            level: Odd sub-function (0x01, 0x03, …) for request-seed.

        Returns:
            The seed bytes from the ECU response.
        """
        request = bytes([UDSServiceID.SECURITY_ACCESS, level])
        resp = self._send_request(request)

        # Response: 67 <level> <seed...>
        seed = resp[2:]
        logger.info(
            "Security seed L%d: %s", level, seed.hex(" ").upper(),
        )
        return seed

    def security_access_send_key(self, level: int, key: bytes) -> None:
        """Send the computed key to unlock a security level.

        Args:
            level: Even sub-function (0x02, 0x04, …) for send-key.
            key:   The computed key bytes.

        Raises:
            UDSNegativeResponseError: If the key is invalid (NRC 0x35).
        """
        request = bytes([UDSServiceID.SECURITY_ACCESS, level]) + key
        self._send_request(request)
        logger.info("Security level %d unlocked", level)

    # ------------------------------------------------------------------
    # RoutineControl (0x31)
    # ------------------------------------------------------------------

    def routine_control(
        self,
        control_type: int,
        routine_id: int,
        option_record: bytes = b"",
    ) -> bytes:
        """Execute a RoutineControl request.

        Args:
            control_type: 0x01 start, 0x02 stop, 0x03 request results.
            routine_id:   2-byte routine identifier.
            option_record: Optional routine-specific data.

        Returns:
            The routineStatusRecord from the positive response.
        """
        request = (
            bytes([UDSServiceID.ROUTINE_CONTROL, control_type])
            + struct.pack(">H", routine_id)
            + option_record
        )
        resp = self._send_request(request)

        # Response: 71 <type> <id_hi> <id_lo> <status_record...>
        status_record = resp[4:]
        logger.info(
            "Routine 0x%04X (type 0x%02X) complete, status=%s",
            routine_id, control_type, status_record.hex(" ").upper() or "OK",
        )
        return status_record

    # ------------------------------------------------------------------
    # RequestDownload (0x34)
    # ------------------------------------------------------------------

    def request_download(
        self,
        memory_address: int,
        memory_size: int,
        data_format: int = 0x00,
        address_length_format: int = 0x44,
    ) -> DownloadResponse:
        """Request a download session to the ECU.

        Args:
            memory_address: Start address in ECU memory.
            memory_size:    Number of bytes to download.
            data_format:    dataFormatIdentifier (0x00 = no compression/encryption).
            address_length_format: addressAndLengthFormatIdentifier
                                   (0x44 = 4-byte addr + 4-byte size).

        Returns:
            DownloadResponse with the max block length reported by the ECU.
        """
        addr_len = address_length_format & 0x0F  # low nibble = address bytes
        size_len = (address_length_format >> 4) & 0x0F  # high nibble = size bytes

        request = (
            bytes([UDSServiceID.REQUEST_DOWNLOAD, data_format, address_length_format])
            + memory_address.to_bytes(addr_len, "big")
            + memory_size.to_bytes(size_len, "big")
        )
        resp = self._send_request(request)

        # Response: 74 <lengthFormatId> <maxBlockLength...>
        # Some ECUs (e.g. boot flash) return only [0x74] with no length field;
        # return max_block_length=0 so the caller can apply its own fallback.
        if len(resp) < 2:
            logger.info(
                "Download accepted (no length field): addr=0x%X size=0x%X, "
                "caller will use fallback block size",
                memory_address, memory_size,
            )
            return DownloadResponse(max_block_length=0)

        length_format = resp[1]
        max_bl_len = (length_format >> 4) & 0x0F  # number of bytes for maxBlockLength
        max_block_length = (
            int.from_bytes(resp[2:2 + max_bl_len], "big")
            if max_bl_len > 0 and len(resp) >= 2 + max_bl_len
            else 0
        )

        logger.info(
            "Download accepted: addr=0x%X size=0x%X maxBlock=%d",
            memory_address, memory_size, max_block_length,
        )
        return DownloadResponse(max_block_length)

    # ------------------------------------------------------------------
    # TransferData (0x36)
    # ------------------------------------------------------------------

    def transfer_data(self, block_counter: int, data: bytes) -> None:
        """Send one block of firmware data.

        Args:
            block_counter: Block sequence counter (wraps 0x00–0xFF).
            data:          The firmware data bytes for this block.
        """
        request = bytes([UDSServiceID.TRANSFER_DATA, block_counter & 0xFF]) + data
        self._send_request(request)
        logger.debug("TransferData block 0x%02X OK (%d bytes)", block_counter, len(data))

    # ------------------------------------------------------------------
    # RequestTransferExit (0x37)
    # ------------------------------------------------------------------

    def request_transfer_exit(self) -> None:
        """Signal the end of the data transfer."""
        request = bytes([UDSServiceID.REQUEST_TRANSFER_EXIT])
        self._send_request(request)
        logger.info("Transfer exit acknowledged")
