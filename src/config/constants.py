"""UDS service IDs, NRC codes, and CAN protocol constants."""

from enum import IntEnum


# =============================================================================
# UDS Service IDs (ISO 14229)
# =============================================================================

class UDSServiceID(IntEnum):
    """UDS service identifiers."""
    DIAGNOSTIC_SESSION_CONTROL = 0x10
    ECU_RESET = 0x11
    SECURITY_ACCESS = 0x27
    ROUTINE_CONTROL = 0x31
    REQUEST_DOWNLOAD = 0x34
    TRANSFER_DATA = 0x36
    REQUEST_TRANSFER_EXIT = 0x37


class DiagnosticSession(IntEnum):
    """DiagnosticSessionControl sub-functions."""
    DEFAULT = 0x01
    PROGRAMMING = 0x02
    EXTENDED = 0x03


class ECUResetType(IntEnum):
    """ECUReset sub-functions."""
    HARD_RESET = 0x01
    KEY_OFF_ON_RESET = 0x02
    SOFT_RESET = 0x03


class RoutineControlType(IntEnum):
    """RoutineControl sub-functions."""
    START = 0x01
    STOP = 0x02
    REQUEST_RESULTS = 0x03


class SecurityAccessType(IntEnum):
    """SecurityAccess sub-functions."""
    REQUEST_SEED = 0x01
    SEND_KEY = 0x02


# =============================================================================
# UDS Negative Response Codes (NRC)
# =============================================================================

class NRC(IntEnum):
    """UDS Negative Response Codes (ISO 14229)."""
    GENERAL_REJECT = 0x10
    SERVICE_NOT_SUPPORTED = 0x11
    SUB_FUNCTION_NOT_SUPPORTED = 0x12
    INCORRECT_MESSAGE_LENGTH = 0x13
    RESPONSE_TOO_LONG = 0x14
    BUSY_REPEAT_REQUEST = 0x21
    CONDITIONS_NOT_CORRECT = 0x22
    REQUEST_SEQUENCE_ERROR = 0x24
    NO_RESPONSE_FROM_SUBNET = 0x25
    FAILURE_PREVENTS_EXECUTION = 0x26
    REQUEST_OUT_OF_RANGE = 0x31
    SECURITY_ACCESS_DENIED = 0x33
    INVALID_KEY = 0x35
    EXCEEDED_NUMBER_OF_ATTEMPTS = 0x36
    REQUIRED_TIME_DELAY_NOT_EXPIRED = 0x37
    UPLOAD_DOWNLOAD_NOT_ACCEPTED = 0x70
    TRANSFER_DATA_SUSPENDED = 0x71
    GENERAL_PROGRAMMING_FAILURE = 0x72
    WRONG_BLOCK_SEQUENCE_COUNTER = 0x73
    REQUEST_CORRECTLY_RECEIVED_RESPONSE_PENDING = 0x78
    SUB_FUNCTION_NOT_SUPPORTED_IN_ACTIVE_SESSION = 0x7E
    SERVICE_NOT_SUPPORTED_IN_ACTIVE_SESSION = 0x7F

    @classmethod
    def get_description(cls, code: int) -> str:
        """Return human-readable description for an NRC code."""
        descriptions = {
            0x10: "General reject",
            0x11: "Service not supported",
            0x12: "Sub-function not supported",
            0x13: "Incorrect message length or invalid format",
            0x14: "Response too long",
            0x21: "Busy, repeat request",
            0x22: "Conditions not correct",
            0x24: "Request sequence error",
            0x25: "No response from sub-net component",
            0x26: "Failure prevents execution of requested action",
            0x31: "Request out of range",
            0x33: "Security access denied",
            0x35: "Invalid key",
            0x36: "Exceeded number of attempts",
            0x37: "Required time delay not expired",
            0x70: "Upload/download not accepted",
            0x71: "Transfer data suspended",
            0x72: "General programming failure",
            0x73: "Wrong block sequence counter",
            0x78: "Request correctly received, response pending",
            0x7E: "Sub-function not supported in active session",
            0x7F: "Service not supported in active session",
        }
        return descriptions.get(code, f"Unknown NRC (0x{code:02X})")


# =============================================================================
# UDS Protocol Constants
# =============================================================================

# Negative response service ID
UDS_NEGATIVE_RESPONSE = 0x7F

# Positive response offset (service_id + 0x40)
UDS_POSITIVE_RESPONSE_OFFSET = 0x40

# =============================================================================
# ISO 15765-2 CAN Transport Protocol Constants
# =============================================================================

class IsoTpFrameType(IntEnum):
    """ISO 15765-2 frame type nibble (upper 4 bits of first byte)."""
    SINGLE_FRAME = 0x0
    FIRST_FRAME = 0x1
    CONSECUTIVE_FRAME = 0x2
    FLOW_CONTROL = 0x3


class FlowStatus(IntEnum):
    """Flow Control flow status byte."""
    CONTINUE_TO_SEND = 0x0
    WAIT = 0x1
    OVERFLOW = 0x2


# ISO-TP timing defaults (milliseconds)
ISOTP_TIMEOUT_AR = 1000       # N_Ar: FC transmission timeout
ISOTP_TIMEOUT_BS = 1000       # N_Bs: FC reception timeout
ISOTP_TIMEOUT_CR = 1000       # N_Cr: CF reception timeout
ISOTP_DEFAULT_ST_MIN = 10     # Default separation time (ms)
ISOTP_MAX_CF_WAIT_COUNT = 10  # Max consecutive FC.Wait frames

# CAN frame constants
CAN_FRAME_MAX_DATA = 8        # Standard CAN 2.0 data bytes
CAN_SF_MAX_DATA = 7           # Max payload in Single Frame (8 - 1 PCI byte)
CAN_FF_FIRST_DATA = 6         # Payload bytes in First Frame (8 - 2 PCI bytes)
CAN_CF_MAX_DATA = 7           # Max payload in Consecutive Frame (8 - 1 PCI byte)

# =============================================================================
# Default CAN Arbitration IDs
# =============================================================================

DEFAULT_TX_ID = 0x7A2   # Tester → ECU (request)
DEFAULT_RX_ID = 0x7AA   # ECU → Tester (response)

# =============================================================================
# OEM Routine IDs
# =============================================================================

ROUTINE_PRE_PROGRAMMING_CHECK = 0x0203
ROUTINE_ERASE_MEMORY = 0xFF00
ROUTINE_CHECK_DEPENDENCIES = 0xFF01
ROUTINE_CRC_CHECKSUM = 0x0202
