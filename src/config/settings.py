"""Default CAN/UDS configuration settings."""

from dataclasses import dataclass, field


@dataclass
class CANSettings:
    """CAN bus connection settings."""
    interface: str = "pcan"
    channel: str = "PCAN_USBBUS1"
    bitrate: int = 500000
    data_bitrate: int = 2000000
    fd: bool = False
    tx_id: int = 0x7A2
    rx_id: int = 0x7AA

    # CAN FD timing parameters (for PCAN USB FD, 80 MHz clock)
    # Nominal (500 kbit/s, 80% SP): 80 MHz / (8 × 20 TQ) = 500 kbps, SP = (1+15)/20 = 80%
    # Data    (2 Mbit/s,  80% SP): 80 MHz / (4 × 10 TQ) = 2 Mbps,   SP = (1+7)/10  = 80%
    f_clock_mhz: int = 80
    nom_brp: int = 8
    nom_tseg1: int = 15
    nom_tseg2: int = 4
    nom_sjw: int = 4
    data_brp: int = 4
    data_tseg1: int = 7
    data_tseg2: int = 2
    data_sjw: int = 1

    # Available PCAN channels
    PCAN_CHANNELS: list[str] = field(default_factory=lambda: [
        "PCAN_USBBUS1",
        "PCAN_USBBUS2",
        "PCAN_USBBUS3",
        "PCAN_USBBUS4",
    ])

    # Available bitrates
    BITRATES: dict[str, int] = field(default_factory=lambda: {
        "125 kbit/s": 125000,
        "250 kbit/s": 250000,
        "500 kbit/s": 500000,
        "1 Mbit/s": 1000000,
    })

    # Available data bitrates (CAN FD)
    DATA_BITRATES: dict[str, int] = field(default_factory=lambda: {
        "1 Mbit/s": 1000000,
        "2 Mbit/s": 2000000,
        "4 Mbit/s": 4000000,
        "5 Mbit/s": 5000000,
    })


@dataclass
class UDSSettings:
    """UDS protocol timing and behavior settings."""
    # P2 timeout: max time to wait for a response (ms)
    p2_timeout: int = 5000
    # P2* timeout: extended timeout after NRC 0x78 (ms)
    p2_star_timeout: int = 10000
    # Max number of NRC 0x78 (ResponsePending) retries
    max_response_pending: int = 50


@dataclass
class FlashSettings:
    """Firmware flashing parameters."""
    # Max block size for TransferData (from ECU response to RequestDownload)
    max_block_size: int = 2048
    # Data format identifier for RequestDownload (0x00 = no compression/encryption)
    data_format: int = 0x00
    # Address and length format identifier (0x44 = 4-byte address, 4-byte size)
    address_length_format: int = 0x44
    # Memory erase routine ID
    erase_routine_id: int = 0xFF00
    # Checksum routine ID
    checksum_routine_id: int = 0x0202
    # Pre-programming check routine ID
    pre_check_routine_id: int = 0x0203
    # Check programming dependencies routine ID
    check_deps_routine_id: int = 0xFF01


@dataclass
class IsoTpSettings:
    """ISO 15765-2 transport layer settings."""
    # Separation time minimum (ms) — sent in FC frames
    st_min: int = 10
    # Block size — sent in FC frames (0 = no limit)
    block_size: int = 0
    # Timeout waiting for FC after sending FF (ms)
    fc_timeout: int = 1000
    # Timeout waiting for CF after receiving FF/FC (ms)
    cf_timeout: int = 1000
    # Padding byte for CAN frames shorter than 8 bytes
    padding_byte: int = 0x00
    # Enable frame padding to 8 bytes
    padding_enabled: bool = True
