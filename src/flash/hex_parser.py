"""Firmware file parser — .hex / .bin / .s19 support via bincopy.

Parses firmware image files into a structured representation with memory
segments, providing helpers for the flash workflow (address range, CRC,
block iteration).

Usage::

    parser = FirmwareParser()
    image = parser.parse("firmware.hex")
    print(f"Address: 0x{image.start_address:08X}, Size: {image.total_size}")
    for block in image.iter_blocks(block_size=2046):
        # send block via TransferData
        pass
"""

import logging
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

import bincopy

logger = logging.getLogger(__name__)


class FirmwareParseError(Exception):
    """Raised when a firmware file cannot be parsed."""


@dataclass
class MemorySegment:
    """A contiguous region of firmware data."""
    address: int
    data: bytes

    @property
    def size(self) -> int:
        return len(self.data)

    @property
    def end_address(self) -> int:
        return self.address + self.size


class FirmwareImage:
    """Parsed firmware image with one or more memory segments.

    Attributes:
        file_path: Original file path.
        segments:  List of contiguous memory segments.
    """

    def __init__(self, file_path: str, segments: list[MemorySegment]) -> None:
        self.file_path = file_path
        self.segments = segments
        self._download_address: Optional[int] = None

    @property
    def download_address(self) -> int:
        """Address sent to ECU in RequestDownload (0x34) and Erase RoutineControl.

        Defaults to start_address (the address embedded in the firmware file),
        but can be overridden by the UI when the user types a different address.
        """
        if self._download_address is not None:
            return self._download_address
        return self.start_address

    @download_address.setter
    def download_address(self, value: int) -> None:
        self._download_address = value

    @property
    def start_address(self) -> int:
        """Lowest memory address across all segments."""
        if not self.segments:
            return 0
        return min(s.address for s in self.segments)

    @property
    def end_address(self) -> int:
        """Highest memory address (exclusive) across all segments."""
        if not self.segments:
            return 0
        return max(s.end_address for s in self.segments)

    @property
    def total_size(self) -> int:
        """Total byte count across all segments."""
        return sum(s.size for s in self.segments)

    @property
    def data(self) -> bytes:
        """Concatenated data from all segments (in address order).

        Note: gaps between segments are NOT filled. Use this only when
        you know the image has a single contiguous region or when the
        flash workflow handles segments individually.
        """
        return b"".join(s.data for s in self.segments)

    def crc32(self) -> int:
        """Compute CRC-32 over the concatenated firmware data."""
        crc = 0
        for seg in self.segments:
            crc = zlib.crc32(seg.data, crc)
        return crc & 0xFFFFFFFF

    def iter_blocks(self, block_size: int) -> Iterator[bytes]:
        """Yield firmware data in fixed-size blocks for TransferData.

        The last block may be shorter than *block_size*.

        Args:
            block_size: Max bytes per block (e.g. 2046 for 2048-byte
                        TransferData with 2-byte header).

        Yields:
            Data chunks of up to *block_size* bytes.
        """
        data = self.data
        offset = 0
        while offset < len(data):
            yield data[offset:offset + block_size]
            offset += block_size

    def __repr__(self) -> str:
        return (
            f"FirmwareImage(file={Path(self.file_path).name!r}, "
            f"segments={len(self.segments)}, "
            f"addr=0x{self.start_address:08X}..0x{self.end_address:08X}, "
            f"size={self.total_size})"
        )


class FirmwareParser:
    """Parse firmware files into FirmwareImage objects.

    Supports Intel HEX (.hex), Motorola S-record (.s19/.srec), and
    raw binary (.bin) formats via the ``bincopy`` library.
    """

    # Map file extensions to bincopy parse methods
    _PARSERS = {
        ".hex": "add_ihex",
        ".ihex": "add_ihex",
        ".s19": "add_srec",
        ".srec": "add_srec",
        ".s": "add_srec",
    }

    def parse(self, file_path: str, base_address: int = 0) -> FirmwareImage:
        """Parse a firmware file.

        Args:
            file_path:    Path to the firmware file.
            base_address: Base address for raw .bin files (ignored for
                          .hex/.s19 which embed addresses).

        Returns:
            A FirmwareImage with parsed memory segments.

        Raises:
            FirmwareParseError: If the file cannot be read or parsed.
        """
        path = Path(file_path)
        if not path.exists():
            raise FirmwareParseError(f"File not found: {file_path}")

        ext = path.suffix.lower()
        logger.info("Parsing firmware file: %s (format: %s)", path.name, ext)

        try:
            if ext == ".bin":
                return self._parse_bin(path, base_address)
            else:
                return self._parse_formatted(path, ext)
        except FirmwareParseError:
            raise
        except Exception as exc:
            raise FirmwareParseError(f"Failed to parse {path.name}: {exc}") from exc

    def _parse_formatted(self, path: Path, ext: str) -> FirmwareImage:
        """Parse Intel HEX or Motorola S-record files."""
        method_name = self._PARSERS.get(ext)
        if method_name is None:
            raise FirmwareParseError(f"Unsupported file format: {ext}")

        bc = bincopy.BinFile()
        content = path.read_text(encoding="ascii", errors="replace")
        getattr(bc, method_name)(content)

        if len(bc) == 0:
            raise FirmwareParseError(f"No data found in {path.name}")

        segments = []
        for segment in bc.segments:
            seg = MemorySegment(
                address=segment.minimum_address,
                data=bytes(segment.data),
            )
            segments.append(seg)
            logger.debug(
                "Segment: 0x%08X..0x%08X (%d bytes)",
                seg.address, seg.end_address, seg.size,
            )

        image = FirmwareImage(str(path), segments)
        logger.info(
            "Parsed %s: %d segment(s), %d bytes total, "
            "address range 0x%08X..0x%08X",
            path.name, len(segments), image.total_size,
            image.start_address, image.end_address,
        )
        return image

    def _parse_bin(self, path: Path, base_address: int) -> FirmwareImage:
        """Parse raw binary files."""
        data = path.read_bytes()
        if not data:
            raise FirmwareParseError(f"Empty binary file: {path.name}")

        segment = MemorySegment(address=base_address, data=data)
        image = FirmwareImage(str(path), [segment])

        logger.info(
            "Parsed %s: binary, %d bytes at 0x%08X",
            path.name, len(data), base_address,
        )
        return image
