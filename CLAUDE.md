# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# MCU Flash Tool

Desktop application for flashing MCU firmware over CAN bus using UDS protocol (ISO 14229) with PCAN USB FD hardware.

## Commands
- `pip install -r requirements.txt` — install dependencies (PySide6, python-can, bincopy)
- `cd src && python main.py` — launch the GUI application (must run from `src/` directory due to relative imports)
- `cd src && python test_pcan.py` — quick hardware connectivity test (sends DiagnosticSessionControl to ECU)

## Architecture

Four-layer stack, each layer only depends on the one below it:

```
UI Layer (PySide6)
  └─ main_window.py → composes all widgets, manages PCANDriver/Flasher lifecycle
  └─ flash_worker.py → FlashWorker(QThread) bridges Flasher callbacks to Qt signals
  └─ widgets/ → ConnectionPanel, FileSelector, FlashProgressBar, LogViewer, StatusIndicator
Flash Layer
  └─ flasher.py  → orchestrates 14-step OEM sequence via callbacks (on_progress, on_log, on_state_changed)
  └─ hex_parser.py → parses .hex/.s19/.bin via bincopy into FirmwareImage with segments
UDS Layer (ISO 14229)
  └─ services.py → UDSClient wraps all 7 UDS services, handles NRC 0x78 ResponsePending loop
  └─ security.py → TEA-based seed→key algorithm (2 rounds, level-dependent keys)
CAN/Transport Layer
  └─ transport.py → IsoTpTransport handles SF/FF/CF/FC segmentation (ISO 15765-2)
  └─ pcan_driver.py → PCANDriver wraps python-can for PCAN USB adapters
Config
  └─ settings.py → dataclasses: CANSettings, UDSSettings, FlashSettings, IsoTpSettings
  └─ constants.py → enums: UDSServiceID, NRC, IsoTpFrameType, FlowStatus + protocol constants
```

**Key data flow**: `Flasher` creates `IsoTpTransport(PCANDriver)` → creates `UDSClient(transport)` + `SecurityManager` → runs steps 1-14 sequentially, reporting progress via callbacks.

**Threading model**: `FlashWorker(QThread)` runs `Flasher.execute()` off the main thread. Flasher callbacks are assigned to `Signal.emit` — Qt auto-queues cross-thread delivery so UI slots run on the main thread.

## CAN Configuration Defaults
- **Request ID (Tester → ECU)**: 0x7A2 / **Response ID (ECU → Tester)**: 0x7AA (configurable)
- **CAN FD**: enabled (fd=True, bitrate_switch=True), DLC always 8 bytes
- **Arbitration**: 500 kbit/s / **Data**: 2 Mbit/s
- **Padding**: Tester uses 0xCC (IsoTpSettings default), ECU uses 0x55

## Flashing Workflow (14 steps, from OEM trace)
1. DiagnosticSessionControl (0x10 0x03) — Extended Session
2. SecurityAccess L1/L2 (0x27 0x01/0x02) — TEA key with k=[0x11,0x22,0x33,0x44]
3. RoutineControl (0x31 0x01 0x0203) — Pre-programming check
4. DiagnosticSessionControl (0x10 0x02) — Programming Session
5. SecurityAccess L3/L4 (0x27 0x03/0x04) — TEA key with k=[0x55,0x66,0x77,0x88]
6. RoutineControl (0x31 0x01 0xFF00) — Erase Memory (format=0x44, ~2.6s)
7. RequestDownload (0x34) — addr + size, format=0x44, no compression
8. TransferData (0x36) — max 2048 bytes/block, counter wraps 01→FF→00
9. RequestTransferExit (0x37)
10. RoutineControl (0x31 0x01 0x0202) — CRC checksum (~2.3s)
11. RoutineControl (0x31 0x01 0xFF01) — Check dependencies
12. ECUReset (0x11 0x01) — Hard Reset

## Seed-Key Algorithm (TEA variant)
Reference implementation: `Seed_key.txt` (C code). Python implementation: `src/uds/security.py`.
- Negate seed bytes → seedInversion
- v[0] = seed as big-endian uint32, v[1] = seedInversion as big-endian uint32
- TEA encipher(2 rounds, v, k) with delta=0x9E3779B9
- Result: v[0] as 4 big-endian bytes = key

## Flashing Parameters (from trace)
- Erase address: 0x00040000, size: 0x00086760 (550,752 bytes)
- addressAndLengthFormatIdentifier: 0x44 (4-byte address, 4-byte size)
- dataFormatIdentifier: 0x00 (no compression, no encryption)
- Max block size: 2048 bytes (ECU response 0x74 0x20 0x0800)

## Coding Conventions
- Python 3.10+ with type hints, PEP 8
- Use `logging` module (never `print()` in production code)
- CAN/UDS layers must be decoupled from UI (communicate via callbacks, not Qt signals directly)
- The `canbus/` package is named to avoid shadowing the `can` package from python-can
- Handle UDS negative responses (NRC) and CAN timeouts gracefully per ISO specs

## Important Notes
- Respond in English when explaining; use English for code and comments
- Assume PCAN USB as default hardware
- Ask before making architectural changes
- When the user asks a question or describes a problem, first rephrase it in polished, natural English before answering
