"""UDS Security Access — TEA-based seed-key computation.

Implements the OEM-specific seed→key algorithm using a variant of the
Tiny Encryption Algorithm (TEA) with 2 rounds.

Algorithm:
    1. Negate each seed byte → seedInversion
    2. Build v[0] from seed (big-endian), v[1] from seedInversion (big-endian)
    3. Select 4-word key by security level
    4. Run TEA encipher with 2 rounds (delta = 0x9E3779B9)
    5. Convert v[0] to 4 big-endian bytes → final key

Reference: Seed_key.txt
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)

# 32-bit mask for unsigned arithmetic
_MASK32 = 0xFFFFFFFF

# TEA keys per security access level (request-seed sub-function)
_TEA_KEYS: dict[int, list[int]] = {
    0x01: [0x00000011, 0x00000022, 0x00000033, 0x00000044],  # Extended Session
    0x03: [0x00000055, 0x00000066, 0x00000077, 0x00000088],  # Programming Session
}


def _tea_encipher(num_rounds: int, v: list[int], k: list[int]) -> None:
    """TEA (Tiny Encryption Algorithm) encipher — modifies *v* in place.

    Args:
        num_rounds: Number of Feistel rounds (OEM uses 2).
        v:          Two-element list [v0, v1] of uint32 values.
        k:          Four-element key schedule [k0, k1, k2, k3].
    """
    v0 = v[0] & _MASK32
    v1 = v[1] & _MASK32
    sum_val = 0
    delta = 0x9E3779B9

    for _ in range(num_rounds):
        mix1 = ((((v1 << 4) & _MASK32) ^ (v1 >> 5)) + v1) & _MASK32
        v0 = (v0 + (mix1 ^ (sum_val + k[sum_val & 3]))) & _MASK32
        sum_val = (sum_val + delta) & _MASK32
        mix2 = ((((v0 << 4) & _MASK32) ^ (v0 >> 5)) + v0) & _MASK32
        v1 = (v1 + (mix2 ^ (sum_val + k[(sum_val >> 11) & 3]))) & _MASK32

    v[0], v[1] = v0, v1


def compute_key(seed: bytes, level: int) -> bytes:
    """Compute the security key from a 4-byte seed.

    Args:
        seed:  4-byte seed received from the ECU (SecurityAccess response).
        level: The request-seed sub-function (0x01 for Extended, 0x03 for Programming).

    Returns:
        4-byte key to send back in the SecurityAccess send-key request.

    Raises:
        ValueError: If seed length is not 4 or level is unsupported.
    """
    if len(seed) != 4:
        raise ValueError(f"Expected 4-byte seed, got {len(seed)} bytes")
    if level not in _TEA_KEYS:
        raise ValueError(f"Unsupported security level: 0x{level:02X}")

    # Step 1: Negate seed bytes
    seed_inv = bytes(~b & 0xFF for b in seed)

    # Step 2: Build v[0] from seed, v[1] from inverted seed (big-endian)
    v0 = int.from_bytes(seed, "big")
    v1 = int.from_bytes(seed_inv, "big")
    v = [v0, v1]

    # Step 3: Select TEA key
    k = _TEA_KEYS[level]

    # Step 4: Encipher
    _tea_encipher(2, v, k)

    # Step 5: Extract first 4 bytes (v[0] as big-endian)
    key = (v[0] & _MASK32).to_bytes(4, "big")

    logger.debug(
        "Security L%d: seed=%s → key=%s",
        level, seed.hex(" ").upper(), key.hex(" ").upper(),
    )
    return key


class SecurityManager:
    """Manage UDS SecurityAccess seed-key computation.

    Supports pluggable key algorithms. Ships with TEA-based OEM default.

    Usage::

        sec = SecurityManager()
        key = sec.compute_key(seed=b'\\xB6\\x7C\\x83\\x8A', level=0x01)
    """

    def __init__(
        self,
        key_function: Optional[callable] = None,
    ) -> None:
        self._compute = key_function or compute_key

    def compute_key(self, seed: bytes, level: int) -> bytes:
        """Compute the key for a given seed and security level."""
        return self._compute(seed, level)
