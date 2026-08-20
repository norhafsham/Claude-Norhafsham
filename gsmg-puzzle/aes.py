"""Pure-Python AES-256-CBC decryption, OpenSSL `enc` compatible.

Written because neither crypto library in this environment is usable: pycryptodome is
absent, and `cryptography` 41.0.7 imports but its Rust binding raises PanicException.
Rather than add an install step to a throwaway analysis rig, this implements the slice
of AES actually needed -- the inverse cipher and OpenSSL's EVP_BytesToKey.

Deliberately not a general implementation. Decryption only, AES-256 only, no encryption
path and no constant-time guarantees. It exists to answer "does this passphrase decrypt
this blob", and it is checked against the real openssl binary in test_aes.py.

The S-box and GF multiplication tables are derived at import rather than pasted as
literals, so there is no transcription risk.

Format reference: FIPS-197, and openssl's crypto/evp/evp_key.c for the KDF.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

BLOCK_SIZE = 16
SALT_MAGIC = b"Salted__"
_NK = 8  # 256-bit key = 8 words
_NR = 14  # 14 rounds for AES-256


def _build_tables() -> tuple[list[int], list[int], list[list[int]]]:
    """Derive the S-box, inverse S-box, and the 9/11/13/14 GF(2^8) product tables."""
    exp, log = [0] * 512, [0] * 256
    x = 1
    for i in range(255):
        exp[i] = x
        log[x] = i
        x ^= ((x << 1) ^ (0x1B if x & 0x80 else 0)) & 0xFF  # multiply by 3
    for i in range(255, 512):
        exp[i] = exp[i - 255]

    def mul(a: int, b: int) -> int:
        return 0 if a == 0 or b == 0 else exp[log[a] + log[b]]

    sbox = [0] * 256
    for i in range(256):
        inv = 0 if i == 0 else exp[255 - log[i]]
        s = inv
        for _ in range(4):
            s = ((s << 1) | (s >> 7)) & 0xFF
            inv ^= s
        sbox[i] = inv ^ 0x63

    inv_sbox = [0] * 256
    for i, s in enumerate(sbox):
        inv_sbox[s] = i

    muls = [[mul(c, b) for b in range(256)] for c in (9, 11, 13, 14)]
    return sbox, inv_sbox, muls


_SBOX, _INV_SBOX, (_M9, _M11, _M13, _M14) = _build_tables()
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _expand_key(key: bytes) -> list[list[int]]:
    """AES-256 key schedule -> 15 round keys of 16 bytes each."""
    words = [list(key[i : i + 4]) for i in range(0, 32, 4)]
    for i in range(_NK, 4 * (_NR + 1)):
        t = list(words[i - 1])
        if i % _NK == 0:
            t = t[1:] + t[:1]  # RotWord
            t = [_SBOX[b] for b in t]
            t[0] ^= _RCON[i // _NK - 1]
        elif i % _NK == 4:
            t = [_SBOX[b] for b in t]
        words.append([a ^ b for a, b in zip(words[i - _NK], t, strict=True)])
    return [[b for w in words[4 * r : 4 * r + 4] for b in w] for r in range(_NR + 1)]


def decrypt_block(block: bytes, round_keys: list[list[int]]) -> bytes:
    """Inverse cipher on a single 16-byte block."""
    s = [b ^ k for b, k in zip(block, round_keys[_NR], strict=True)]
    for rnd in range(_NR - 1, -1, -1):
        # InvShiftRows: row r rotates right by r; flat index is 4*col + row.
        s = [s[(4 * ((c - r) % 4)) + r] for c in range(4) for r in range(4)]
        s = [_INV_SBOX[b] for b in s]
        rk = round_keys[rnd]
        s = [b ^ k for b, k in zip(s, rk, strict=True)]
        if rnd:  # every round but the last applies InvMixColumns
            out = []
            for c in range(0, 16, 4):
                a0, a1, a2, a3 = s[c : c + 4]
                out += [
                    _M14[a0] ^ _M11[a1] ^ _M13[a2] ^ _M9[a3],
                    _M9[a0] ^ _M14[a1] ^ _M11[a2] ^ _M13[a3],
                    _M13[a0] ^ _M9[a1] ^ _M14[a2] ^ _M11[a3],
                    _M11[a0] ^ _M13[a1] ^ _M9[a2] ^ _M14[a3],
                ]
            s = out
    return bytes(s)


def evp_bytes_to_key(password: bytes, salt: bytes) -> tuple[bytes, bytes]:
    """OpenSSL's EVP_BytesToKey with SHA-256 and count=1 -> (32-byte key, 16-byte IV).

    SHA-256 is the default digest for `openssl enc` since 1.1.0. The pre-1.1.0 default
    was MD5; the GSMG blobs are SHA-256, which ANALYSIS.md records as a control result.
    """
    material, prev = b"", b""
    while len(material) < 48:
        prev = hashlib.sha256(prev + password + salt).digest()
        material += prev
    return material[:32], material[32:48]


def strip_padding(plaintext: bytes) -> bytes | None:
    """Remove PKCS#7 padding, or return None if it is not well formed."""
    if not plaintext:
        return None
    pad = plaintext[-1]
    if not 1 <= pad <= BLOCK_SIZE or len(plaintext) < pad:
        return None
    if plaintext[-pad:] != bytes([pad]) * pad:
        return None
    return plaintext[:-pad]


@dataclass(frozen=True)
class Blob:
    """A parsed OpenSSL `Salted__` container."""

    salt: bytes
    ciphertext: bytes

    @classmethod
    def parse(cls, raw: bytes) -> Blob:
        if not raw.startswith(SALT_MAGIC):
            raise ValueError("not an OpenSSL salted blob")
        body = raw[len(SALT_MAGIC) + 8 :]
        if not body or len(body) % BLOCK_SIZE:
            raise ValueError(f"ciphertext is {len(body)} bytes, not a multiple of 16")
        return cls(salt=raw[8:16], ciphertext=body)

    @property
    def blocks(self) -> int:
        return len(self.ciphertext) // BLOCK_SIZE

    def padding_ok(self, password: bytes) -> bool:
        """Cheap filter: is the *last* block's padding well formed?

        CBC makes the final plaintext block depend only on the last two ciphertext
        blocks, so a candidate costs one block-decrypt regardless of blob size. This is
        the hot path -- a wrong passphrase survives it with probability ~1/256.
        """
        key, iv = evp_bytes_to_key(password, self.salt)
        prev = self.ciphertext[-2 * BLOCK_SIZE : -BLOCK_SIZE] if self.blocks > 1 else iv
        last = decrypt_block(self.ciphertext[-BLOCK_SIZE:], _expand_key(key))
        return strip_padding(bytes(a ^ b for a, b in zip(last, prev, strict=True))) is not None

    def decrypt(self, password: bytes) -> bytes | None:
        """Full CBC decrypt. Returns the unpadded plaintext, or None on bad padding."""
        key, iv = evp_bytes_to_key(password, self.salt)
        round_keys = _expand_key(key)
        out, prev = bytearray(), iv
        for i in range(0, len(self.ciphertext), BLOCK_SIZE):
            block = self.ciphertext[i : i + BLOCK_SIZE]
            clear = decrypt_block(block, round_keys)
            out += bytes(a ^ b for a, b in zip(clear, prev, strict=True))
            prev = block
        return strip_padding(bytes(out))
