"""Checks the pure-Python AES against FIPS-197 and against the real openssl binary.

The point of the parity test is that a negative cracking result is only worth as much as
the rig producing it. If this implementation disagreed with openssl anywhere, "no hits"
would mean nothing.
"""

from __future__ import annotations

import base64
import hashlib
import subprocess
from pathlib import Path

import aes
import crack
import pytest

DATA = Path(__file__).parent / "data"


def openssl_accepts(b64: str, password: str) -> bool:
    """True when `openssl enc -d` exits 0, i.e. the padding validated."""
    result = subprocess.run(
        ["openssl", "enc", "-aes-256-cbc", "-d", "-a", "-md", "sha256",
         "-pass", f"pass:{password}"],
        input=b64.encode(),
        capture_output=True,
    )
    return result.returncode == 0


@pytest.mark.parametrize(
    ("key_size", "ciphertext", "rounds"),
    [
        (16, "69c4e0d86a7b0430d8cdb78070b4c55a", 10),  # FIPS-197 C.1
        (24, "dda97ca4864cdfe06eaf70a0ec0d7191", 12),  # FIPS-197 C.2
        (32, "8ea2b7ca516745bfeafc49904b496089", 14),  # FIPS-197 C.3
    ],
)
def test_fips197_inverse_cipher(key_size, ciphertext, rounds):
    """All three key sizes. AES-192 is the one that catches key-schedule mistakes.

    The `i % nk == 4` sub-word step applies only when nk > 6; running it for AES-192
    produces a plausible-looking schedule that is simply wrong.
    """
    round_keys = aes._expand_key(bytes(range(key_size)))
    assert len(round_keys) - 1 == rounds
    plaintext = aes.decrypt_block(bytes.fromhex(ciphertext), round_keys)
    assert plaintext.hex() == "00112233445566778899aabbccddeeff"


def test_key_expansion_rejects_a_bad_key_length():
    with pytest.raises(ValueError):
        aes._expand_key(bytes(20))


@pytest.mark.parametrize("key_size", [16, 24, 32])
@pytest.mark.parametrize("digest", ["md5", "sha1", "sha256"])
def test_parity_with_openssl_across_every_cipher_and_digest(key_size, digest):
    """Encrypt with the real openssl, decrypt with this implementation. All nine combos.

    The unsolved blobs never state a cipher -- the README only claims they share the
    *container* format -- so the sweep has to be able to vary these. Widening the cipher
    core is the risky part of that, and this is what makes it safe.
    """
    plaintext = b"Cosmic Duality parity probe -- pack my box with five dozen liquor jugs.\n"
    password = "parity-password"
    encrypted = subprocess.run(
        ["openssl", "enc", f"-aes-{key_size * 8}-cbc", "-a", "-md", digest,
         "-pass", f"pass:{password}"],
        input=plaintext, capture_output=True, check=True,
    )
    blob = aes.Blob.parse(base64.b64decode(encrypted.stdout))
    assert blob.decrypt(password.encode(), digest=digest, key_size=key_size) == plaintext

    wrong = blob.decrypt(b"not-the-password", digest=digest, key_size=key_size)
    assert wrong != plaintext


def test_defaults_still_describe_the_solved_stages():
    """The default path must not drift: the solved blobs state aes-256-cbc with sha256."""
    assert aes.DEFAULT_KEY_SIZE == 32
    assert aes.DEFAULT_DIGEST == "sha256"
    assert aes.ROUNDS[32] == 14


def test_evp_bytes_to_key_matches_openssl():
    """Derived key/IV must match openssl's own -P output for the same salt."""
    salt = bytes.fromhex("3ab585348552415d")
    key, iv = aes.evp_bytes_to_key(b"testpassword", salt)
    result = subprocess.run(
        ["openssl", "enc", "-aes-256-cbc", "-md", "sha256", "-pass", "pass:testpassword",
         "-S", salt.hex(), "-P"],
        capture_output=True, text=True, check=True,
    )
    # openssl prints the IV field as "iv =...", so keys need stripping too.
    fields = {
        name.strip(): value.strip()
        for name, _, value in (line.partition("=") for line in result.stdout.splitlines())
        if _
    }
    assert key.hex().upper() == fields["key"]
    assert iv.hex().upper() == fields["iv"]


def test_known_blob_decrypts_to_expected_plaintext():
    blob = crack.load("known")
    plaintext = blob.decrypt(crack.KNOWN_PASSWORD)
    assert plaintext is not None
    assert plaintext.startswith(b"I've been waiting for you.")


def test_wrong_password_rejected():
    assert crack.load("known").decrypt(b"not-the-password") is None


@pytest.mark.parametrize("name", ["a", "b", "c"])
def test_unsolved_blobs_are_wellformed(name):
    """Each blob must be a complete OpenSSL container with a whole number of blocks."""
    blob = crack.load(name)
    assert len(blob.salt) == 8
    assert blob.blocks >= 5


def test_parity_with_openssl_across_many_candidates():
    """The pure-Python padding verdict must match openssl's exit code, candidate for candidate."""
    b64 = (DATA / "blob_a.b64").read_text().strip()
    blob = crack.load("a")

    passwords = [crack.KNOWN_PASSWORD.decode()]
    passwords += [hashlib.sha256(f"parity{i}".encode()).hexdigest() for i in range(60)]
    passwords += [f"plain{i}" for i in range(40)]

    disagreements = [
        p for p in passwords if blob.padding_ok(p.encode()) != openssl_accepts(b64, p)
    ]
    assert not disagreements, f"pure-Python disagreed with openssl on: {disagreements}"


def test_longest_printable_run_separates_text_from_noise():
    """The scorer must accept the known plaintext, which is only ~60% printable ASCII."""
    plaintext = crack.load("known").decrypt(crack.KNOWN_PASSWORD)
    assert crack.printable_ratio(plaintext) < 0.9  # why a ratio threshold fails
    assert crack.longest_printable_run(plaintext) > 100

    noise = base64.b64decode("3q2+7wAAAAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f")
    assert crack.longest_printable_run(noise) < 16
