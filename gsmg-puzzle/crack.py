"""Try candidate passphrases against the unsolved GSMG.IO AES blobs.

Two-stage check per candidate. Stage one decrypts only the final CBC block and tests its
PKCS#7 padding -- one block-decrypt regardless of blob size, ~7.6k candidates/sec here,
against ~200/sec if we shelled out to `openssl` for each. Stage one lets roughly 1 in 256
wrong passphrases through, so stage two fully decrypts the survivors and scores them for
printable text before anything is reported.

Every passphrase is tried in four encodings, because the solved stages used the digest
rather than the phrase: the raw string, its lowercase SHA-256 hex, that hex uppercased,
and the digest of the digest.

Decryption defaults to AES-256-CBC with a SHA-256 KDF, which is what the puzzle states for
its *solved* phases. The unsolved blobs state no cipher, so `--all-params` sweeps all nine
combinations of key size and digest rather than inheriting that assumption.

    python3 crack.py --self-test          # controls; run this before trusting a result
    python3 crack.py --blob a             # the 5-block blob embedded in SalPhaseIon
    python3 crack.py --blob b             # the 83-block Cosmic Duality blob
    python3 crack.py --blob b --all-params            # every cipher x digest
    python3 crack.py --blob b --key-size 16 --digest md5
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import string
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import aes
import candidates
import compose
import phrases
import score
from aes import Blob

DATA = Path(__file__).parent / "data"
BLOBS = {
    "a": "blob_a.b64",  # 5 blocks, embedded in the SalPhaseIon letter block
    "b": "blob_b.b64",  # 83 blocks, the Cosmic Duality textarea
    "c": "blob_c.b64",  # 5 blocks, trailing the decrypted phase-3.2 plaintext
    "known": "known_phase32.b64",  # solved; positive control only
}

# The passphrase for the phase-3.2 blob, published in the puzzle README. Used as a
# positive control: a rig that cannot rediscover this cannot be trusted to report "no hit".
KNOWN_PASSWORD = b"250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c"

_PRINTABLE = set(bytes(string.printable, "ascii"))


class EmptySweep(RuntimeError):
    """Raised when a sweep tried no candidates at all.

    Deliberately an exception rather than a printed warning: a zero-candidate run has the
    same output shape and the same exit code as a real exhaustive negative, so anything
    quieter can be scrolled past and written down as a result.
    """


def load(name: str) -> Blob:
    raw = base64.b64decode((DATA / BLOBS[name]).read_text().strip())
    return Blob.parse(raw)


def encodings(candidate: str) -> Iterator[bytes]:
    """The four passphrase forms the puzzle's conventions make plausible."""
    yield candidate.encode()
    digest = hashlib.sha256(candidate.encode()).hexdigest()
    yield digest.encode()
    yield digest.upper().encode()
    yield hashlib.sha256(digest.encode()).hexdigest().encode()


def printable_ratio(data: bytes) -> float:
    return sum(b in _PRINTABLE for b in data) / len(data) if data else 0.0


def longest_printable_span(data: bytes) -> bytes:
    """The longest unbroken stretch of printable ASCII.

    This, not the printable *ratio*, is the discriminator. The known phase-3.2 plaintext is
    only 60% printable because it embeds box-drawing characters and a base64 blob, so a
    ratio threshold rejects a correct decryption. Spans separate cleanly instead: the real
    plaintext's is 447 characters, while wrong keys on a blob that size top out near 15.
    """
    best = current = b""
    for byte in data:
        current = current + bytes([byte]) if byte in _PRINTABLE else b""
        if len(current) > len(best):
            best = current
    return best


def longest_printable_run(data: bytes) -> int:
    return len(longest_printable_span(data))


def is_hit(plaintext: bytes, min_run: int) -> bool:
    """Whether a padding survivor is really a decryption.

    Length alone is not enough at scale. A wrong key's longest span tops out near 15 on a
    2.4 KB blob, but a sweep of a million candidates leaves thousands of padding survivors,
    and roughly one in 1300 of those clears 16 by chance -- which is exactly how the first
    run of the phrase control reported three hits on a blob with one known key. So the span
    also has to read as language, judged by the calibrated scorer.
    """
    span = longest_printable_span(plaintext)
    if len(span) < min_run:
        return False
    return score.confident(span.decode("ascii", "replace"))


def search(
    blob: Blob,
    source: Iterator[str],
    min_run: int = 16,
    digest: str = aes.DEFAULT_DIGEST,
    key_size: int = aes.DEFAULT_KEY_SIZE,
) -> list[tuple[bytes, bytes]]:
    """Run the corpus against a blob. Returns [(passphrase, plaintext)] for real hits.

    `digest` and `key_size` default to the values the solved stages state. They are
    parameters because the unsolved blobs never state a cipher -- see ANALYSIS.md.
    """
    hits: list[tuple[bytes, bytes]] = []
    ranked: list[tuple[int, bytes, bytes]] = []
    tried = survivors = 0
    start = time.perf_counter()

    for candidate in source:
        for password in encodings(candidate):
            tried += 1
            if not blob.padding_ok(password, digest, key_size):
                continue
            # ~1/256 of wrong passphrases reach here by chance; stage two sorts them out.
            survivors += 1
            plaintext = blob.decrypt(password, digest, key_size)
            if plaintext is None:
                continue
            run = longest_printable_run(plaintext)
            ranked.append((run, password, plaintext))
            if is_hit(plaintext, min_run):
                hits.append((password, plaintext))
                print(f"\n*** HIT  passphrase={password.decode()!r}  run={run}")
                print(plaintext.decode("utf-8", "replace"))

    elapsed = time.perf_counter() - start
    rate = tried / elapsed if elapsed else 0
    if not tried:
        # An empty source must never look like a completed sweep. The whole product of this
        # directory is trustworthy negatives, and "searched nothing, found nothing" prints
        # identically to "searched a million, found nothing" unless it is called out.
        raise EmptySweep(
            "the candidate source produced nothing, so this is not a negative result"
        )
    print(
        f"\ntried={tried:,} in {elapsed:.1f}s ({rate:,.0f}/sec)  "
        f"padding-survivors={survivors}  real-hits={len(hits)}"
    )
    # Show the best near-misses so a marginal result is never silently dropped.
    for run, password, plaintext in sorted(ranked, reverse=True, key=lambda r: r[0])[:5]:
        if run < min_run:
            print(
                f"  best-effort run={run:3d} printable={printable_ratio(plaintext):.0%} "
                f"pass={password[:40].decode()}"
            )
    return hits


def self_test() -> bool:
    """Controls that must pass before any negative result is meaningful."""
    ok = True

    def report(label: str, passed: bool) -> bool:
        print(f"{label:<52} {'PASS' if passed else 'FAIL'}")
        return passed

    known = load("known")
    plaintext = known.decrypt(KNOWN_PASSWORD)
    ok &= report(
        "positive control (known passphrase decrypts)",
        plaintext is not None and plaintext.startswith(b"I've been waiting for you."),
    )
    ok &= report("negative control (random key rejected)", known.decrypt(b"deadbeef" * 8) is None)

    found = search(known, iter([KNOWN_PASSWORD.decode()]))
    ok &= report("end-to-end (search finds the known passphrase)", len(found) == 1)

    for name in ("a", "b", "c"):
        blob = load(name)
        print(f"blob {name}: {blob.blocks} blocks, salt={blob.salt.hex()}")

    return ok


def phrase_control() -> bool:
    """Control for the phrase sweep: recover a known key through the whole pipeline.

    The phase-3.2 passphrase is the SHA-256 of three quote answers run together, which is
    exactly the shape the phrase sweep assumes. Requiring the sweep to rediscover it --
    window -> lowercase-and-strip -> SHA-256 -> decrypt -- is what makes a negative on the
    Cosmic Duality blob mean something.
    """
    found = search(load("known"), phrases.generate())
    ok = len(found) == 1
    print(f"phrase pipeline recovers the known phase-3.2 key: {'PASS' if ok else 'FAIL'}")
    return ok


def _positive(value: str) -> int:
    """A word cap below 1 yields no candidates at all, so reject it at the boundary."""
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError(f"must be 1 or greater, got {number}")
    return number


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--blob", choices=sorted(BLOBS), help="which ciphertext to attack")
    parser.add_argument("--self-test", action="store_true", help="run controls and exit")
    parser.add_argument("--source", choices=["terms", "phrases", "compose"], default="terms",
                        help="terms: short strings; phrases: word windows; "
                             "compose: answer concatenations")
    parser.add_argument("--phrase-control", action="store_true",
                        help="check the phrase pipeline recovers a known key, then exit")
    parser.add_argument("--max-words", type=_positive, help="cap phrase length in words")
    parser.add_argument("--digest", choices=aes.DIGESTS, default=aes.DEFAULT_DIGEST,
                        help="KDF digest (the solved stages use sha256)")
    parser.add_argument("--key-size", type=int, choices=sorted(aes.ROUNDS),
                        default=aes.DEFAULT_KEY_SIZE, help="AES key bytes: 16, 24 or 32")
    parser.add_argument("--all-params", action="store_true",
                        help="sweep every cipher x digest combination, not just the default")
    parser.add_argument("--max-terms", type=int, default=2, help="concatenation depth")
    parser.add_argument("--no-thematic", action="store_true", help="drop SPECULATIVE seeds")
    args = parser.parse_args()

    if args.self_test:
        return 0 if self_test() else 1
    if args.phrase_control:
        return 0 if phrase_control() else 1
    if not args.blob:
        parser.error("pass --blob, --self-test or --phrase-control")

    blob = load(args.blob)
    print(f"blob {args.blob}: {blob.blocks} blocks, salt={blob.salt.hex()}")

    def build_source() -> Iterator[str]:
        """Fresh generator per parameter combination -- an iterator is consumed once."""
        if args.source == "phrases":
            return phrases.generate(max_words=args.max_words)
        if args.source == "compose":
            return compose.generate()
        return candidates.generate(max_terms=args.max_terms, thematic=not args.no_thematic)

    if args.source == "phrases":
        print(phrases.describe())
    elif args.source == "compose":
        print(compose.describe())

    if args.all_params:
        combos = [(d, k) for k in sorted(aes.ROUNDS) for d in aes.DIGESTS]
    else:
        combos = [(args.digest, args.key_size)]

    hits = []
    for digest, key_size in combos:
        if len(combos) > 1:
            print(f"\n--- aes-{key_size * 8}-cbc / {digest} ---")
        hits += search(blob, build_source(), digest=digest, key_size=key_size)
    return 0 if hits else 1


if __name__ == "__main__":
    sys.exit(main())
