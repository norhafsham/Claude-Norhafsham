"""Sweep candidate decodings of the SalPhaseIon letter block and rank them.

Built as three composable stages so combinations can be swept rather than hand-tried:

    mask  ->  reader  ->  decoder

A *mask* optionally combines the digits with key material (the 14x14 first puzzle piece).
A *reader* reorders them (identity, or a transposition through some rectangle). A *decoder*
turns the reordered digit string into text.

The point of the sweep is not that one of these is likely to be right. It is that the same
machinery re-derives the four decodings already known to be correct, so a negative result on
the two undecoded regions means something. `--rediscover` runs exactly that control.

    python3 decode.py --rediscover     # must recover the four known plaintexts
    python3 decode.py --region A       # sweep one undecoded region
    python3 decode.py --all            # sweep everything
"""

from __future__ import annotations

import argparse
import random
import string
import sys
from collections.abc import Callable, Iterator
from dataclasses import dataclass

import block
import score as scoring

DIGIT_ALPHABET = "abcdefghi"
KEY_STRINGS = ["matrixsumlist", "thematrixhasyou", "causality", "salphaseion", "cosmicduality"]


@dataclass(frozen=True)
class Candidate:
    chain: str
    text: str
    value: float


# --------------------------------------------------------------------------- masks


def mask_none(digits: str) -> str:
    return digits


def _spiral_bits() -> list[int]:
    return block.spiral_ccw(block.load_matrix())


def mask_xor_spiral(digits: str) -> str:
    """XOR each digit's value with the repeating spiral bit stream from puzzle piece one."""
    bits = _spiral_bits()
    out = []
    for i, char in enumerate(digits):
        value = ord(char) - ord("a")
        out.append(chr(ord("a") + (value ^ bits[i % len(bits)]) % 9))
    return "".join(out)


def mask_add_spiral(digits: str) -> str:
    """Add the repeating spiral bit stream to each digit, modulo 9."""
    bits = _spiral_bits()
    return "".join(
        chr(ord("a") + (ord(c) - ord("a") + bits[i % len(bits)]) % 9) for i, c in enumerate(digits)
    )


MASKS: dict[str, Callable[[str], str]] = {
    "plain": mask_none,
    "xor-spiral": mask_xor_spiral,
    "add-spiral": mask_add_spiral,
}


# ------------------------------------------------------------------------- readers


def _rectangles(length: int) -> list[tuple[int, int]]:
    return [(r, length // r) for r in range(2, length) if length % r == 0 and length // r > 1]


def readers_for(digits: str) -> Iterator[tuple[str, str]]:
    """Yield (name, reordered digits): identity plus transpositions through each rectangle."""
    yield "identity", digits
    for rows, cols in _rectangles(len(digits)):
        grid = [digits[r * cols : (r + 1) * cols] for r in range(rows)]
        yield f"cols{rows}x{cols}", "".join(grid[r][c] for c in range(cols) for r in range(rows))
        yield f"boustro{rows}x{cols}", "".join(
            row if i % 2 == 0 else row[::-1] for i, row in enumerate(grid)
        )


# ------------------------------------------------------------------------ decoders


def decode_binary(digits: str) -> str | None:
    """a/b runs are bits."""
    if set(digits) - set("ab"):
        return None
    bits = digits.replace("a", "0").replace("b", "1")
    return "".join(chr(int(bits[i : i + 8], 2)) for i in range(0, len(bits) // 8 * 8, 8))


def decode_base16(digits: str) -> str | None:
    """The published method: digits -> decimal integer -> base 16 -> bytes."""
    if set(digits) - set(block.DIGITS + block.ZERO):
        return None
    hexed = f"{int(digits.translate(block.DIGIT_MAP)):x}"
    raw = bytes.fromhex(("0" + hexed) if len(hexed) % 2 else hexed)
    return raw.decode("ascii", "replace")


def _chunk(digits: str, size: int, offset: int, base: int) -> str:
    out = []
    for i in range(0, len(digits) - size + 1, size):
        value = 0
        for char in digits[i : i + size]:
            value = value * base + (ord(char) - ord("a") + offset)
        out.append(chr(value % 256))
    return "".join(out)


def _group_a1z26(digits: str, size: int, op: str) -> str:
    out = []
    for i in range(0, len(digits) - size + 1, size):
        values = [ord(c) - ord("a") + 1 for c in digits[i : i + size]]
        total = sum(values) if op == "sum" else _product(values)
        letter = (total - 1) % 26
        out.append(chr(ord("a") + letter))
    return "".join(out)


def _product(values: list[int]) -> int:
    result = 1
    for value in values:
        result *= value
    return result


def _polybius_square(key: str) -> list[str]:
    """A 9x9 square seeded with `key`, then the rest of the printable-ish alphabet."""
    pool = key + string.ascii_lowercase + string.digits + " .,'-/:!?"
    seen: list[str] = []
    for char in pool:
        if char not in seen:
            seen.append(char)
    seen = (seen + list(string.punctuation))[:81]
    return ["".join(seen[r * 9 : (r + 1) * 9]) for r in range(9)]


def _polybius(digits: str, key: str) -> str | None:
    if len(digits) % 2:
        return None
    square = _polybius_square(key)
    out = []
    for i in range(0, len(digits), 2):
        row = ord(digits[i]) - ord("a")
        col = ord(digits[i + 1]) - ord("a")
        out.append(square[row][col])
    return "".join(out)


def decoders() -> Iterator[tuple[str, Callable[[str], str | None]]]:
    yield "binary", decode_binary
    yield "base16", decode_base16
    for size in (2, 3, 4):
        for offset in (0, 1):
            for base in (9, 10):
                yield (
                    f"chunk{size}b{base}o{offset}",
                    lambda d, s=size, o=offset, b=base: _chunk(d, s, o, b),
                )
    for size in (2, 3, 4, 5):
        for op in ("sum", "product"):
            yield f"a1z26-{op}{size}", lambda d, s=size, o=op: _group_a1z26(d, s, o)
    for key in KEY_STRINGS:
        yield f"polybius[{key}]", lambda d, k=key: _polybius(d, k)


# --------------------------------------------------------------------------- sweep


def sweep(digits: str, label: str, limit: int = 8) -> list[Candidate]:
    """Every mask x reader x decoder combination, ranked by English-likeness."""
    results: list[Candidate] = []
    for mask_name, mask in MASKS.items():
        masked = mask(digits)
        for reader_name, reordered in readers_for(masked):
            for decoder_name, decoder in decoders():
                try:
                    text = decoder(reordered)
                except (ValueError, IndexError):
                    continue
                if not text:
                    continue
                results.append(
                    Candidate(f"{label} | {mask_name} | {reader_name} | {decoder_name}",
                              text, scoring.score(text))
                )
    results.sort(key=lambda c: c.value, reverse=True)
    return results[:limit]


def rediscover() -> bool:
    """Control: the sweep must re-derive the four already-known decodings.

    Without this, "nothing found in region A" is not evidence of anything.
    """
    tokens = block.load_tokens()
    segments = block.segment(tokens)
    expected = {
        "binary": ["matrixsumlist", "enter"],
        "digits": ["lastwordsbeforearchichoice", "thispassword"],
    }
    found: list[str] = []
    for segment in segments:
        if segment.kind == "binary":
            found.append(segment.as_binary() or "")
        elif segment.kind == "digits" and segment.length < 80:
            decoded = segment.as_base16()
            found.append(decoded.decode("ascii", "replace") if decoded else "")

    ok = True
    for group in expected.values():
        for want in group:
            hit = want in found
            print(f"  rediscovered {want!r}: {'PASS' if hit else 'FAIL'}")
            ok &= hit

    # And the sweep itself must rank the true decoding top for a known segment.
    known = next(s for s in segments if s.kind == "digits" and s.length == 63)
    best = sweep(known.text, "known-seg", limit=1)[0]
    hit = "lastwordsbeforearchichoice" in best.text
    verdict = "PASS" if hit else "FAIL"
    print(f"  sweep ranks known segment correctly: {verdict}  -> {best.text[:40]!r}")
    return ok and hit


def null_distribution(digits: str, label: str, trials: int = 5, seed: int = 0) -> list[float]:
    """Sweep shuffled copies of the same digits to get an empirical noise ceiling.

    Shuffling preserves length and letter frequencies but destroys any ordering, so whatever
    the sweep scores here is what it scores on data with no signal in it. If the real region
    does not beat this, the sweep found nothing -- which is a much stronger statement than
    comparing against an arbitrary threshold.
    """
    rng = random.Random(seed)
    tops = []
    for trial in range(trials):
        shuffled = list(digits)
        rng.shuffle(shuffled)
        best = sweep("".join(shuffled), f"{label}-shuffled{trial}", limit=1)
        tops.append(best[0].value if best else float("-inf"))
    return tops


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--region", choices=["A", "B", "AB", "main"], help="which region")
    parser.add_argument("--rediscover", action="store_true", help="run the control and exit")
    parser.add_argument("--all", action="store_true", help="sweep every region")
    parser.add_argument("--null", action="store_true", help="compare against shuffled controls")
    parser.add_argument("--trials", type=int, default=5, help="shuffled trials for --null")
    parser.add_argument("--limit", type=int, default=8, help="results to show per region")
    args = parser.parse_args()

    tokens = block.load_tokens()
    segments = block.segment(tokens)
    a, b = block.undecoded_regions(segments)
    regions = {"A": a.text, "B": b.text, "AB": a.text + b.text,
               "main": "".join(tokens[a.start : b.end])}

    if args.rediscover:
        return 0 if rediscover() else 1
    if not (args.region or args.all):
        parser.error("pass --region, --all or --rediscover")

    chosen = regions if args.all else {args.region: regions[args.region]}
    for label, digits in chosen.items():
        print(f"\n=== region {label} ({len(digits)} chars) ===")
        best = sweep(digits, label, args.limit)
        for candidate in best:
            print(f"  {candidate.value:7.2f}  {candidate.chain}")
            print(f"           {candidate.text[:96]!r}")
        if args.null:
            tops = null_distribution(digits, label, args.trials)
            real = best[0].value if best else float("-inf")
            # Rank-based p-value rather than "did it beat the max". With few trials the
            # observed max is itself noisy: region B once cleared a 5-trial max by 0.20 and
            # looked like signal, then sat mid-distribution at 25 trials.
            exceeded = sum(1 for t in tops if t >= real)
            p_value = (exceeded + 1) / (len(tops) + 1)
            print(f"  -- shuffled controls (n={len(tops)}): max={max(tops):.2f} "
                  f"mean={sum(tops)/len(tops):.2f}")
            verdict = "signal" if p_value < 0.05 else "within noise -> no signal"
            print(f"  -- real best={real:.2f}  p={p_value:.3f} -> {verdict}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
