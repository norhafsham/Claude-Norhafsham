"""Segment the SalPhaseIon letter block, and load the first puzzle piece's 14x14 grid.

The SalPhaseIon page presents 1075 space-separated single characters. Most of them are
`a`-`i` (a digit alphabet where a=1..i=9, with `o`=0), but the block also carries runs of
plain English, two halves of a base64 blob, and `a`/`b` runs that are really binary. The
upstream README transcribes only part of it and decodes less.

Boundaries are derived from the data rather than hard-coded, so the map can be re-checked
against the source instead of trusted. `z` acts as the separator between sections; the
`a`/`b` binary runs are found by looking for long runs drawn from just those two letters,
which is what distinguishes them from surrounding digit text.

A note on the digit alphabet: the solved segments use `o` for zero, but the two large
undecoded regions contain no `o` at all. Their digits are 1-9 only, which is what you would
expect of 1-indexed coordinates rather than values.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

DATA = Path(__file__).parent / "data"
DIGITS = "abcdefghi"
ZERO = "o"
SEPARATOR = "z"
DIGIT_MAP = str.maketrans("abcdefghio", "1234567890")

# A run of only `a`/`b` this long is binary, not digit text. The two real runs are 104 and
# 40 characters; incidental ab-runs inside digit text are far shorter.
MIN_BINARY_RUN = 24


@dataclass(frozen=True)
class Segment:
    """One contiguous stretch of the block, with where it came from."""

    start: int
    end: int
    kind: str
    text: str

    @property
    def length(self) -> int:
        return self.end - self.start

    def as_binary(self) -> str | None:
        """Interpret an a/b run as bits (a=0, b=1)."""
        if set(self.text) - set("ab"):
            return None
        bits = self.text.replace("a", "0").replace("b", "1")
        return "".join(chr(int(bits[i : i + 8], 2)) for i in range(0, len(bits) // 8 * 8, 8))

    def as_base16(self) -> bytes | None:
        """The README's method: digits -> decimal integer -> base 16 -> bytes."""
        if set(self.text) - set(DIGITS + ZERO):
            return None
        hexed = f"{int(self.text.translate(DIGIT_MAP)):x}"
        return bytes.fromhex(("0" + hexed) if len(hexed) % 2 else hexed)


def load_tokens(path: Path | None = None) -> list[str]:
    text = (path or DATA / "salphaseion_letters.txt").read_text()
    return text.split()


def segment(tokens: list[str]) -> list[Segment]:
    """Split the block into binary runs, digit regions, separators and everything else."""
    joined = "".join(tokens)
    cuts = {0, len(joined)}

    for index, char in enumerate(joined):
        if char == SEPARATOR:
            cuts |= {index, index + 1}
    for match in re.finditer(rf"[ab]{{{MIN_BINARY_RUN},}}", joined):
        cuts |= {match.start(), match.end()}

    bounds = sorted(cuts)
    segments = []
    for start, end in zip(bounds, bounds[1:], strict=False):  # consecutive pairs
        chunk = joined[start:end]
        if chunk == SEPARATOR:
            kind = "separator"
        elif len(chunk) >= MIN_BINARY_RUN and not set(chunk) - set("ab"):
            kind = "binary"
        elif not set(chunk) - set(DIGITS + ZERO):
            kind = "digits"
        else:
            kind = "mixed"
        segments.append(Segment(start, end, kind, chunk))
    return segments


def undecoded_regions(segments: list[Segment]) -> tuple[Segment, Segment]:
    """Regions A and B: the two large digit stretches flanking the `matrixsumlist` marker.

    These are the only parts of the block that no published method decodes.
    """
    digit_runs = sorted(
        (s for s in segments if s.kind == "digits"), key=lambda s: s.length, reverse=True
    )
    a, b = sorted(digit_runs[:2], key=lambda s: s.start)
    return a, b


def load_matrix(path: Path | None = None) -> list[list[int]]:
    """The 14x14 bit grid from the first puzzle piece."""
    text = (path or DATA / "first_puzzle_matrix.txt").read_text()
    rows = [[int(bit) for bit in line.split()] for line in text.splitlines() if line.strip()]
    if len(rows) != 14 or any(len(row) != 14 for row in rows):
        raise ValueError(f"expected a 14x14 grid, got {len(rows)} rows")
    return rows


def spiral_ccw(grid: list[list[int]]) -> list[int]:
    """Read a grid counterclockwise from the upper left.

    This is the traversal that turns the first puzzle piece into `gsmg.io/theseedisplanted`,
    which is what makes it trustworthy as a key stream here.
    """
    top, bottom, left, right = 0, len(grid) - 1, 0, len(grid[0]) - 1
    out: list[int] = []
    while top <= bottom and left <= right:
        for row in range(top, bottom + 1):
            out.append(grid[row][left])
        left += 1
        for col in range(left, right + 1):
            out.append(grid[bottom][col])
        bottom -= 1
        if left <= right:
            for row in range(bottom, top - 1, -1):
                out.append(grid[row][right])
            right -= 1
        if top <= bottom:
            for col in range(right, left - 1, -1):
                out.append(grid[top][col])
            top += 1
    return out


def bits_to_text(bits: list[int]) -> str:
    joined = "".join(str(bit) for bit in bits)
    return "".join(chr(int(joined[i : i + 8], 2)) for i in range(0, len(joined) // 8 * 8, 8))
