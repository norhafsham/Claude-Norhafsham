"""Readings of the instruction `matrixsumlist` against the first puzzle piece.

`matrixsumlist` is the only imperative recovered from the SalPhaseIon block, and
`our first hint is your last command` points back to the first puzzle piece -- the 14x14
grid that opens the puzzle. Taken together they suggest: make a matrix, sum it, get a list.

The trouble is that "sum" has several defensible readings and nothing in the block picks
one, which is why the general sweep in decode.py could not settle it. This module makes the
readings explicit and enumerable so each can be tested against shuffled controls rather than
argued about.

The grid's own sums, for reference: rows [6,10,8,7,6,6,5,4,9,9,7,8,7,9], columns
[8,10,8,10,8,7,3,6,7,5,9,6,6,8], 101 ones against 95 zeros. Both lists contain values above
9, so they cannot map onto the block's a-i alphabet directly -- any use has to be as a key,
an index, or an ordering.

    python3 matrixsum.py            # all readings, ranked
    python3 matrixsum.py --null     # with shuffled-control p-values
"""

from __future__ import annotations

import argparse
import random
import sys
from collections.abc import Iterator

import block
import score as scoring

Reading = tuple[str, str]  # (name, output text)


def _values(region: str) -> list[int]:
    """Region characters as their digit values, a=1..i=9."""
    return [ord(char) - ord("a") + 1 for char in region]


def _letters(values: list[int], offset: int = -1) -> str:
    return "".join(chr(ord("a") + (value + offset) % 26) for value in values)


def _cumulative(values: list[int]) -> list[int]:
    running, out = 0, []
    for value in values:
        running += value
        out.append(running)
    return out


def _rectangles(length: int) -> list[tuple[int, int]]:
    return [(r, length // r) for r in range(2, length) if length % r == 0 and length // r > 1]


def grid_sums(grid: list[list[int]]) -> dict[str, list[int]]:
    rows = [sum(row) for row in grid]
    cols = [sum(grid[r][c] for r in range(len(grid))) for c in range(len(grid[0]))]
    return {"rowsums": rows, "colsums": cols, "row+col": rows + cols}


# ------------------------------------------------------------------------- readings


def reshape_axis_sum(region: str, grid: list[list[int]]) -> Iterator[Reading]:
    """Fold the region into a rectangle, sum along each axis, read the list as letters."""
    values = _values(region)
    for rows, cols in _rectangles(len(values)):
        table = [values[i * cols : (i + 1) * cols] for i in range(rows)]
        axes = {
            "colsum": [sum(table[r][c] for r in range(rows)) for c in range(cols)],
            "rowsum": [sum(row) for row in table],
        }
        for axis, sums in axes.items():
            for offset in (-1, 0):
                yield f"reshape {rows}x{cols} {axis} off{offset}", _letters(sums, offset)


def key_shift(region: str, grid: list[list[int]]) -> Iterator[Reading]:
    """Use the grid's sums as a repeating additive key over the region, modulo 9."""
    values = _values(region)
    for name, key in grid_sums(grid).items():
        shifted = [((v - 1 + key[i % len(key)]) % 9) + 1 for i, v in enumerate(values)]
        yield f"key-shift[{name}]", "".join(chr(ord("a") + v - 1) for v in shifted)


def index_cumulative(region: str, grid: list[list[int]]) -> Iterator[Reading]:
    """Treat the running totals of the grid's sums as 1-indexed positions into the region."""
    for name, key in grid_sums(grid).items():
        positions = [p for p in _cumulative(key) if 1 <= p <= len(region)]
        if positions:
            yield f"index-cum[{name}]", "".join(region[p - 1] for p in positions)


def transpose_by_rank(region: str, grid: list[list[int]]) -> Iterator[Reading]:
    """Columnar transposition, column order given by the rank of each sum."""
    for name, key in grid_sums(grid).items():
        width = len(key)
        order = sorted(range(width), key=lambda i: (key[i], i))
        usable = len(region) - len(region) % width
        table = [region[i : i + width] for i in range(0, usable, width)]
        yield f"transpose[{name}]", "".join("".join(row[c] for row in table) for c in order)


def mask_select(region: str, grid: list[list[int]]) -> Iterator[Reading]:
    """Use the grid as a selection mask over the region, keeping where the bit is set.

    The spiral is the traversal the puzzle itself established at phase one, so it is the
    natural order in which to lay the grid over a linear string. Row-major is included as
    the obvious alternative.
    """
    orders = {
        "spiral": block.spiral_ccw(grid),
        "rowmajor": [bit for row in grid for bit in row],
    }
    for name, bits in orders.items():
        for keep in (1, 0):
            picked = "".join(
                char for i, char in enumerate(region) if bits[i % len(bits)] == keep
            )
            if picked:
                yield f"mask-{name}[keep{keep}]", picked


READINGS = {
    "reshape_axis_sum": reshape_axis_sum,
    "key_shift": key_shift,
    "index_cumulative": index_cumulative,
    "transpose_by_rank": transpose_by_rank,
    "mask_select": mask_select,
}


# --------------------------------------------------------------------------- driving


def run(region: str, grid: list[list[int]]) -> list[tuple[float, str, str]]:
    """Every reading applied to one region, ranked by score."""
    out = []
    for family, reading in READINGS.items():
        for name, text in reading(region, grid):
            if len(text) >= 4:
                out.append((scoring.score(text), f"{family} | {name}", text))
    return sorted(out, reverse=True, key=lambda row: row[0])


def null_top(region: str, grid: list[list[int]], trials: int, seed: int = 0) -> list[float]:
    """Best score each reading family reaches on shuffled copies of the same region."""
    rng = random.Random(seed)
    tops = []
    for _ in range(trials):
        shuffled = list(region)
        rng.shuffle(shuffled)
        results = run("".join(shuffled), grid)
        tops.append(results[0][0] if results else float("-inf"))
    return tops


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--null", action="store_true", help="compare against shuffled copies")
    parser.add_argument("--trials", type=int, default=15)
    parser.add_argument("--limit", type=int, default=6)
    args = parser.parse_args()

    grid = block.load_matrix()
    segments = block.segment(block.load_tokens())
    a, b = block.undecoded_regions(segments)

    for label, region in (("A", a.text), ("B", b.text)):
        print(f"\n=== region {label} ({len(region)} chars) ===")
        results = run(region, grid)
        for value, name, text in results[: args.limit]:
            flag = "HIT" if scoring.confident(text) else "   "
            print(f"  {flag} {value:7.2f}  {name:34s} {text[:60]!r}")
        if args.null:
            tops = null_top(region, grid, args.trials)
            best, _, best_text = results[0]
            exceeded = sum(1 for t in tops if t >= best)
            p_value = (exceeded + 1) / (len(tops) + 1)
            print(f"  -- shuffled (n={len(tops)}): max={max(tops):.2f} "
                  f"mean={sum(tops) / len(tops):.2f}")
            # Both conditions are required. A rank-based p bottoms out at 1/(trials+1), so a
            # small run can report 0.048 purely for lack of samples; and the best result here
            # is a six-letter string, which is too short for its score to mean anything.
            letters = sum(char.isalpha() for char in best_text)
            if letters < scoring.MIN_RELIABLE_LETTERS:
                verdict = f"too short to judge ({letters} letters) -> no claim"
            elif not scoring.confident(best_text):
                verdict = "within noise -> no signal"
            elif p_value < 0.05:
                verdict = "signal"
            else:
                verdict = "within noise -> no signal"
            print(f"  -- real best={best:.2f}  p={p_value:.3f} -> {verdict}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
