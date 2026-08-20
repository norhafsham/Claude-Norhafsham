"""Passphrases read out of the first puzzle piece, for the blob that asks for them.

Blob A is the only ciphertext with instructions attached to it. In the letter block it sits
between `shabef` + `ourfirsthintisyourlastcommand` and `shabef` + `anstoo`, with the `enter`
run splitting its two halves. Read together: *the puzzle's first hint, hashed, is the
passphrase* -- `shabef` being the block's own way of writing `sha256`.

The first hint is the first puzzle piece: the 14x14 grid whose counterclockwise spiral spells
`gsmg.io/theseedisplanted`. Every sweep so far has used the grid's *output*; none has used
the grid itself as a passphrase string.

So enumerate its readings rather than guessing one. The grid admits a bounded number of
sensible traversals -- spirals from each corner in each direction, row and column order,
boustrophedon, diagonals, the transpose -- and each can be written as bits, as hex, or as the
ASCII those bits decode to. That is around a hundred strings, trivial beside the
million-candidate sweeps, and complete for this reading.

    python3 firsthint.py --describe
    python3 firsthint.py --blob a
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Iterator

import block
import crack


def _rotations(grid: list[list[int]]) -> Iterator[tuple[str, list[list[int]]]]:
    """The grid in each of four rotations, plus its transpose.

    Spiralling from a different corner is the same as rotating the grid and spiralling from
    the usual one, so this covers the corner variants without four more traversal functions.
    """
    current = grid
    for quarter in range(4):
        yield f"rot{quarter * 90}", current
        current = [list(row) for row in zip(*current[::-1], strict=True)]
    yield "transpose", [list(row) for row in zip(*grid, strict=True)]


def traversals(grid: list[list[int]]) -> Iterator[tuple[str, list[int]]]:
    """Named bit orderings of the grid."""
    for name, view in _rotations(grid):
        yield f"spiral-{name}", block.spiral_ccw(view)
        yield f"rows-{name}", [bit for row in view for bit in row]
        yield f"cols-{name}", [bit for col in zip(*view, strict=True) for bit in col]
        yield f"boustro-{name}", [
            bit
            for index, row in enumerate(view)
            for bit in (row if index % 2 == 0 else row[::-1])
        ]
    size = len(grid)
    yield "diagonals", [
        grid[r][d - r] for d in range(2 * size - 1) for r in range(size) if 0 <= d - r < size
    ]


def renderings(bits: list[int]) -> Iterator[str]:
    """A bit ordering as the strings a solver would plausibly type."""
    joined = "".join(str(bit) for bit in bits)
    yield joined
    yield joined[::-1]
    value = int(joined, 2)
    yield f"{value:x}"
    yield f"{value:X}"
    text = block.bits_to_text(bits)
    if text.isprintable():
        yield text
        # The puzzle's own `/(aaa, connected enf)` convention strips punctuation entirely,
        # so `gsmg.io/theseedisplanted` also has to be offered as `gsmgiotheseedisplanted`.
        yield "".join(char for char in text if char.isalnum())
        yield "".join(char for char in text if char.isalnum()).lower()


def generate(grid: list[list[int]] | None = None) -> Iterator[str]:
    grid = grid if grid is not None else block.load_matrix()
    seen: set[str] = set()
    for _, bits in traversals(grid):
        for candidate in renderings(bits):
            if candidate and candidate not in seen:
                seen.add(candidate)
                yield candidate


def describe() -> str:
    grid = block.load_matrix()
    orders = list(traversals(grid))
    strings = list(generate(grid))
    return (
        f"  {len(orders)} traversals of the 14x14 grid\n"
        f"  {len(strings)} distinct passphrase strings (bits, hex, decoded ASCII, reversed)"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--blob", choices=sorted(crack.BLOBS), help="which ciphertext")
    parser.add_argument("--describe", action="store_true")
    args = parser.parse_args()

    if args.describe or not args.blob:
        print(describe())
        return 0

    blob = crack.load(args.blob)
    print(f"blob {args.blob}: {blob.blocks} blocks, salt={blob.salt.hex()}")
    print(describe())
    return 0 if crack.search(blob, generate()) else 1


if __name__ == "__main__":
    sys.exit(main())
