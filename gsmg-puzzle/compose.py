"""Passphrases built by concatenating the puzzle's answers in every order.

Both keys in this puzzle whose construction is published are built this way, out of pieces
that are not adjacent in any text:

    phase 3    SHA256("causality" + "Safenet" + "Luna" + "HSM" + "11110" + <scriptSig> + <FEN>)
    phase 3.2  SHA256("jacquefresco" + "giveitjustonesecond" + "heisenbergsuncertaintyprinciple")

`phrases.py` cannot reach that shape -- it only walks contiguous word windows of a text --
and `candidates.py` stopped at ordered triples of short terms. This module closes that gap:
ordered permutations of the *answers* themselves, to depth four.

The atom list is answers only, each with its provenance recorded. Padding it with thematic
guesses would multiply the search space without improving the odds, and would make a
negative result harder to state precisely.

    python3 compose.py --control     # must rediscover the published phase-3.2 key
    python3 compose.py --describe    # atom list and search size
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Iterator
from itertools import permutations

import crack
import phrases

# (atom, where it came from). Casing is the puzzle's own -- phase 3's key preserves
# `Safenet` and `HSM` while lowercasing `causality`, so both forms are tried below.
ATOMS: list[tuple[str, str]] = [
    ("causality", "phase 3 part 1"),
    ("Safenet", "phase 3 part 2"),
    ("Luna", "phase 3 part 3"),
    ("HSM", "phase 3 part 4"),
    ("11110", "phase 3 part 5, JFK executive order"),
    ("jacquefresco", "phase 3.2 answer 1"),
    ("giveitjustonesecond", "phase 3.2 answer 2"),
    ("heisenbergsuncertaintyprinciple", "phase 3.2 answer 3"),
    ("matrixsumlist", "SalPhaseIon binary run"),
    ("enter", "SalPhaseIon binary run"),
    ("lastwordsbeforearchichoice", "SalPhaseIon digit segment"),
    ("thispassword", "SalPhaseIon digit segment"),
    ("thematrixhasyou", "Beaufort key, phase 3.2.1"),
    ("hashthetext", "Decentraland audio spectrogram"),
    ("theseedisplanted", "phase 1 answer"),
    ("theflowerblossomsthroughwhatseemstobeaconcretesurface", "phase 2 password"),
    ("returntothesourcecodes", "Architect speech imperative"),
    ("reinsertingtheprimebasics", "Architect speech imperative"),
    ("ciaobella", "Architect speech closing words"),
    ("sha256anstoo", "SalPhaseIon trailing instruction"),
]

SEPARATORS = ("", " ")  # the puzzle's "connected enf" / "connected not enf"


def atoms() -> list[str]:
    return [atom for atom, _ in ATOMS]


def compose(min_depth: int = 2, max_depth: int = 4) -> Iterator[str]:
    """Ordered concatenations of distinct atoms, in the puzzle's separator and casing forms."""
    seen: set[str] = set()
    pool = atoms()
    for depth in range(min_depth, max_depth + 1):
        for combo in permutations(pool, depth):
            for separator in SEPARATORS:
                joined = separator.join(combo)
                for variant in (joined, joined.lower()):
                    if variant not in seen:
                        seen.add(variant)
                        yield variant


def initialisms() -> Iterator[str]:
    """First letters of each sentence of the narrative texts.

    Cheap, and no sweep so far has covered it: an initialism is neither a contiguous window
    nor a concatenation of answers.
    """
    seen: set[str] = set()
    for words in phrases.sources().values():
        letters = "".join(word[0] for word in words if word)
        for candidate in (letters, letters.lower(), letters.upper()):
            if len(candidate) >= 4 and candidate not in seen:
                seen.add(candidate)
                yield candidate


def generate(max_depth: int = 4) -> Iterator[str]:
    yield from initialisms()
    yield from compose(max_depth=max_depth)


def control() -> bool:
    """The composer must rediscover the one published key of this shape, and only it.

    phase 3.2's passphrase is three atoms concatenated in order with no separator. If the
    composer cannot find that, its silence on the unsolved blobs means nothing.
    """
    target = "jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple"
    found = crack.search(crack.load("known"), compose(min_depth=3, max_depth=3))
    ok = len(found) == 1 and found[0][1].startswith(b"I've been waiting for you.")
    print(f"composer recovers the published phase-3.2 key ({target[:24]}...): "
          f"{'PASS' if ok else 'FAIL'}")
    return ok


def describe() -> str:
    pool = atoms()
    total = 0
    lines = [f"  {len(pool)} atoms"]
    for depth in (2, 3, 4):
        count = 1
        for i in range(depth):
            count *= len(pool) - i
        total += count
        lines.append(f"  depth {depth}: {count:,} orderings")
    lines.append(f"  total {total:,} orderings x {len(SEPARATORS)} separators x 2 casings")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--control", action="store_true", help="run the composer control")
    parser.add_argument("--describe", action="store_true", help="print the search size")
    args = parser.parse_args()

    if args.control:
        return 0 if control() else 1
    print(describe())
    for atom, provenance in ATOMS:
        print(f"  {atom[:44]:46s} {provenance}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
