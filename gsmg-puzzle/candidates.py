"""Candidate passphrases for the unsolved GSMG.IO blobs, drawn from puzzle material.

A generic wordlist is pointless here. Every solved GSMG stage used a passphrase the
solver *constructed* from in-puzzle text -- `causality`, a seven-part concatenation, a
run-on sentence of three quote answers. So the corpus is seeded from decoded puzzle
strings and expanded with the puzzle's own documented rules, rather than from English.

Two of those rules are stated on the puzzle pages themselves and are applied here:

    /(aaa, connected enf)      lowercase the answer, strip whitespace
    /(aBa, connected not enf)  keep the given casing, keep whitespace

Provenance is noted per group. Anything not traceable to the puzzle is marked SPECULATIVE
so a negative result can be read honestly -- ruling out a guess is weaker than ruling out
something the puzzle actually points at.
"""

from __future__ import annotations

from collections.abc import Iterator
from itertools import permutations

# Decoded out of the SalPhaseIon letter block. These are the strongest leads: they are
# the only plaintext the unsolved stage has yielded, and two read as instructions.
SALPHASEION = [
    "matrixsumlist",
    "enter",
    "lastwordsbeforearchichoice",
    "thispassword",
]

# Passphrases and parts confirmed by earlier, solved stages.
SOLVED_PARTS = [
    "causality",
    "Safenet",
    "Luna",
    "HSM",
    "11110",
    "thematrixhasyou",
    "theseedisplanted",
    "theflowerblossomsthroughwhatseemstobeaconcretesurface",
    "jacquefresco",
    "giveitjustonesecond",
    "heisenbergsuncertaintyprinciple",
    "jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple",
    "hashthetext",  # from the Decentraland audio spectrogram
]

# The literal strings the puzzle told solvers to hash, kept verbatim (casing matters).
LITERALS = [
    "GSMGIO5BTCPUZZLECHALLENGE1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe",
    "1GSMG1JC9wtdSwfwApgj2xcmJPAwx7prBe",
    (
        "0x736B6E616220726F662074756F6C69616220646E6F63657320666F206B6E697262206E6F"
        "20726F6C6C65636E61684320393030322F6E614A2F33302073656D695420656854"
    ),
    "B5KR/1r5B/2R5/2b1p1p1/2P1k1P1/1p2P2p/1P2P2P/3N1N2 b - - 0 1",
    # The full phase-3 seven-part concatenation, and the digest it produced.
    (
        "causalitySafenetLunaHSM111100x736B6E616220726F662074756F6C69616220646E6F6365"
        "7320666F206B6E697262206E6F20726F6C6C65636E61684320393030322F6E614A2F33302073"
        "656D695420656854B5KR/1r5B/2R5/2b1p1p1/2P1k1P1/1p2P2p/1P2P2P/3N1N2 b - - 0 1"
    ),
    "1a57c572caf3cf722e41f5f9cf99ffacff06728a43032dd44c481c77d2ec30d5",
    "250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c",
    "89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32",
]

# SPECULATIVE: Matrix / Alice vocabulary the puzzle leans on heavily but never names as
# an answer. Included because the stage is titled after Matrix concepts.
THEMATIC = [
    "thearchitect",
    "architect",
    "merovingian",
    "morpheus",
    "trinity",
    "neo",
    "theone",
    "zion",
    "theoracle",
    "keymaker",
    "thekeymaker",
    "whiterabbit",
    "followthewhiterabbit",
    "cheshirecat",
    "thesourcecode",
    "returntothesource",
    "cosmicduality",
    "salphaseion",
    "primebasics",
    "reinsertingtheprimebasics",
]


def casings(term: str) -> list[str]:
    """The casing variants the puzzle's own aaa/aBa notation makes plausible."""
    return list(dict.fromkeys([term, term.lower(), term.upper(), term.capitalize()]))


def _seeds() -> list[str]:
    return SALPHASEION + SOLVED_PARTS + LITERALS + THEMATIC


def generate(max_terms: int = 2, thematic: bool = True) -> Iterator[str]:
    """Yield unique candidate passphrases.

    max_terms controls the ordered-concatenation depth over the SalPhaseIon strings and
    solved parts. Depth 3 over the full seed set is combinatorially large without being
    more likely, so concatenation is restricted to the strings the unsolved stage itself
    produced plus the solved-stage parts -- the pattern every earlier stage followed.
    """
    seen: set[str] = set()

    def emit(value: str) -> Iterator[str]:
        for variant in casings(value):
            if variant and variant not in seen:
                seen.add(variant)
                yield variant

    pool = _seeds() if thematic else SALPHASEION + SOLVED_PARTS + LITERALS
    for term in pool:
        yield from emit(term)

    joinable = SALPHASEION + SOLVED_PARTS
    for n in range(2, max_terms + 1):
        for combo in permutations(joinable, n):
            for sep in ("", " "):  # "connected enf" vs "connected not enf"
                yield from emit(sep.join(combo))
