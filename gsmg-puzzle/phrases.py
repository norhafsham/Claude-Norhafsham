"""Candidate passphrases built from contiguous phrases of the puzzle's recovered texts.

The SalPhaseIon block's decoded fragments read as a recipe rather than as passwords:
`lastwordsbeforearchichoice` ("the last words before the Architect's choice"), then
`thispassword` ("...is this password"), then `shabef` + `anstoo` ("sha256, answer too").
Every solved stage was built that way -- the phase-3.2 key is the SHA-256 of
`jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple`, three quote answers run
together and stripped of spaces.

The earlier corpus in candidates.py recombined known *short strings*. This one takes whole
phrases out of the narrative texts instead, which is what "the last words before X" actually
describes.

The hard part of that instruction is where to cut, and guessing badly is a silent miss. So
nothing is guessed: every contiguous word window of every source is enumerated. The Architect
text alone is 331 words, giving 54,946 windows, which is cheap enough to be exhaustive. That
turns the outcome from "some phrases were tried" into "no contiguous phrase of these texts
decrypts this blob".

Windows are emitted longest-first so that a hit names the most specific phrase that works
rather than some short fragment of it.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

import aes

DATA = Path(__file__).parent / "data"

# The phase-3.2 plaintext is not transcribed; it is decrypted from the pinned ciphertext with
# its published passphrase, so the text used here is exactly what the puzzle produced.
KNOWN_PHASE32_PASSWORD = b"250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c"


def _clean(text: str) -> list[str]:
    """Words of a source, dropping comment lines and punctuation.

    Punctuation becomes a separator rather than being stripped in place, so hyphenated and
    ampersand-joined constructions keep *both* halves: `fubcd-king & oracle-queen` yields
    five words, not three.
    """
    lines = [line for line in text.splitlines() if not line.lstrip().startswith("#")]
    return re.sub(r"[^A-Za-z0-9 ]+", " ", " ".join(lines)).split()


def _is_payload(line: str) -> bool:
    """Whether a line of the phase-3.2 plaintext is an encoded payload rather than prose.

    The plaintext carries a base64 blob, a long digit string and an EBCDIC block alongside
    its English. Those have to go, but selecting prose by character class instead silently
    drops short words trapped between punctuation -- the first version of this used a
    `[A-Za-z ',.]{12,}` match and lost `king` and `oracle` out of
    `A fubcd-king & oracle-queen`, so no phrase window ever contained them.
    """
    stripped = line.strip()
    if not stripped:
        return True
    if " " not in stripped and len(stripped) > 24:  # base64 or digit run
        return True
    letters = sum(char.isalpha() or char.isspace() for char in stripped)
    return letters / len(stripped) < 0.7  # EBCDIC block and similar


def phase32_text() -> str:
    """The decrypted phase-3.2 plaintext, prose only.

    Decrypted from the pinned ciphertext rather than transcribed, so it cannot drift from
    what the puzzle actually emitted.
    """
    import base64

    raw = (DATA / "known_phase32.b64").read_text()
    blob = aes.Blob.parse(base64.b64decode(raw))
    plaintext = blob.decrypt(KNOWN_PHASE32_PASSWORD)
    if plaintext is None:
        raise RuntimeError("phase-3.2 control blob failed to decrypt")
    text = plaintext.decode("ascii", "ignore")
    return " ".join(line for line in text.splitlines() if not _is_payload(line))


def sources() -> dict[str, list[str]]:
    """Every text a phrase might be drawn from, as word lists."""
    return {
        "architect": _clean((DATA / "architect.txt").read_text()),
        "film_lines": _clean((DATA / "film_lines.txt").read_text()),
        "decoded_lines": _clean((DATA / "decoded_lines.txt").read_text()),
        "phase32": _clean(phase32_text()),
    }


def windows(words: list[str], max_words: int | None = None) -> Iterator[list[str]]:
    """Every contiguous word window, longest first."""
    limit = len(words) if max_words is None else min(max_words, len(words))
    for length in range(limit, 0, -1):
        for start in range(len(words) - length + 1):
            yield words[start : start + length]


def normalisations(words: list[str]) -> Iterator[str]:
    """The casing and spacing conventions the puzzle documents on its own pages.

    `/(aaa, connected enf)` means lowercase and strip whitespace; `/(aBa, connected not enf)`
    means keep the given casing and the spaces. Both appear in the phase-2 and phase-3 text,
    and the solved passphrases use the stripped lowercase form.
    """
    joined = " ".join(words)
    yield joined.lower().replace(" ", "")
    yield joined.lower()
    yield joined.replace(" ", "")
    yield joined.upper().replace(" ", "")


def generate(max_words: int | None = None) -> Iterator[str]:
    """Unique candidate passphrases across all sources."""
    seen: set[str] = set()
    for words in sources().values():
        for window in windows(words, max_words):
            for candidate in normalisations(window):
                if candidate and candidate not in seen:
                    seen.add(candidate)
                    yield candidate


def describe() -> str:
    lines = []
    total = 0
    for name, words in sources().items():
        count = len(words) * (len(words) + 1) // 2
        total += count
        lines.append(f"  {name:14s} {len(words):4d} words -> {count:,} windows")
    lines.append(f"  {'total':14s} {'':4s}    {total:,} windows")
    return "\n".join(lines)


if __name__ == "__main__":
    print(describe())
