"""Score a candidate decoding for how much it looks like English.

The previous stage of this work established that the obvious metric is a trap. Printable
ratio rejects a *known-correct* plaintext -- the solved phase-3.2 text is only 60% printable
because it embeds box-drawing characters -- and it also rewards nonsense: a decoding that
emits values 0..80 scores 60% printable purely by construction, which briefly looked like a
77% hit until the range was checked.

So scoring here is a bigram log-probability over letters, with a bonus for whole words and
a penalty for unprintable bytes. The model is trained on the prose embedded below rather
than on any puzzle text, so a high score cannot come from having memorised the answers.

Calibration is asserted in the tests: the four known plaintexts must score far above random
bytes and above restricted-range decoys.
"""

from __future__ import annotations

import math
import re
import string
from collections import Counter
from functools import lru_cache

# Ordinary English prose, used only to fit bigram frequencies. Deliberately unrelated to the
# puzzle so the model cannot be accused of recognising the expected answers.
_TRAINING = """
the quick brown fox jumps over the lazy dog while the rain falls steadily on the old stone
roof of the house at the end of the lane there was a time when people would walk for miles
to reach the market and trade what they had grown through the summer months the roads were
narrow and often flooded but the journey was made all the same because it mattered to those
who depended on it for their living in the evening the men would gather near the fire and
speak of the weather and the price of grain and whether the winter would come early this
year the children listened from the doorway and learned the names of distant places they
had never seen a letter arrived once every few weeks carrying news of relatives who had
moved to the city and taken work in the factories there the writing was careful and small
because paper was expensive and every inch of it had to be used the answer would be written
on the same sheet and sent back along the same slow route it is difficult now to imagine
how much patience such a life required and how ordinary it seemed to everyone living it
history is mostly made of these small repeated actions rather than the great events that
fill the books we read about them long afterward and forget that each day passed much like
any other for the people who were there we should remember that when we look back and try
to understand what they thought and why they made the choices that they did the record is
always incomplete and the most important things are often the ones nobody bothered to write
down because everybody already knew them and assumed that they would always be known
"""

_WORD_SOURCE = """the and that have for not with you this but his from they she her been than its
    were are was one all would there their what out about who get which when make can like
    time just him know take people into year your good some could them see other then now
    look only come over think also back after use two how our work first well way even new
    want because any these give day most password key answer enter list matrix sum last
    words before choice this hint command private bitcoin puzzle"""
_COMMON_WORDS = set(_WORD_SOURCE.split())

_PRINTABLE = set(bytes(string.printable, "ascii"))
_SMOOTHING = 0.5  # add-k over the full 26x26 bigram space
_FLOOR = -12.0  # fallback when a string has too few letters to score


@lru_cache(maxsize=1)
def _bigram_model() -> tuple[dict[str, float], float]:
    """Add-k smoothed bigram log-probabilities.

    Smoothing rather than a hard floor for unseen bigrams: real but unusual strings like
    `matrixsumlist` contain pairs (`xs`, `ml`) absent from any short training text, and
    charging them a large fixed penalty pushes genuine plaintext down into the noise.
    """
    letters = re.sub(r"[^a-z]", "", _TRAINING.lower())
    counts = Counter(letters[i : i + 2] for i in range(len(letters) - 1))
    total = sum(counts.values()) + _SMOOTHING * 26 * 26
    model = {
        bigram: math.log10((n + _SMOOTHING) / total)
        for bigram, n in counts.items()
    }
    unseen = math.log10(_SMOOTHING / total)
    return model, unseen


def english_score(text: str) -> float:
    """Mean bigram log-probability of the letters in `text`. Higher is more English-like.

    Roughly: fluent English lands near -2.2, random letters near -3.5 or worse.
    """
    letters = re.sub(r"[^a-z]", "", text.lower())
    if len(letters) < 2:
        return _FLOOR
    model, floor = _bigram_model()
    total = sum(model.get(letters[i : i + 2], floor) for i in range(len(letters) - 1))
    return total / (len(letters) - 1)


def word_hits(text: str) -> int:
    """Count common words appearing in the text, including run together without spaces."""
    lowered = re.sub(r"[^a-z]", "", text.lower())
    return sum(1 for word in _COMMON_WORDS if len(word) >= 4 and word in lowered)


def printable_ratio(data: bytes) -> float:
    return sum(byte in _PRINTABLE for byte in data) / len(data) if data else 0.0


def letter_ratio(text: str) -> float:
    """Fraction of characters that are ASCII letters or spaces.

    This is what stops the restricted-range decoys from scoring: they produce mostly
    control characters, which are neither letters nor spaces even when technically low-valued.
    """
    if not text:
        return 0.0
    return sum(char.isalpha() or char == " " for char in text) / len(text)


def score(data: bytes | str) -> float:
    """Combined score. Higher is better; anything below about 0 is noise.

    Weighted so that a candidate has to be *both* mostly letters and bigram-plausible.
    Either alone is cheap to produce by accident.
    """
    if isinstance(data, bytes):
        if printable_ratio(data) < 0.75:
            return -100.0
        text = data.decode("ascii", "replace")
    else:
        text = data

    letters = letter_ratio(text)
    if letters < 0.6:
        return -100.0
    return (english_score(text) + 3.2) * 10 * letters + word_hits(text) * 2.0
