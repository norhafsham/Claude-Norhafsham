"""Controls for the phrase-window sweep.

The sweep exists to produce a trustworthy negative on the Cosmic Duality blob, so what
matters is proving it would find a passphrase of the expected shape if one were there.
The full control lives behind `crack.py --phrase-control` because it takes minutes; these
tests exercise the same chain on a small corpus.
"""

from __future__ import annotations

import hashlib
import random

import crack
import phrases

# The phase-3.2 passphrase is SHA256 of these three quote answers run together. It is the
# only passphrase in this puzzle whose construction is published, so it is the one thing
# that can validate the "phrase -> strip -> hash" assumption the sweep is built on.
CONTROL_PHRASE = "jacquefrescogiveitjustonesecondheisenbergsuncertaintyprinciple"


def test_window_count_and_ordering():
    words = ["a", "b", "c", "d"]
    produced = list(phrases.windows(words))
    assert len(produced) == len(words) * (len(words) + 1) // 2
    lengths = [len(w) for w in produced]
    # Longest-first, so a hit names the most specific phrase that works.
    assert lengths == sorted(lengths, reverse=True)
    assert words in produced


def test_normalisations_cover_the_puzzles_conventions():
    forms = set(phrases.normalisations(["Two", "Words"]))
    assert "twowords" in forms  # /(aaa, connected enf)
    assert "two words" in forms  # /(aaa, connected not enf)
    assert "TWOWORDS" in forms


def test_phase32_text_comes_from_the_pinned_ciphertext():
    """The text is decrypted, not transcribed, so it cannot drift from what the puzzle emitted."""
    assert "waiting for you" in phrases.phase32_text().lower()


def test_corpus_contains_the_control_phrase():
    assert any(candidate == CONTROL_PHRASE for candidate in phrases.generate())


def test_control_phrase_hashes_to_the_known_key():
    assert hashlib.sha256(CONTROL_PHRASE.encode()).hexdigest() == crack.KNOWN_PASSWORD.decode()


def test_search_recovers_the_known_key_from_a_phrase_corpus():
    """The whole chain on a small corpus: window -> normalise -> SHA-256 -> decrypt."""
    rng = random.Random(4)
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    decoys = ["".join(rng.choice(alphabet) for _ in range(20)) for _ in range(200)]
    corpus = [*decoys[:100], CONTROL_PHRASE, *decoys[100:]]
    hits = crack.search(crack.load("known"), iter(corpus))
    assert len(hits) == 1
    assert hits[0][1].startswith(b"I've been waiting for you.")


def test_is_hit_rejects_a_random_padding_survivor():
    """Regression: span length alone let three false hits through on a 2.4 KB blob.

    A wrong key's longest printable span tops out near 15 there, but with thousands of
    padding survivors some clear 16 by chance, so the span must also read as language.
    """
    rng = random.Random(2)
    junk = bytes(rng.randrange(256) for _ in range(2422))
    assert not crack.is_hit(junk, 16)

    real = crack.load("known").decrypt(crack.KNOWN_PASSWORD)
    assert crack.is_hit(real, 16)


def test_longest_printable_span_finds_the_english_paragraph():
    real = crack.load("known").decrypt(crack.KNOWN_PASSWORD)
    span = crack.longest_printable_span(real)
    assert len(span) > 400
    assert span.startswith(b"I've been waiting for you.")
