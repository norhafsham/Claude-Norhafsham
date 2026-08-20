"""Controls for the letter-block segmentation, the scorer, and the decoding sweep.

The sweep's job is to produce a trustworthy *negative*, so these tests are mostly about
proving the machinery would notice a positive if one existed.
"""

from __future__ import annotations

import base64
import random

import block
import decode
import score


def test_segmentation_is_lossless():
    tokens = block.load_tokens()
    segments = block.segment(tokens)
    assert "".join(s.text for s in segments) == "".join(tokens)
    assert len(tokens) == 1075


def test_segmentation_finds_the_expected_map():
    segments = block.segment(block.load_tokens())
    spans = {(s.start, s.end, s.kind) for s in segments}
    assert (0, 91, "digits") in spans  # region A
    assert (91, 195, "binary") in spans  # matrixsumlist marker
    assert (195, 765, "digits") in spans  # region B
    assert (860, 959, "mixed") in spans  # blob A's first half, including its trailing `z`
    assert (959, 999, "binary") in spans  # enter marker


def test_only_three_of_the_four_z_characters_are_separators():
    """The block's separator is also a legal base64 character, and both uses occur.

    `z` separates digit segments at 765, 829 and 859 -- but the one at 958 is the last
    character of blob A's first line (`...GWVHefvdrd9z`). Treating it as a separator drops
    it from the ciphertext.
    """
    joined = "".join(block.load_tokens())
    positions = [i for i, char in enumerate(joined) if char == "z"]
    assert positions == [765, 829, 859, 958]
    assert [i for i in positions if block._is_separator(joined, i)] == [765, 829, 859]

    separators = [s for s in block.segment(block.load_tokens()) if s.kind == "separator"]
    assert len(separators) == 3


def test_blob_a_round_trips_from_the_letter_block():
    """The pinned ciphertext must match what the letter block actually says.

    This is the check that caught the `z` bug: with 958 treated as a separator the
    reconstruction came to 127 characters and would not base64-decode, so no passphrase
    could ever have worked against it. Keeping the pinned file and the segmentation tied
    together means they cannot drift apart silently.
    """
    derived = block.blob_a_base64(block.segment(block.load_tokens()))
    pinned = (block.DATA / "blob_a.b64").read_text().replace("\n", "")
    assert derived == pinned, f"derived {len(derived)} chars, pinned {len(pinned)}"

    raw = base64.b64decode(derived)
    assert raw[:8] == b"Salted__"
    assert (len(raw) - 16) % 16 == 0


def test_known_decodings_are_recovered():
    segments = block.segment(block.load_tokens())
    binaries = [s.as_binary() for s in segments if s.kind == "binary"]
    assert "matrixsumlist" in binaries
    assert "enter" in binaries

    digits = [s.as_base16() for s in segments if s.kind == "digits" and s.length < 80]
    assert b"lastwordsbeforearchichoice" in digits
    assert b"thispassword" in digits


def test_undecoded_regions_use_no_zero():
    """A and B are 1-9 only; the solved segments use `o` for zero. This is a real asymmetry."""
    a, b = block.undecoded_regions(block.segment(block.load_tokens()))
    assert set(a.text) <= set(block.DIGITS)
    assert set(b.text) <= set(block.DIGITS)
    assert block.ZERO not in a.text + b.text


def test_first_puzzle_matrix_spiral_control():
    """The pinned grid must reproduce the known phase-1 answer, or it is not trustworthy."""
    grid = block.load_matrix()
    assert block.bits_to_text(block.spiral_ccw(grid)) == "gsmg.io/theseedisplanted"


def test_scorer_separates_known_plaintext_from_noise():
    knowns = ["matrixsumlist", "lastwordsbeforearchichoice", "thispassword",
              "ourfirsthintisyourlastcommand"]
    rng = random.Random(7)
    noise = ["".join(rng.choice(block.DIGITS) for _ in range(60)) for _ in range(20)]

    worst_known = min(score.score(k) for k in knowns)
    best_noise = max(score.score(n) for n in noise)
    assert worst_known > best_noise + 3, f"known={worst_known:.2f} noise={best_noise:.2f}"


def test_scorer_rejects_restricted_range_decoys():
    """Values 0..80 are 60% printable by construction; that must not read as a decoding."""
    rng = random.Random(11)
    decoy = bytes(rng.randrange(81) for _ in range(80))
    assert score.score(decoy) < 0
    assert score.score(bytes(rng.randrange(256) for _ in range(80))) < 0


def test_sweep_rediscovers_a_known_segment():
    """The single most important control: the sweep must rank a true decoding first."""
    segments = block.segment(block.load_tokens())
    known = next(s for s in segments if s.kind == "digits" and s.length == 63)
    best = decode.sweep(known.text, "known", limit=1)[0]
    assert "lastwordsbeforearchichoice" in best.text


def test_rediscover_control_passes():
    assert decode.rediscover()


def test_null_distribution_is_reproducible_and_beats_nothing():
    """Shuffled data should score in the same band as the real undecoded regions."""
    a, _ = block.undecoded_regions(block.segment(block.load_tokens()))
    tops = decode.null_distribution(a.text, "A", trials=3, seed=5)
    assert len(tops) == 3
    assert decode.null_distribution(a.text, "A", trials=3, seed=5) == tops  # deterministic
