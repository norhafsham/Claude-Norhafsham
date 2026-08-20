"""Controls for the matrix-sum readings and the length-aware confidence guard.

The regression test that matters here is `cohert`: a six-letter output that scores 9.76,
inside the band real plaintext occupies, and is nonetheless noise. It is pinned so the
guard cannot silently regress.
"""

from __future__ import annotations

import random

import block
import matrixsum
import score


def test_grid_sums_match_the_documented_values():
    sums = matrixsum.grid_sums(block.load_matrix())
    assert sums["rowsums"] == [6, 10, 8, 7, 6, 6, 5, 4, 9, 9, 7, 8, 7, 9]
    assert sums["colsums"] == [8, 10, 8, 10, 8, 7, 3, 6, 7, 5, 9, 6, 6, 8]
    assert sum(sums["rowsums"]) == sum(sums["colsums"]) == 101


def test_every_reading_family_produces_output():
    grid = block.load_matrix()
    a, _ = block.undecoded_regions(block.segment(block.load_tokens()))
    for name, reading in matrixsum.READINGS.items():
        produced = list(reading(a.text, grid))
        assert produced, f"{name} produced nothing"


def test_cohert_is_reproducible_and_rejected():
    """The exact false positive: real, high-scoring, and not a decoding."""
    _, b = block.undecoded_regions(block.segment(block.load_tokens()))
    results = matrixsum.run(b.text, block.load_matrix())
    best_score, best_name, best_text = results[0]

    assert best_text == "cohert"
    assert best_score > 9.0, "the point is that it scores in the plaintext band"
    assert "95x6" in best_name
    assert not score.confident(best_text), "must not be reported as a hit"


def test_shuffled_data_reaches_the_same_score_under_that_reading():
    """Why `cohert` is rejected: shuffled copies of B land in the same band.

    Asserted as a margin against the real best rather than a fixed number, because the
    shuffled maximum moves with the seed and trial count -- the very instability that made
    an earlier max-based verdict unreliable.
    """
    _, b = block.undecoded_regions(block.segment(block.load_tokens()))
    grid = block.load_matrix()
    best = matrixsum.run(b.text, grid)[0][0]
    tops = matrixsum.null_top(b.text, grid, trials=20, seed=3)
    assert max(tops) >= best - 1.0, f"shuffled max {max(tops):.2f} vs real {best:.2f}"


def test_no_reading_is_confident():
    """Records the outcome: none of the 82 readings clears the bar."""
    grid = block.load_matrix()
    a, b = block.undecoded_regions(block.segment(block.load_tokens()))
    for region in (a.text, b.text):
        assert not [r for r in matrixsum.run(region, grid) if score.confident(r[2])]


def test_confidence_guard_keeps_genuine_short_plaintexts():
    """`thispassword` (12) and `matrixsumlist` (13) are real and must survive the guard."""
    assert score.confident("thispassword")
    assert score.confident("matrixsumlist")
    assert score.confident("lastwordsbeforearchichoice")
    assert not score.confident("cohert")


def test_confidence_threshold_is_justified_by_chance_rates():
    """At the chosen length, random strings should essentially never reach the threshold."""
    rng = random.Random(42)
    length = score.MIN_RELIABLE_LETTERS
    hits = sum(
        score.score("".join(rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(length)))
        >= 8.0
        for _ in range(2000)
    )
    assert hits <= 2, f"{hits}/2000 random strings reached the threshold at length {length}"


def test_null_top_is_deterministic():
    a, _ = block.undecoded_regions(block.segment(block.load_tokens()))
    grid = block.load_matrix()
    assert matrixsum.null_top(a.text, grid, trials=3, seed=9) == matrixsum.null_top(
        a.text, grid, trials=3, seed=9
    )
