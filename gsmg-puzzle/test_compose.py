"""Controls for the composition sweep and the corpus extraction fix.

The sweep's job is a trustworthy negative, so the test that matters is the one proving the
composer reproduces the single published key of its own shape.
"""

from __future__ import annotations

import compose
import crack
import phrases


def test_composer_recovers_the_published_key_and_only_it():
    """phase 3.2's key is three atoms concatenated in order -- exactly what this builds.

    Depth 3 rather than 4: the control needs to exercise the shape, not the whole space,
    and depth 4 would make the suite slow for no extra assurance.
    """
    hits = crack.search(crack.load("known"), compose.compose(min_depth=3, max_depth=3))
    assert len(hits) == 1, f"expected exactly the known key, got {[h[0] for h in hits]}"
    assert hits[0][1].startswith(b"I've been waiting for you.")


def test_control_entrypoint_passes():
    assert compose.control()


def test_atoms_are_unique_and_carry_provenance():
    """Every atom has to be traceable to a stage, or a negative cannot be stated precisely."""
    names = compose.atoms()
    assert len(names) == len(set(names)), "duplicate atoms inflate the search for nothing"
    for atom, provenance in compose.ATOMS:
        assert atom and provenance, f"{atom!r} is missing provenance"


def test_composition_depth_and_uniqueness():
    produced = list(compose.compose(min_depth=2, max_depth=2))
    assert produced, "depth 2 must produce candidates"
    assert len(produced) == len(set(produced)), "candidates must be deduplicated"
    # Both separator conventions appear: /(connected enf) and /(connected not enf).
    assert any(" " in candidate for candidate in produced)
    assert any(" " not in candidate for candidate in produced)


def test_phase32_extraction_keeps_short_words_between_punctuation():
    """Regression: `A fubcd-king & oracle-queen` used to yield only `fubcd queen`.

    The prose selector matched `[A-Za-z ',.]{12,}`, so `king` and `oracle` -- short
    fragments bounded by a hyphen and an ampersand -- fell below the length floor and were
    dropped. No phrase window ever contained them until this was fixed.
    """
    words = phrases.sources()["phase32"]
    for word in ("king", "oracle", "fubcd", "queen"):
        assert word in words, f"{word!r} missing from the phase-3.2 corpus"


def test_phase32_extraction_excludes_payloads():
    """The plaintext embeds base64, a digit run and an EBCDIC block; none are prose."""
    words = phrases.sources()["phase32"]
    assert "sWDzNLxDmlPMsDSiuW" not in words
    assert not [w for w in words if len(w) > 20 and not w.islower()], "looks like a payload"


def test_initialisms_are_generated():
    produced = list(compose.initialisms())
    assert produced
    assert all(len(candidate) >= 4 for candidate in produced)
