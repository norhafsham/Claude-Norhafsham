# The SalPhaseIon letter block

A structural map of the 1075-character block on the
[SalPhaseIon page](https://gsmg.io/89727c598b9cd1cf8873f27cb7057f050645ddb6a7a157a110239ac0152f6a32),
and a decoding sweep over the parts nobody has solved.

Companion to [ANALYSIS.md](ANALYSIS.md), which covers the AES blobs and concluded that the
passphrases have to come from decoding more of this block rather than from recombining
already-known strings. This is that attempt.

**Result: no new plaintext.** Everything decodable by published methods was already known,
and the two large undecoded regions score no better than shuffled copies of themselves.
That negative is quantified below rather than asserted.

## The map

`block.py` derives these boundaries from the data — `z` separators and long `a`/`b` runs —
rather than hard-coding offsets, so the map can be re-checked against the source:

| Span | Kind | Content | Status |
|------|------|---------|--------|
| `[0:91]` | digits | **region A**, 91 chars | **undecoded** |
| `[91:195]` | binary | `matrixsumlist` | decoded |
| `[195:765]` | digits | **region B**, 570 chars | **undecoded** |
| `[766:829]` | digits | `lastwordsbeforearchichoice` | decoded |
| `[830:859]` | digits | `thispassword` | decoded |
| `[860:958]` | mixed | `shabef` + `ourfirsthintisyourlastcommand` + base64 | decoded |
| `[959:999]` | binary | `enter` | decoded |
| `[999:1075]` | mixed | base64 (second half of blob A) + `shabef` + `anstoo` | decoded |

Two encodings are in play. `a`–`i` are digits 1–9 and `o` is 0; separately, runs drawn from
only `a`/`b` are binary (`a`=0, `b`=1), which is how `matrixsumlist` and `enter` are carried.
`shabef` is the digit alphabet applied to letters: `sha` + `b`=2, `e`=5, `f`=6 → `sha256`.

Both markers are *inserted into* other data rather than appended to it: `enter` splits the
base64 blob across `[959:999]`, and `matrixsumlist` sits between regions A and B the same
way. So the undecoded mass is A + B = **661 characters**.

## Four findings that constrain the search

**1. The undecoded regions contain no zero.** The solved segments use `o` for 0. A and B use
`a`–`i` exclusively — 1 through 9, never 0. A 1-indexed alphabet is what you would expect of
*coordinates* rather than values, which is why the sweep includes Polybius-style readings.

**2. The published method fails on them.** Digits → decimal integer → base 16 → ASCII gives
100% printable on both solved segments and 42% / 33% on A / B, i.e. noise:

```console
$ python3 -c "import block; s=block.segment(block.load_tokens()); \
    print([x.as_base16() for x in s if x.kind=='digits' and x.length<80])"
[b'lastwordsbeforearchichoice', b'thispassword']
```

**3. Region B's index of coincidence is flat.** IC = 0.118 against 0.111 for a uniform
9-symbol alphabet — a ratio of **1.06**, where English sits near 1.73 and random sits at
1.00. B is not a substitution cipher over natural language. It is either already encrypted
or a dense uniform encoding. (The whole-block IC looks higher only because the embedded
`a`/`b` marker skews the pair counts; that is an artifact, not structure.)

**4. Scoring by "printable ratio" is worthless here.** Values 0–80 are 60% printable *by
construction*, so a chunked base-9 decoding scored 77% and briefly looked like a hit. The
scorer in `score.py` uses smoothed bigram log-probability plus word hits and a letter-ratio
gate instead. Calibration, asserted in the tests:

| Input | Score |
|-------|-------|
| `ourfirsthintisyourlastcommand` | 17.2 |
| `lastwordsbeforearchichoice` | 15.5 |
| `matrixsumlist` | 9.6 |
| random `a`–`i` strings | ≤ 3.3 |
| restricted-range decoys, random bytes | −100 |

## The sweep

`decode.py` composes three stages — **mask → reader → decoder** — and ranks every
combination:

- **masks**: plain; XOR and mod-9 addition against the 196-bit key stream from the first
  puzzle piece
- **readers**: identity, plus column-wise and boustrophedon transposition through every
  rectangle that divides the region's length
- **decoders**: binary; decimal → base 16; chunked base-9/base-10 (sizes 2–4, both digit
  offsets); group sum and product → a1z26 (sizes 2–5); Polybius over a 9×9 square keyed by
  five puzzle strings

4,536 combinations per full sweep, 72,576 including the shuffled controls.

The 14×14 grid used for the masks is pinned in `data/first_puzzle_matrix.txt` and validated
by a control: read counterclockwise from the upper left it must produce
`gsmg.io/theseedisplanted`, the known phase-1 answer. Unvalidated key material would make
any result meaningless.

## Results

The important control is **rediscovery**: the same machinery, pointed at the block with no
hand-placed boundaries, must recover the four decodings already known to be correct.

```console
$ python3 decode.py --rediscover
  rediscovered 'matrixsumlist': PASS
  rediscovered 'enter': PASS
  rediscovered 'lastwordsbeforearchichoice': PASS
  rediscovered 'thispassword': PASS
  sweep ranks known segment correctly: PASS  -> 'lastwordsbeforearchichoice'
```

Against the undecoded regions, each compared with 15 shuffled copies of itself — same
length, same letter frequencies, no ordering — with a rank-based p-value:

| Region | Chars | Best score | Shuffled max | Shuffled mean | p | Verdict |
|--------|-------|-----------|--------------|---------------|---|---------|
| A | 91 | 4.05 | 5.35 | 3.66 | 0.375 | no signal |
| B | 570 | 3.29 | 4.75 | 2.96 | 0.188 | no signal |
| A+B | 661 | 1.11 | 3.17 | 1.82 | 0.750 | no signal |
| main | 765 | 2.85 | 3.17 | 2.69 | 0.500 | no signal |

Every region scores inside the band its own shuffled data produces, and every best result
sits far below the 9.6–17.2 band that real plaintext occupies.

One methodological note, because it nearly became a false claim: at 5 trials region B
cleared the shuffled maximum by 0.20 and the tool reported "ABOVE noise". At 25 trials it
sat mid-distribution. The observed maximum of a handful of samples is itself noisy, so the
verdict is now a rank-based p-value rather than a comparison against the best of a few runs.

## What this rules out, and what it doesn't

Ruled out: that regions A and B yield English under any composition of the transformations
above, including every one that solved an earlier stage of this puzzle.

Not ruled out: essentially any keyed transformation. Finding 3 is the honest bound — a flat
index of coincidence means there is no statistical structure left to exploit, so if B is
enciphered, sweeping cannot recover it without the key. Adding more transformations to the
registry is unlikely to help; the missing ingredient is external information, not search.

The one lead that remains untested by anything here is the instruction itself.
`matrixsumlist` is imperative, and `our first hint is your last command` points back to the
first puzzle piece — but "sum" over the 14×14 grid has many plausible readings (row sums,
column sums, spiral partial sums), and picking among them needs a constraint the block does
not supply. That is where a solver should look, not at wider automated sweeps.

## Reproducing

```console
$ cd gsmg-puzzle
$ python3 decode.py --rediscover              # the control that makes negatives meaningful
$ python3 decode.py --all --null --trials 15  # sweep + shuffled comparison
$ python3 decode.py --region B --limit 10     # top candidates for one region
$ pytest test_decoding.py
```
