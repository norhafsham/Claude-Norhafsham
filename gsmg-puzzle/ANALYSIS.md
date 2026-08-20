# The undecoded GSMG.IO AES blobs

Notes and a cracking rig for the ciphertexts left unsolved at the end of the
[GSMG.IO 5 BTC puzzle](https://gsmg.io/puzzle). Source material:
[`puzzlehunt/gsmgio-5btc-puzzle`](https://github.com/puzzlehunt/gsmgio-5btc-puzzle),
whose README documents the solved chain up to phase 3.2 and then stops.

**Result: no passphrase found.** That is the expected outcome — the puzzle has been public
since 2019 with a live bounty. What is here is a calibrated rig, three findings that
invalidate the obvious naive approach, and an honest record of what has been ruled out.

## The ciphertexts

Four OpenSSL `Salted__` containers. The first is solved and is used as a control; the rest
are open.

| Blob | Blocks | Salt | Provenance | State |
|------|--------|------|------------|-------|
| `known_phase32.b64` | 152 | `eefc4c5befc1656a` | README lines 209–259 | **solved**, passphrase published |
| `blob_c.b64` | 5 | `b45a5e3d827593ca` | tail of the decrypted phase-3.2 plaintext | open |
| `blob_a.b64` | 5 | `3ab585348552415d` | embedded in the SalPhaseIon letter block | open |
| `blob_b.b64` | 83 | `2d3f6fe06dc950e6` | the Cosmic Duality textarea | open |

Three things worth recording about provenance:

- **`blob_a` is split in the source.** In the puzzle README it appears interrupted
  mid-ciphertext by an `abba` binary run (which separately decodes to `enter`). The
  README's own "AES Blob" section reassembles it by excising that run; the reassembled
  128 base64 chars decode to 96 bytes with an intact `Salted__` header and exactly 5
  cipher blocks, which is good evidence the reassembly is correct.
- **`blob_c` is not discussed anywhere in the README.** It sits at the end of the phase-3.2
  plaintext, so chronologically it is the *next* step after the last solved stage — arguably
  a better target than `blob_a`. It surfaced here only because the control decryption
  printed the full plaintext.
- **`blob_b` could not be reconstructed from the repo.** The repo's screenshot crops it.
  The full 1792-char ciphertext was fetched from the live page and pinned in `data/`, along
  with the authoritative 2149-char SalPhaseIon letter block (the README's transcription of
  those letters is partial).

## Three findings that break the naive approach

### 1. The KDF is SHA-256, not MD5

`openssl enc` used MD5 to derive keys before 1.1.0 and SHA-256 after. A rig that assumes the
legacy default is silently wrong on every candidate. Settled by decrypting the solved blob
both ways — only SHA-256 produces the plaintext:

```console
$ openssl enc -aes-256-cbc -d -a -md md5 -in data/known_phase32.b64 \
    -pass pass:250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c
<binary garbage>

$ openssl enc -aes-256-cbc -d -a -md sha256 -in data/known_phase32.b64 \
    -pass pass:250f37726d6862939f723edc4f993fde9d33c6004aab4f2203d9ee489d61ce4c
I've been waiting for you. You have many questions, ...
```

### 2. "Did openssl print anything?" matches every passphrase

OpenSSL streams plaintext blocks to stdout as it goes and only fails at the end, when the
final block's padding turns out to be wrong. On a 5-block blob it therefore emits 4 blocks
of garbage for a *wrong* passphrase before erroring. Any wrapper that tests for non-empty
output — or that reads `$?` after a pipeline, where the exit status belongs to the last
command — scores a hit on everything it tries.

Detection must use openssl's own exit code (0 = padding validated, 1 = rejected), or check
the padding directly as this rig does.

### 3. Printable *ratio* is the wrong success signal

The obvious "is this real text" test rejects a known-correct decryption. The solved
phase-3.2 plaintext is only **60% printable ASCII**, because it embeds box-drawing
characters and a base64 blob alongside its English. A 90% threshold discards it.

`crack.py` scores the **longest unbroken run of printable ASCII** instead. English, base64
and hex all produce one long run; random bytes (p ≈ 0.39 per byte) give an expected maximum
run near 5. The end-to-end control in `--self-test` exists specifically because this bug was
live until that control caught it.

## The rig

Neither crypto library in this environment is usable — pycryptodome is absent, and
`cryptography` 41.0.7 imports but its Rust binding raises `PanicException` — so `aes.py`
implements the AES-256 inverse cipher and `EVP_BytesToKey` directly, with no dependencies.
S-box and GF tables are derived at import rather than pasted, removing transcription risk.

Each candidate is checked in two stages:

1. **Filter.** Decrypt only the *last* CBC block and test its PKCS#7 padding. CBC makes that
   block depend solely on the last two ciphertext blocks, so the cost is one block-decrypt
   regardless of whether the blob is 5 blocks or 83. Measured ~7,600 candidates/sec, against
   ~200/sec if `openssl` were spawned per candidate.
2. **Confirm.** Roughly 1 in 256 wrong passphrases produces valid padding by chance, so
   survivors are fully decrypted and scored before anything is reported.

Every candidate is tried in four encodings — raw, lowercase SHA-256 hex, that hex uppercased,
and the digest of the digest — because every solved stage used the *digest* of a phrase as
the passphrase rather than the phrase itself.

`candidates.py` is seeded from puzzle-internal material only: the four decoded SalPhaseIon
strings, the solved-stage parts, the literal strings the puzzle told solvers to hash, and a
Matrix/Alice thematic set marked `SPECULATIVE`. It then applies the puzzle's own documented
transformation rules — `/(aaa, connected enf)` (lowercase, strip whitespace) versus
`/(aBa, connected not enf)` (preserve casing and whitespace) — and ordered concatenation.
A generic English wordlist would be pointless: every historical answer was a phrase the
solver *constructed*, not a dictionary word.

## Results

Corpus of 28,914 unique candidates (concatenation depth 3) × 4 encodings = 115,656 checks
per blob:

| Blob | Checks | Padding survivors | Observed rate | Real hits |
|------|--------|-------------------|---------------|-----------|
| `a` | 115,656 | 432 | 0.373% | 0 |
| `b` | 115,656 | 431 | 0.373% | 0 |
| `c` | 115,656 | 466 | 0.403% | 0 |

Survivor rates track the theoretical 1/256 = 0.391% closely. That is itself a useful
negative result: the ciphertexts show no structural deviation from what correctly-encrypted
AES-CBC should look like, so there is no shortcut visible at this level — the passphrase
has to come from solving the puzzle, not from the ciphertext.

Best near-miss on any blob was a 13-character printable run, consistent with noise
(432 draws from a distribution whose single-sample maximum is ~5).

## What this does and does not rule out

Ruled out: the four decoded SalPhaseIon strings, the solved-stage passphrases and their
digests, the literal hashed strings, and ordered concatenations up to three terms across
those, under four encodings and four casings.

Not ruled out — essentially everything else. In particular the corpus assumes the passphrase
is built from strings *already decoded*. If the SalPhaseIon letter block hides further
plaintext (the README decodes only part of its 2149 characters), the real passphrase is
probably a string nobody has extracted yet, and no amount of recombining known fragments
will reach it. The productive next step is decoding more of `data/salphaseion_letters.txt`,
not enlarging this corpus.

Unbounded brute force is deliberately not attempted. The keyspace is a chosen English
phrase, so untargeted search is wasted compute and is not a path to the bounty.

**Followed up in [DECODING.md](DECODING.md).** The next step named above — decoding more of
the letter block — was attempted and produced no new plaintext. It did establish that the
two undecoded regions score no better than shuffled copies of themselves, and that region B
has a flat index of coincidence, which bounds what any further sweeping can achieve.

## The phrase-window sweep

The corpus above recombines known *short strings*. That is the wrong shape. The SalPhaseIon
block's decoded fragments read as an ordered recipe:

| Fragment | Reading |
|---|---|
| `lastwordsbeforearchichoice` | the last words before the Architect's choice |
| `thispassword` | …is this password |
| `ourfirsthintisyourlastcommand` | the first hint is the last instruction |
| `shabef` + `anstoo` | `sha256`, *answer too* — hash the answer as well |

So the intended passphrase is a **phrase** lifted from a narrative text, stripped per the
puzzle's own `/(aaa, connected enf)` convention and hashed. Every solved stage worked that
way: the phase-3.2 key is `SHA256("jacquefrescogiveitjustonesecondheisenbergsuncertainty`
`principle")` — three quote answers run together.

`CHOICE` appears nowhere in the puzzle's own Architect text, so the phrase anchors to the
film scene. Rather than guess where to cut, `phrases.py` enumerates **every contiguous word
window** of every text available, longest-first:

| Source | Words | Windows |
|--------|-------|---------|
| `architect.txt` (Beaufort plaintext) | 336 | 56,616 |
| `film_lines.txt` (**approximate**, recalled) | 210 | 22,155 |
| `phase32` (decrypted at runtime, not transcribed) | 100 | 5,050 |
| `decoded_lines.txt` | 91 | 4,186 |
| **total** | | **88,007** |

Times four normalisations and four encodings: **1,152,396 candidates per blob.**

### Result

| Blob | Candidates | Padding survivors | Longest span | Hits |
|------|-----------|-------------------|--------------|------|
| B (Cosmic Duality) | 1,152,396 | 4,569 | 15 | **0** |
| A | 1,152,396 | 4,596 | 15 | **0** |
| C | 1,152,396 | 4,552 | 13 | **0** |

Survivor counts sit at 0.40% against the theoretical 1/256 = 0.39%, and the longest printable
spans match the wrong-key distribution exactly (measured median 8, max 15 on a blob this
size). Nothing stands out from noise anywhere.

### The control that makes this mean something

`crack.py --phrase-control` runs the entire pipeline — window → lowercase-and-strip →
SHA-256 → decrypt — against the one blob whose passphrase is published, and requires it to
come back with exactly that key. It recovers it from 1,152,396 candidates, alone.

Getting that control to pass exposed a real defect. On its first run it reported **three**
hits on a blob with one known key. Cause: the hit test was span length alone, `>= 16`
printable characters. A wrong key's longest span tops out near 15 on a 2.4 KB blob — but
4,527 padding survivors give roughly one in 1,300 a chance of clearing 16 anyway, so about
three false hits were expected, and three arrived. The span now also has to read as language
under the calibrated scorer in `score.py`. That threshold had been fine for every earlier
sweep and only broke at a million candidates.

### What this rules out

Ruled out: any passphrase that is a contiguous word window of these texts, under four
normalisations and four encodings.

Not ruled out, and worth being plain about: a phrase that is **paraphrased**, drawn from a
source not in `data/`, or assembled from **non-adjacent** pieces the way the phase-3.2 key
was — that key is three separate answers concatenated, which is exactly the shape this sweep
cannot reach for texts it does not already hold verbatim. And `film_lines.txt` is recalled
rather than sourced, so a wording error there is a silent miss; a negative over that file is
weaker than one over the puzzle's own texts.

```console
$ python3 crack.py --phrase-control        # ~3.5 min; must recover the known key
$ python3 crack.py --blob b --source phrases
```

## Reproducing

```console
$ cd gsmg-puzzle
$ python3 crack.py --self-test          # controls; run before trusting any result
$ python3 crack.py --blob a --max-terms 3
$ python3 crack.py --blob b --max-terms 3
$ python3 crack.py --blob c --max-terms 3
$ pytest test_aes.py                    # FIPS-197 vector + 101-candidate openssl parity
```

`test_aes.py` checks the pure-Python implementation against the real `openssl` binary
candidate-for-candidate, including key/IV derivation against `openssl enc -P`. A negative
cracking result is only worth as much as the rig that produced it.
