# Paper → Code Mapping

Every clause of the paper traced to the code that implements it, plus an
explicit list of where this implementation deliberately differs.

Sources:

- *Secure Hybrid AES + Custom Cipher Encryption* (IEEE conference paper)
- *CipherX: A Secure Hybrid AES–Custom Structural Cipher with Base-26 Encoding
  and Multi-Layer Obfuscation* (project report)

---

## Algorithm 1 — `HYBRID_ENCRYPT(M, P, Kc)`

| Line | Paper step | Implementation |
|---:|---|---|
| 1 | `S ← RANDOM_BYTES(16)` | [`aead.seal`](../cipherx/aead.py) · `SALT_LEN` |
| 2 | `KA ← SCRYPT(P, S, N=2^16, r=8, p=2)` | [`kdf.derive_payload_keys`](../cipherx/kdf.py) |
| 3 | `IV ← RANDOM_BYTES(12)` | [`aead.seal`](../cipherx/aead.py) · `NONCE_LEN` |
| 4 | `(C, Tgcm) ← AES_GCM_ENCRYPT(KA, IV, M)` | [`aead.seal`](../cipherx/aead.py) |
| 5 | `B ← PACK(S‖IV‖C‖Tgcm)` | [`aead.seal`](../cipherx/aead.py) return value |
| 6 | `S26 ← BASE26_ENCODE(B)` | [`base26.encode`](../cipherx/base26.py) |
| 7 | `S1 ← NONLINEAR_MAP(S26)` | [`mapping.forward_map`](../cipherx/mapping.py) |
| 8 | `S2 ← VIGENERE_EXTEND(S1, Kc)` | [`structural.vigenere`](../cipherx/structural.py) |
| 9 | split into segments `{w1..wn}` | [`structural.segment_lengths`](../cipherx/structural.py) — **changed, see D2** |
| 10–18 | odd → reverse, even → keyed rotate | [`structural.transform_segments`](../cipherx/structural.py) |
| 20–21 | `S4 ← INSERT_NOISE(S3, rngN)` | [`structural.insert_noise`](../cipherx/structural.py) |
| 22–23 | `S5 ← BLOCK_SHUFFLE(S4, blk=6, rngB)` | [`structural.block_shuffle`](../cipherx/structural.py) — **changed, see D3** |
| 24 | `TH ← HMAC_SHA256(Kc, S5)` | [`hybrid.CipherX._tag`](../cipherx/hybrid.py) — **changed, see D4** |
| 25 | `CT ← S5 ‖ HEX(TH)` | [`hybrid.CipherX.encrypt`](../cipherx/hybrid.py) |

## Narrative sections

| Paper section | Topic | Implementation |
|---|---|---|
| 5.2 / 4.1 | Scrypt KDF, AES key + HMAC key | [`kdf.py`](../cipherx/kdf.py) |
| 5.3 / 4.2 | AES-256-GCM | [`aead.py`](../cipherx/aead.py) |
| 5.4 / 4.3 | Base-26 encoding, 4-letter header | [`base26.py`](../cipherx/base26.py) |
| 4.4 | HKDF–HMAC deterministic CSPRNG | [`csprng.py`](../cipherx/csprng.py) |
| 5.5.F / 5.6.1 | Nonlinear alphabet remapping | [`mapping.py`](../cipherx/mapping.py) |
| 5.5.G / 5.6.2 | Enhanced Vigenère shifting | `structural.vigenere` |
| 5.5.H / 5.6.3 | Word-level reversal and rotation | `structural.transform_segments` |
| 5.5.I | CSPRNG rotational obfuscation | `structural.transform_segments` |
| 5.5.J / 5.6.4 | Controlled noise insertion | `structural.insert_noise` |
| 5.6.5 | Block-level permutation | `structural.block_shuffle` |
| 5.5.K / 4.6 | HMAC-SHA256 outer integrity | `hybrid.CipherX._tag` |
| 5.8 | Error handling | [`exceptions.py`](../cipherx/exceptions.py) |
| 6 / 7 | Entropy, timing, expansion metrics | [`analysis.py`](../cipherx/analysis.py), [`benchmarks/`](../benchmarks/) |

---

## Deliberate differences

Five changes. Three are bug fixes, one resolves a contradiction in the paper,
one is a pure optimisation.

### D1 — Stage order corrected to match Algorithm 1

Algorithm 1 applies the Vigenère shift (line 8) **before** segmentation (line
9). The reference implementation ran the segment transform first and the
Vigenère afterwards. The documented order is used here.

*Pinned by* `tests/test_structural.py::TestFullLayer::test_stage_order_matches_algorithm_1`

### D2 — Segmentation that produces more than one segment

Algorithm 1 line 9 splits `S2` into "word-like segments" and lines 10–18 then
treat odd and even segments differently. The reference split on **whitespace**
— but its input is a Base-26 string, which contains none. There was always
exactly one segment, always odd, so the even-index branch (lines 14–16) was
unreachable and the CSPRNG rotational obfuscation of Section 5.5.I never ran.

Segment boundaries are now drawn from `CSPRNG(Kc, "SEGMENT")` with lengths in
`[4, 12]`. They depend only on the key and the total length — both known at
decryption — so reversibility is preserved. A 200-character string now yields
roughly 28 segments instead of 1.

*Pinned by* `tests/test_structural.py::TestSegmentation`

### D3 — Lossless block padding

The reference padded to a block multiple with `'X'` and recovered with
`rstrip('X')`. `'X'` is a legal Base-26 character, so any genuine trailing
`'X'` was silently eaten and the message destroyed.

Measured on the reference implementation:

| Structural key | Custom-layer round-trip failures |
|---|---|
| `akanksh-super-unique-key` (its shipped default) | **0 %** |
| `my-secret-m-key` | 6.5 % |
| `demo-key-2025` | 10 % |
| `MMMM` | 69 % |

Direct probes of the padding routine fail at 19/500 on uniformly random
letters and 29/29 on inputs ending in `'X'`.

The default key masks it by coincidence. The Base-26 header's first character
is `'A'` for any payload under 17,576 bytes; the odd-index reversal moves it to
the end; the nonlinear map sends `'A'` at position 1 to `'L'`; and turning
`'L'` into `'X'` needs a Vigenère shift of 12, i.e. an `'M'` in the key.
`akanksh-super-unique-key` contains no `'M'`, so the trailing character is
never `'X'` and the bug never fires — until someone changes the key.

Replaced with an explicit 6-character Base-26 length header prepended before
padding (exactly one block at the paper's `blk = 6`). This is the only change
that alters ciphertext length: **+6 characters**, which is precisely the offset
visible between this implementation and Table II.

*Pinned by* `tests/test_structural.py::TestBlockPermutation::test_payload_ending_in_x_survives`

### D4 — Outer HMAC key is derived

The paper contradicts itself. Algorithm 1 line 24 keys the outer tag with `Kc`
directly; Section 5.2 says the HMAC key comes from Scrypt. The reference used
raw `Kc.encode()`, satisfying neither.

Resolved as `HKDF(Kc, info="CIPHERX/v1/MAC")` — still `Kc` material as
Algorithm 1 requires, properly derived and domain-separated as Section 5.2
intends. The version label is bound into the MAC input so a ciphertext from one
pipeline version cannot be replayed against another.

Scrypt still produces 64 bytes and splits them into an AES key and a reserved
inner MAC key, as Section 5.2 describes.

### D5 — Base-26 conversion is subquadratic

The paper reads the packed blob as one big integer and peels digits with
`divmod(n, 26)`. That is O(d²) word operations — about 22,000 divisions against
an 80,000-bit integer for the 10 kB test case.

This implementation produces the **identical digit string** by recursive
splitting at `26^(d/2)`. `tests/test_base26.py::TestEquivalence` asserts
equality against a literal transcription of the paper's method, so fidelity is
exact and the change is invisible in the output.

---

## Reproduction

```bash
python benchmarks/reproduce_paper.py
```

Measured on Python 3.12, against the published tables:

| Input | Paper enc / dec / len | This implementation |
|---:|---|---|
| 12 | 556 / 525 / 136 | 591 / 518 / 142 |
| 71 | 496 / 497 / 256 | 442 / 402 / 262 |
| 37 | 428 / 466 / 190 | 407 / 468 / 196 |
| 44 | 447 / 480 / 202 | 453 / 446 / 208 |
| 1,000 | 470 / 462 / 2,158 | 449 / 449 / 2,164 |
| 10,000 | 584 / 499 / 20,536 | 481 / 467 / 20,542 |

Every ciphertext length is exactly **+6** — the length header from D3.
Entropy averages 5.25 bits/char against the paper's 5.28, inside the published
5.23–5.33 band. Timings differ by hardware, but the shape holds: a 1.45×
spread in encryption time across an 833× range of input sizes, because Scrypt
accounts for 87 % of the clock.
