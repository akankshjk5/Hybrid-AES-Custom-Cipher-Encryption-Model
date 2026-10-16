# CipherX

**A hybrid AES-256-GCM + custom structural cipher with Base-26 alphabet-only encoding.**

Reference implementation of *"Secure Hybrid AES + Custom Cipher Encryption"* —
Akanksh J K and Sujal Sunil Badde, Dept. of Cyber Security, NMAM Institute of
Technology, Nitte.

[![tests](https://github.com/akankshjk5/Hybrid-AES-Custom-Cipher-Encryption-Model/actions/workflows/ci.yml/badge.svg)](https://github.com/akankshjk5/Hybrid-AES-Custom-Cipher-Encryption-Model/actions/workflows/ci.yml)
![python](https://img.shields.io/badge/python-3.9%2B-blue)
![license](https://img.shields.io/badge/license-MIT-green)

---

## What it is

AES-GCM is excellent at keeping message *contents* secret and terrible at
hiding everything around them — message length, repetition, block alignment,
the unmistakable shape of Base64. In repetitive IoT telemetry that residue is
enough to infer device behaviour without breaking anything. And its binary
output simply will not pass through SMS gateways, SCADA links or text-only log
pipelines.

CipherX wraps AES-256-GCM in a reversible structural layer that converts the
ciphertext to a restricted alphabet and scrambles its visible structure:

```
plaintext
   │  Scrypt(N=2¹⁶, r=8, p=2) ───────────► AES-256 key + MAC key
   ▼
AES-256-GCM  ──► salt ‖ nonce ‖ ciphertext ‖ tag
   ▼
Base-26      ──► 4-letter length header + A–Z body
   ▼
Structural layer  ◄── fresh 16-char nonce per message
   ├─ nonlinear alphabet remapping
   ├─ enhanced Vigenère shifting
   ├─ keyed segment reversal / rotation
   ├─ deterministic noise insertion
   └─ block-level permutation
   ▼
HMAC-SHA256 outer tag
   ▼
nonce ‖ body ‖ tag
```

Every structural stage is a bijection driven by an HKDF/HMAC-SHA256 CSPRNG
seeded by the key *and a per-message nonce*, so decryption redraws the
identical choices and runs the inverses in reverse. The nonce travels in the
clear like an IV and is authenticated by the outer tag.

> **Read [`docs/SECURITY.md`](docs/SECURITY.md) before using this for
> anything.** The security of CipherX is the security of AES-256-GCM; the
> structural layer is obfuscation. Six findings are documented there — one
> now fixed, five standing.

## Install

```bash
git clone https://github.com/akankshjk5/Hybrid-AES-Custom-Cipher-Encryption-Model.git
cd Hybrid-AES-Custom-Cipher-Encryption-Model
pip install -e .
```

Requires Python 3.9+ and [`cryptography`](https://cryptography.io) 41+.

## Use

```python
from cipherx import CipherX

cipher = CipherX()
ct = cipher.encrypt("sensor=1;temp=23.5", "aes-passphrase", "structural-key")
pt = cipher.decrypt(ct, "aes-passphrase", "structural-key")
assert pt == "sensor=1;temp=23.5"
```

For anything real, use the hardened profile — it keeps the outer tag at its
full 256 bits instead of the paper's 64:

```python
from cipherx import CipherX, STRICT

cipher = CipherX(STRICT)
```

Failures are typed and fail closed — no partial plaintext is ever returned:

```python
from cipherx import CipherXError, IntegrityError, DecodingError

try:
    cipher.decrypt(tampered, passphrase, key)
except IntegrityError:
    ...   # wrong key, or the ciphertext was modified
except DecodingError:
    ...   # malformed input
```

### Command line

```bash
python -m cipherx selftest
python -m cipherx benchmark --sizes 12 1000 10000
python -m cipherx entropy --in ciphertext.txt

export CIPHERX_PASSPHRASE='...' CIPHERX_KEY='...'
python -m cipherx encrypt --text "secret" --stats
python -m cipherx encrypt --in message.txt --out cipher.txt
python -m cipherx decrypt --in cipher.txt
```

Secrets come from `CIPHERX_PASSPHRASE` / `CIPHERX_KEY` or a no-echo prompt —
never from flags, since argv is visible to every process and lands in shell
history.

## Reproducing the paper

```bash
python benchmarks/reproduce_paper.py
```

Measured on Python 3.12 against the published Table II:

| Input | Paper enc/dec/len | This implementation | Entropy |
|---:|---|---|---:|
| 12 | 556 / 525 / 136 | 568 / 423 / **158** | 5.19 |
| 71 | 496 / 497 / 256 | 410 / 422 / **278** | 5.24 |
| 37 | 428 / 466 / 190 | 453 / 465 / **212** | 5.22 |
| 44 | 447 / 480 / 202 | 448 / 437 / **224** | 5.24 |
| 1,000 | 470 / 462 / 2,158 | 410 / 414 / **2,180** | 5.24 |
| 10,000 | 584 / 499 / 20,536 | 438 / 444 / **20,558** | 5.24 |

Every ciphertext length is exactly **+22** characters: the 6-character
lossless length header that replaces the reference implementation's lossy
padding (D3), plus the 16-character per-message nonce (D6). Entropy averages
5.23 bits/char against the paper's 5.28, inside the published 5.23–5.33 band.

The paper's linear-time claim holds for the reason it gives: Scrypt accounts
for **92 %** of the clock, so encryption stays in a narrow band across an 833×
range of input sizes.

The benchmark pins the structural nonce so figures are stable. With fresh
nonces, a fixed 1,000-character plaintext produces ciphertexts of 2,078–2,414
characters, since the noise interval is drawn per message.

## What changed from the original implementation

The two scripts this replaces are preserved in [`legacy/`](legacy/). Five
deliberate differences, documented clause by clause in
[`docs/PAPER_MAPPING.md`](docs/PAPER_MAPPING.md):

**D1 — Stage order.** Algorithm 1 applies the Vigenère shift (line 8) before
segmentation (line 9); the original did it the other way round.

**D2 — Segmentation that segments.** Algorithm 1 splits into "word-like
segments" and treats odd and even ones differently. The original split on
**whitespace** — but its input is a Base-26 string, which has none. There was
always exactly one segment, always odd, so the even-index CSPRNG rotation
branch was unreachable and the rotational obfuscation of Section 5.5.I never
ran. Boundaries now come from a keyed CSPRNG: 200 characters yield ~28
segments instead of 1.

**D3 — Lossless padding.** The original padded with `'X'` and recovered with
`rstrip('X')`. `'X'` is a legal Base-26 character, so a genuine trailing `'X'`
was silently eaten and the message destroyed. Measured on the original:

| Structural key | Round-trip failures |
|---|---|
| `akanksh-super-unique-key` (its own default) | **0 %** |
| `my-secret-m-key` | 6.5 % |
| `demo-key-2025` | 10 % |
| `MMMM` | 69 % |

The shipped default masks it by coincidence: the Base-26 header always begins
`'A'`, the odd-index reversal moves it to the end, the nonlinear map sends it
to `'L'`, and turning `'L'` into `'X'` needs an `'M'` in the key — which that
key does not contain. Change the key and the corruption appears. Replaced with
an explicit length header; this is the only change to ciphertext length.

**D4 — Derived HMAC key.** The paper contradicts itself (Algorithm 1 line 24
says key with `Kc`; Section 5.2 says derive it). The original used raw
`Kc.encode()`, satisfying neither. Now `HKDF(Kc, "CIPHERX/v1/MAC")`, with the
version bound into the MAC input.

**D5 — Subquadratic Base-26.** The original peels digits with `divmod` in a
loop: O(d²), about 22,000 divisions on an 80,000-bit integer for the 10 kB
case. Replaced with recursive splitting that produces the **identical** digit
string — asserted against a transcription of the paper's own method.

**D6 — Per-message nonce.** Every CSPRNG stream was seeded from the structural
key alone, so each key induced one fixed transformation per message length.
About **90 %** of noise positions repeated across two messages under the same
key, letting an observer locate the noise, read off the interval, and strip
that stage with no key at all. A 16-character nonce (~75 bits) is now drawn
per message, prefixed to the ciphertext like an IV, authenticated by the outer
tag, and folded into all four streams — not just the noise one, since a fixed
segmentation and block permutation per `(key, length)` leaks the same way
under known plaintext. Noise agreement drops to **0.7 %**. This is the one
change that alters the wire format.

## Tests

```bash
pip install pytest
pytest                  # 166 tests
pytest -m "not slow"    # skip the full-Scrypt cases
```

Covers per-stage invertibility, the four regressions above, fuzzed round-trips
across six structural keys and fresh nonces, tamper detection on every
character position including the nonce, malformed-input handling, CSPRNG
determinism and bias, and the paper's own quantitative claims — including two
it gets wrong (`docs/SECURITY.md`, Findings 1 and 4).

## Layout

```
cipherx/
  params.py       profiles: PAPER, STRICT, FAST_TEST
  csprng.py       HKDF + HMAC-SHA256 deterministic CSPRNG
  mapping.py      nonlinear alphabet table
  base26.py       alphabet-only codec, subquadratic
  structural.py   the five reversible stages
  kdf.py          Scrypt and HKDF derivation
  aead.py         AES-256-GCM and wire packing
  hybrid.py       Algorithm 1 end to end
  analysis.py     entropy, IoC, chi-square, timing
  cli.py          python -m cipherx
docs/             PAPER_MAPPING.md, SECURITY.md
benchmarks/       reproduce_paper.py
legacy/           the original cipher1.py / cipher2.py
```

## Citing

```bibtex
@inproceedings{cipherx,
  title     = {Secure Hybrid AES + Custom Cipher Encryption},
  author    = {Akanksh J K and Badde, Sujal Sunil},
  booktitle = {Proc. IEEE Conference},
  address   = {NMAM Institute of Technology, Nitte},
  year      = {2025}
}
```

## License

MIT — see [LICENSE](LICENSE).
