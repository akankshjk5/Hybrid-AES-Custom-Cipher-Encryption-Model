# Security Notes

An honest account of what CipherX provides, what it does not, and what an
implementer should know before using it. Written to be useful to a reviewer,
not to flatter the design.

## Status

**Research artifact.** It implements a published academic construction and is
suitable for coursework, replication and study. It has had no third-party
cryptanalysis and no independent audit. For production confidentiality, use a
vetted AEAD — libsodium, `cryptography`'s `AESGCM`, or TLS — directly.

## What the layers actually do

| Layer | Provides | Does not provide |
|---|---|---|
| Scrypt (`N=2^16, r=8, p=2`) | Expensive offline guessing of weak passphrases | Protection against a leaked derived key |
| AES-256-GCM | Confidentiality and integrity of the payload | Length hiding, traffic-pattern hiding |
| Base-26 | Alphabet-restricted transport | Any confidentiality — it is a public encoding |
| Structural layer | Obfuscation against pattern and format inference | Cryptographic strength; it is keyed but unproven |
| Outer HMAC | Tamper detection on the transformed wire format | Replay protection across sessions |

**The security of CipherX is the security of AES-256-GCM under a Scrypt-derived
key.** The structural layer is defence in depth against traffic analysis. It
adds no provable confidentiality, and the paper (Section 1, "Out of Scope")
agrees: it offers no formal proof for that layer. Treat it as obfuscation.

---

## Findings

### Finding 1 — The noise layer repeats across messages (design limitation)

**Severity: moderate.** The noise pool ordering and the interval `gap` come
from `CSPRNG(Kc, "NOISE")`, which depends on the structural key alone — not on
any per-message value. Every message under one key therefore carries nearly
the same noise subsequence.

Measured over two encryptions of the same plaintext:

| Position class | Agreement |
|---|---|
| Payload (`A-Z`) positions | 4.9 % (chance is 3.8 %) |
| Noise positions | ~90 % |

The payload is well randomised; the noise is not. An adversary with two
ciphertexts under the same key can locate noise positions, read off `gap`, and
strip the stage without knowing any key — undoing one of the five obfuscation
layers for free. This partly contradicts the claim in Section 3.B that
repetition patterns are concealed.

*Remedy:* derive the noise schedule from a per-message nonce transmitted in the
clear alongside the ciphertext, e.g. `CSPRNG(Kc, "NOISE" || nonce)`. This
changes the ciphertext format, which the paper does not specify, so it is
documented rather than silently applied.

*Pinned by* `tests/test_paper_claims.py::TestReversibility::test_noise_layer_repeats_across_messages`

### Finding 2 — The `PAPER` profile truncates the outer tag to 64 bits

Section 4.6 specifies a 16-hex-character tag. 64 bits is below the 128-bit
norm: forging requires about 2^64 attempts, which is out of reach for a remote
attacker against an online oracle but is not a comfortable margin, and it
offers no post-quantum headroom.

The inner GCM tag is a full 128 bits and still guards the payload, so a forged
outer tag does not by itself yield a decryption — it gets an attacker past the
first check only.

*Remedy:* use the `STRICT` profile, which keeps the full 256-bit tag.

```python
from cipherx import CipherX, STRICT
cipher = CipherX(STRICT)
```

`PAPER` remains the default so the published tables reproduce.

### Finding 3 — "Alphabet-only ciphertext" is not literally true

The paper repeatedly claims alphabet-only output. The **Base-26 encoding** is
alphabet-only, but the noise stage then injects characters from
`0123456789@#$%&*`, so the final ciphertext spans roughly 42 symbols.

This matters for the stated use cases — SMS gateways, SCADA links, legacy
serial protocols. A channel that genuinely accepts only `A-Z` will reject
CipherX output as it stands.

There is no parameter that fixes this: `StructuralParams` rejects an empty
noise alphabet, and a noise alphabet drawn from `A-Z` would be unremovable,
since noise is identified precisely by being outside the payload alphabet.
Making the output truly alphabet-only requires either dropping the noise stage
in code or re-encoding the final string — both ciphertext-format changes.
Flagged as future work rather than quietly patched.

### Finding 4 — The entropy claim is arithmetically explained, not evidence of strength

The paper reports 5.23–5.33 bits/char against `log2(26) ≈ 4.70` and presents
the excess as evidence of obfuscation strength. The excess is simply the
widened alphabet: noise injection takes the symbol set from 26 to about 42,
lifting the ceiling to `log2(42) ≈ 5.39`.

Measured entropy sits at 97–98 % of the ceiling **for the alphabet actually
used**, which is the correct and still-favourable statement: the output is
close to uniform over its own symbol set. Comparing it against `log2(26)` is
not meaningful.

High entropy is in any case a necessary, not sufficient, condition —
ciphertext from a broken cipher can look perfectly uniform.

*Pinned by* `tests/test_paper_claims.py::TestEntropy::test_excess_over_log2_26_is_explained_by_alphabet_width`

### Finding 5 — No replay protection

Nothing binds a ciphertext to a session, sequence number or timestamp. An
adversary can re-send a captured ciphertext and it will decrypt successfully.
Section 5.5.K claims protection against replay; the construction does not
provide it. Callers needing it must add a counter or timestamp inside the
plaintext and check it after decryption.

### Finding 6 — Length is not hidden

Ciphertext length is a near-affine function of plaintext length (expansion ~2×
for inputs past 1 kB). Message size, and therefore a good deal of traffic
structure, remains visible. The paper's metadata-leakage motivation is only
partly addressed: content patterns are obscured, size is not. Pad before
encrypting if size matters.

---

## Properties that do hold

Verified by the test suite:

- **Reversibility.** Round-trips cleanly across empty strings, Unicode,
  repetitive telemetry, payloads ending in `'X'`, and multi-kilobyte inputs,
  across six structural keys chosen to span the reference implementation's
  failure modes.
- **Tamper detection.** Every single-character modification of a ciphertext is
  rejected, as is every truncation and append tested.
- **Constant-time tag comparison.** `hmac.compare_digest`, so the outer check
  is not a byte-at-a-time forgery oracle.
- **Semantic security against repetition.** A fresh salt and nonce per call
  mean identical plaintexts produce unrelated payload bytes (Finding 1 covers
  the noise positions).
- **Unbiased CSPRNG draws.** `randint` uses rejection sampling, so rotations,
  intervals and permutations carry no modulo bias.
- **Fail-closed decryption.** The outer tag is verified *before* any structural
  inversion runs, so attacker-chosen input never reaches the inverse
  transforms. All failures raise typed exceptions; no partial plaintext is
  ever returned.

## Operational guidance

- **Never reuse a `(passphrase, salt)` pair, and never pin `salt=` or `nonce=`
  outside tests.** The parameters exist for reproducible test vectors. GCM
  fails catastrophically on nonce reuse: two messages under one key and nonce
  leak their XOR and expose the GHASH authentication key.
- **Keep the two keys independent.** The AES passphrase and the structural key
  protect different layers; deriving one from the other collapses them.
- **Scrypt costs ~64 MB per derivation.** That is the point, but it rules out
  small microcontrollers and makes the KDF a denial-of-service lever on a
  server that derives per request. Cache derived keys where the threat model
  allows.
- **Maximum payload is 456,975 bytes** (`26^4 - 1`), fixed by the 4-letter
  Base-26 length header. Larger inputs raise `PayloadTooLargeError`.
- **Secrets are not accepted as CLI flags** — argv is world-readable and lands
  in shell history. Use `CIPHERX_PASSPHRASE` / `CIPHERX_KEY`, or the no-echo
  prompt.

## Reporting

This is academic work. Open an issue for anything found; there is no embargo
process and no production deployment to coordinate with.
