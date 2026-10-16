"""The reversible structural-obfuscation layer (paper Section 5.6, Algorithm 1).

Five stages, applied in the order Algorithm 1 gives them::

    S26 --[1 nonlinear map]--> S1 --[2 Vigenere]--> S2
        --[3 segment reverse/rotate]--> S3
        --[4 noise insertion]--> S4
        --[5 block permutation]--> S5

Every stage is a bijection on strings, and every "random" choice comes from a
:class:`~cipherx.csprng.KeyedCSPRNG` seeded by the structural key, a context
label, and a per-message nonce. Decryption redraws the same choices and runs
the inverses in reverse order. No stage consults the plaintext to decide
anything, which is what keeps the whole layer invertible.

All generator access goes through :class:`StructuralContext`, so no stage can
accidentally be seeded without the nonce.

Four deliberate corrections to the reference implementation
------------------------------------------------------------
1. **Stage order.** Algorithm 1 puts the Vigenere shift (line 8) *before*
   segmentation (line 9). The reference code ran the segment transform first
   and the Vigenere afterwards. Fixed here.

2. **Segmentation that actually segments.** Algorithm 1 line 9 says "split into
   word-like segments", and lines 10-18 then treat odd and even segments
   differently. The reference code split on whitespace -- but its input is a
   Base-26 string, which has no whitespace, so there was always exactly one
   segment, always odd, and the even-index CSPRNG rotation branch (lines 14-16)
   was unreachable. One of the paper's named contributions never ran. Segment
   boundaries are now drawn from the ``b"SEGMENT"`` CSPRNG stream.

3. **Lossless block padding.** The reference padded to a block multiple with
   ``'X'`` and recovered by ``rstrip('X')``. ``'X'`` is a legal Base-26
   character, so any genuine trailing ``'X'`` was eaten and the message was
   silently destroyed. Measured failure rates on random payloads: 0% with the
   shipped demo key but 6.5% with ``"my-secret-m-key"``, 10% with
   ``"demo-key-2025"``, 69% with ``"MMMM"``. Replaced with an explicit Base-26
   length header (one block wide at the paper's ``blk = 6``).

4. **Per-message nonce.** Every generator previously depended on the structural
   key alone, so each key induced one fixed transformation per message length.
   The visible consequence was that roughly 90% of noise positions repeated
   across messages, letting an observer with two ciphertexts locate the noise
   and strip the stage without any key. See :data:`NONCE_LEN` and
   ``docs/SECURITY.md`` Finding 1.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from typing import List

from .csprng import KeyedCSPRNG
from .exceptions import DecodingError, ParameterError
from .mapping import forward_map, inverse_map
from .params import StructuralParams

__all__ = [
    "CTX_SEGMENT",
    "CTX_WORDS",
    "CTX_NOISE",
    "CTX_BLOCKS",
    "LENGTH_HEADER_LEN",
    "NONCE_LEN",
    "NONCE_BITS",
    "StructuralContext",
    "generate_nonce",
    "validate_nonce",
    "vigenere",
    "segment_lengths",
    "transform_segments",
    "invert_segments",
    "insert_noise",
    "remove_noise",
    "block_shuffle",
    "block_unshuffle",
    "apply_structural",
    "invert_structural",
]

# Domain-separation labels for the CSPRNG streams (paper Section 4.4).
CTX_SEGMENT = b"SEGMENT"
CTX_WORDS = b"WORDS"
CTX_NOISE = b"NOISE"
CTX_BLOCKS = b"BLOCKS"

#: Base-26 digits prepended before block padding to record the exact
#: pre-padding length. Six digits span 308,915,775 characters, far beyond the
#: 456,975-byte ceiling of the payload codec, and it is exactly one block at
#: the paper's ``blk = 6``.
LENGTH_HEADER_LEN = 6

#: Characters in the per-message structural nonce. Sixteen uniform ``A-Z``
#: draws carry ``log2(26**16)`` bits; the birthday bound puts a repeat at
#: roughly 2**37 messages under one key, and a repeat merely restores the old
#: behaviour for that one pair rather than breaking anything.
NONCE_LEN = 16
NONCE_BITS = 75.2  # log2(26 ** 16), for documentation

_A = ord("A")
_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Largest multiple of 26 below 256; bytes at or above it are rejected so the
# nonce is drawn without modulo bias.
_UNBIASED_LIMIT = 234


def generate_nonce() -> str:
    """Return a fresh ``NONCE_LEN``-character structural nonce.

    Drawn from :func:`os.urandom` with rejection sampling, so every character
    is uniform over ``A-Z``. The nonce is public -- it travels in the clear at
    the head of the ciphertext, exactly like an IV -- and is authenticated by
    the outer HMAC.
    """
    out: List[str] = []
    while len(out) < NONCE_LEN:
        for b in os.urandom(NONCE_LEN * 2):
            if b < _UNBIASED_LIMIT:
                out.append(_ALPHABET[b % 26])
                if len(out) == NONCE_LEN:
                    break
    return "".join(out)


def validate_nonce(nonce: str) -> str:
    """Check a nonce is exactly ``NONCE_LEN`` uppercase letters; return it."""
    if len(nonce) != NONCE_LEN:
        raise ParameterError(
            f"structural nonce must be exactly {NONCE_LEN} characters, got {len(nonce)}"
        )
    if not all("A" <= c <= "Z" for c in nonce):
        raise ParameterError("structural nonce must contain only A-Z")
    return nonce


@dataclass(frozen=True)
class StructuralContext:
    """Everything the structural stages need, bundled so nothing can be dropped.

    Holding the key, the per-message nonce and the parameters together means
    every generator in the layer is reached through :meth:`rng` or
    :meth:`segment_rng`, and both fold in the nonce. A stage cannot be seeded
    from the key alone by accident -- which is exactly the defect this type
    exists to prevent.
    """

    key: str
    nonce: str
    params: StructuralParams

    def __post_init__(self) -> None:
        validate_nonce(self.nonce)

    @property
    def key_bytes(self) -> bytes:
        return self.key.encode("utf-8")

    def _info(self, label: bytes) -> bytes:
        """HKDF ``info``: ``label || "/" || nonce``.

        The separator keeps labels unambiguous. Without it, a fixed-length
        nonce already makes collisions impossible, but the separator means the
        property does not silently depend on that.
        """
        return label + b"/" + self.nonce.encode("ascii")

    def rng(self, label: bytes) -> KeyedCSPRNG:
        """A generator for one stage, domain-separated by label and nonce."""
        return KeyedCSPRNG(self.key_bytes, self._info(label))

    def segment_rng(self, index: int) -> KeyedCSPRNG:
        """Per-segment generator, matching ``CSPRNG(Kc, "WORDS", i)``."""
        return KeyedCSPRNG(
            self.key_bytes + struct.pack(">I", index), self._info(CTX_WORDS)
        )


# ----------------------------------------------------------------------
# Stage 2 -- enhanced Vigenere shifting (paper Section 5.6.2)
# ----------------------------------------------------------------------

def vigenere(text: str, key: str, *, encrypt: bool) -> str:
    """Poly-alphabetic shift over ``A-Z``, leaving other characters untouched.

    The key index advances only on alphabetic characters, so inserting or
    removing non-letters elsewhere in the pipeline cannot desynchronise it.

    This stage takes the key directly rather than a context: it is a pure
    keyed substitution with no generator, so there is nothing for a nonce to
    randomise. Per-message variation enters at the stages that follow.
    """
    letters = [c for c in key.upper() if "A" <= c <= "Z"]
    if not letters:
        return text
    width = len(letters)
    shifts = [ord(c) - _A for c in letters]

    out = []
    append = out.append
    ki = 0
    for ch in text:
        if "A" <= ch <= "Z":
            k = shifts[ki % width]
            delta = k if encrypt else -k
            append(chr(_A + (ord(ch) - _A + delta) % 26))
            ki += 1
        else:
            append(ch)
    return "".join(out)


# ----------------------------------------------------------------------
# Stage 3 -- keyed segmentation, reversal and rotation (Algorithm 1, 9-18)
# ----------------------------------------------------------------------

def segment_lengths(total: int, ctx: StructuralContext) -> List[int]:
    """Draw the segment partition of a ``total``-character string.

    Depends only on ``(key, nonce, total)``, all available at decryption time,
    so the identical partition is reproduced there.
    """
    if total <= 0:
        return []
    rng = ctx.rng(CTX_SEGMENT)
    lengths: List[int] = []
    remaining = total
    while remaining > 0:
        take = rng.randint(ctx.params.segment_min, ctx.params.segment_max)
        if take > remaining:
            take = remaining
        lengths.append(take)
        remaining -= take
    return lengths


def _rotate_right(s: str, k: int) -> str:
    if not s:
        return s
    k %= len(s)
    return s[-k:] + s[:-k] if k else s


def _rotate_left(s: str, k: int) -> str:
    if not s:
        return s
    k %= len(s)
    return s[k:] + s[:k] if k else s


def transform_segments(text: str, ctx: StructuralContext) -> str:
    """Reverse odd-indexed segments, rotate even-indexed ones (1-based)."""
    pieces: List[str] = []
    offset = 0
    for i, length in enumerate(segment_lengths(len(text), ctx), start=1):
        chunk = text[offset:offset + length]
        offset += length
        if i % 2 == 1:
            pieces.append(chunk[::-1])
        else:
            r = ctx.segment_rng(i).randint(1, max(1, len(chunk)))
            pieces.append(_rotate_right(chunk, r))
    return "".join(pieces)


def invert_segments(text: str, ctx: StructuralContext) -> str:
    """Exact inverse of :func:`transform_segments`."""
    pieces: List[str] = []
    offset = 0
    for i, length in enumerate(segment_lengths(len(text), ctx), start=1):
        chunk = text[offset:offset + length]
        offset += length
        if i % 2 == 1:
            pieces.append(chunk[::-1])
        else:
            r = ctx.segment_rng(i).randint(1, max(1, len(chunk)))
            pieces.append(_rotate_left(chunk, r))
    return "".join(pieces)


# ----------------------------------------------------------------------
# Stage 4 -- deterministic noise insertion (paper Section 5.6.4)
# ----------------------------------------------------------------------

def _noise_schedule(ctx: StructuralContext):
    """Return ``(pool, gap)`` -- identical on the encrypt and decrypt sides.

    Both depend on the per-message nonce, so two messages under one key get
    unrelated noise. Before that fix roughly 90% of noise positions matched
    across messages, which let an observer identify and strip the stage.
    """
    rng = ctx.rng(CTX_NOISE)
    pool = rng.sequence(list(ctx.params.noise_alphabet))
    gap = rng.randint(ctx.params.noise_gap_min, ctx.params.noise_gap_max)
    return pool, gap


def insert_noise(text: str, ctx: StructuralContext) -> str:
    """Insert one noise character after every ``gap``-th alphabetic character.

    Noise is drawn from a pool disjoint from ``A-Z``, so removal is exact: a
    character is noise precisely when the running letter count before it is a
    nonzero multiple of ``gap``.
    """
    pool, gap = _noise_schedule(ctx)
    width = len(pool)
    out: List[str] = []
    append = out.append
    letters = 0
    noise_i = 0
    for ch in text:
        append(ch)
        if "A" <= ch <= "Z":
            letters += 1
            if letters % gap == 0:
                append(pool[noise_i % width])
                noise_i += 1
    return "".join(out)


def remove_noise(text: str, ctx: StructuralContext) -> str:
    """Exact inverse of :func:`insert_noise`.

    Raises:
        DecodingError: if a position that must hold a noise character holds a
            letter instead, which means the stream is corrupt.
    """
    pool, gap = _noise_schedule(ctx)
    noise_set = set(pool)
    out: List[str] = []
    append = out.append
    letters = 0
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        append(ch)
        i += 1
        if "A" <= ch <= "Z":
            letters += 1
            if letters % gap == 0 and i < n:
                if text[i] not in noise_set:
                    raise DecodingError(
                        f"expected a noise character at offset {i}, found {text[i]!r}"
                    )
                i += 1
    return "".join(out)


# ----------------------------------------------------------------------
# Stage 5 -- block permutation with a lossless length header
# ----------------------------------------------------------------------

def _encode_length(value: int) -> str:
    digits = [0] * LENGTH_HEADER_LEN
    for i in range(LENGTH_HEADER_LEN - 1, -1, -1):
        value, digits[i] = divmod(value, 26)
    if value:
        raise DecodingError("string too long for the block length header")
    return "".join(chr(_A + d) for d in digits)


def _decode_length(text: str) -> int:
    value = 0
    for i, ch in enumerate(text):
        d = ord(ch) - _A
        if d < 0 or d >= 26:
            raise DecodingError(f"corrupt block length header at offset {i}")
        value = value * 26 + d
    return value


def block_shuffle(text: str, ctx: StructuralContext) -> str:
    """Prepend an exact length header, pad to a block multiple, permute blocks."""
    size = ctx.params.block_size
    payload = _encode_length(len(text)) + text
    pad = (-len(payload)) % size
    payload += "X" * pad

    blocks = [payload[i:i + size] for i in range(0, len(payload), size)]
    order = ctx.rng(CTX_BLOCKS).permutation(len(blocks))
    return "".join(blocks[i] for i in order)


def block_unshuffle(text: str, ctx: StructuralContext) -> str:
    """Exact inverse of :func:`block_shuffle`.

    Truncates to the recorded length rather than stripping padding characters,
    which is what makes a payload ending in ``'X'`` survive.
    """
    size = ctx.params.block_size
    if len(text) % size:
        raise DecodingError(
            f"ciphertext body length {len(text)} is not a multiple of block size {size}"
        )

    blocks = [text[i:i + size] for i in range(0, len(text), size)]
    order = ctx.rng(CTX_BLOCKS).permutation(len(blocks))

    restored: List[str] = [""] * len(blocks)
    for position, source in enumerate(order):
        restored[source] = blocks[position]
    joined = "".join(restored)

    if len(joined) < LENGTH_HEADER_LEN:
        raise DecodingError("ciphertext body is shorter than the block length header")
    length = _decode_length(joined[:LENGTH_HEADER_LEN])
    body = joined[LENGTH_HEADER_LEN:]
    if length > len(body):
        raise DecodingError(
            f"block length header claims {length} characters but only {len(body)} are present"
        )
    return body[:length]


# ----------------------------------------------------------------------
# Full layer
# ----------------------------------------------------------------------

def apply_structural(text: str, ctx: StructuralContext) -> str:
    """Run stages 1-5 in Algorithm 1 order over an ``A-Z`` input."""
    stage = forward_map(text, ctx.params.shift_pattern)
    stage = vigenere(stage, ctx.key, encrypt=True)
    stage = transform_segments(stage, ctx)
    stage = insert_noise(stage, ctx)
    return block_shuffle(stage, ctx)


def invert_structural(text: str, ctx: StructuralContext) -> str:
    """Run the inverses of stages 5-1, recovering the original ``A-Z`` input."""
    stage = block_unshuffle(text, ctx)
    stage = remove_noise(stage, ctx)
    stage = invert_segments(stage, ctx)
    stage = vigenere(stage, ctx.key, encrypt=False)
    return inverse_map(stage, ctx.params.shift_pattern)
