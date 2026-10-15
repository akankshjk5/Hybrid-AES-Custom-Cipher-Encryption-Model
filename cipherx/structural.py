"""The reversible structural-obfuscation layer (paper Section 5.6, Algorithm 1).

Five stages, applied in the order Algorithm 1 gives them::

    S26 --[1 nonlinear map]--> S1 --[2 Vigenere]--> S2
        --[3 segment reverse/rotate]--> S3
        --[4 noise insertion]--> S4
        --[5 block permutation]--> S5

Every stage is a bijection on strings, and every "random" choice comes from a
:class:`~cipherx.csprng.KeyedCSPRNG` seeded only by the structural key and a
context label. Decryption therefore redraws the same choices and runs the
inverses in reverse order. No stage consults the plaintext to decide anything,
which is what keeps the whole layer invertible.

Three deliberate corrections to the reference implementation
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
   boundaries are now drawn from the ``b"SEGMENT"`` CSPRNG stream, so the odd
   and even branches both execute. Lengths depend only on the key and the total
   length -- both known at decryption -- so this stays reversible.

3. **Lossless block padding.** The reference padded to a block multiple with
   ``'X'`` and recovered by ``rstrip('X')``. ``'X'`` is a legal Base-26
   character, so any genuine trailing ``'X'`` was eaten and the message was
   silently destroyed. Measured failure rates on random payloads: 0% with the
   shipped demo key but 6.5% with ``"my-secret-m-key"``, 10% with
   ``"demo-key-2025"``, 69% with ``"MMMM"`` -- the default key masks the bug
   because it happens to contain no letter that maps a trailing ``'L'`` onto
   ``'X'``. Replaced with an explicit Base-26 length header (one block wide at
   the paper's ``blk = 6``) prepended before padding, so the exact length is
   recovered instead of guessed. See ``tests/test_structural.py``.
"""

from __future__ import annotations

import struct
from typing import List, Sequence

from .csprng import KeyedCSPRNG
from .exceptions import DecodingError
from .mapping import forward_map, inverse_map
from .params import StructuralParams

__all__ = [
    "CTX_SEGMENT",
    "CTX_WORDS",
    "CTX_NOISE",
    "CTX_BLOCKS",
    "LENGTH_HEADER_LEN",
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

_A = ord("A")


# ----------------------------------------------------------------------
# Stage 2 -- enhanced Vigenere shifting (paper Section 5.6.2)
# ----------------------------------------------------------------------

def vigenere(text: str, key: str, *, encrypt: bool) -> str:
    """Poly-alphabetic shift over ``A-Z``, leaving other characters untouched.

    The key index advances only on alphabetic characters, so inserting or
    removing non-letters elsewhere in the pipeline cannot desynchronise it.
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

def segment_lengths(total: int, key_bytes: bytes, params: StructuralParams) -> List[int]:
    """Draw the segment partition of a ``total``-character string.

    Depends only on ``(key, total)``, both available at decryption time, so the
    identical partition is reproduced there.
    """
    if total <= 0:
        return []
    rng = KeyedCSPRNG(key_bytes, CTX_SEGMENT)
    lengths: List[int] = []
    remaining = total
    while remaining > 0:
        take = rng.randint(params.segment_min, params.segment_max)
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


def _segment_rng(key_bytes: bytes, index: int) -> KeyedCSPRNG:
    """Per-segment generator, matching ``CSPRNG(Kc, "WORDS", i)``."""
    return KeyedCSPRNG(key_bytes + struct.pack(">I", index), CTX_WORDS)


def transform_segments(text: str, key_bytes: bytes, params: StructuralParams) -> str:
    """Reverse odd-indexed segments, rotate even-indexed ones (1-based)."""
    pieces: List[str] = []
    offset = 0
    for i, length in enumerate(segment_lengths(len(text), key_bytes, params), start=1):
        chunk = text[offset:offset + length]
        offset += length
        if i % 2 == 1:
            pieces.append(chunk[::-1])
        else:
            r = _segment_rng(key_bytes, i).randint(1, max(1, len(chunk)))
            pieces.append(_rotate_right(chunk, r))
    return "".join(pieces)


def invert_segments(text: str, key_bytes: bytes, params: StructuralParams) -> str:
    """Exact inverse of :func:`transform_segments`."""
    pieces: List[str] = []
    offset = 0
    for i, length in enumerate(segment_lengths(len(text), key_bytes, params), start=1):
        chunk = text[offset:offset + length]
        offset += length
        if i % 2 == 1:
            pieces.append(chunk[::-1])
        else:
            r = _segment_rng(key_bytes, i).randint(1, max(1, len(chunk)))
            pieces.append(_rotate_left(chunk, r))
    return "".join(pieces)


# ----------------------------------------------------------------------
# Stage 4 -- deterministic noise insertion (paper Section 5.6.4)
# ----------------------------------------------------------------------

def _noise_schedule(key_bytes: bytes, params: StructuralParams):
    """Return ``(pool, gap)`` -- identical on the encrypt and decrypt sides."""
    rng = KeyedCSPRNG(key_bytes, CTX_NOISE)
    pool = rng.sequence(list(params.noise_alphabet))
    gap = rng.randint(params.noise_gap_min, params.noise_gap_max)
    return pool, gap


def insert_noise(text: str, key_bytes: bytes, params: StructuralParams) -> str:
    """Insert one noise character after every ``gap``-th alphabetic character.

    Noise is drawn from a pool disjoint from ``A-Z``, so removal is exact: a
    character is noise precisely when the running letter count before it is a
    nonzero multiple of ``gap``.
    """
    pool, gap = _noise_schedule(key_bytes, params)
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


def remove_noise(text: str, key_bytes: bytes, params: StructuralParams) -> str:
    """Exact inverse of :func:`insert_noise`.

    Raises:
        DecodingError: if a position that must hold a noise character holds a
            letter instead, which means the stream is corrupt.
    """
    pool, gap = _noise_schedule(key_bytes, params)
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


def block_shuffle(text: str, key_bytes: bytes, params: StructuralParams) -> str:
    """Prepend an exact length header, pad to a block multiple, permute blocks."""
    size = params.block_size
    payload = _encode_length(len(text)) + text
    pad = (-len(payload)) % size
    payload += "X" * pad

    blocks = [payload[i:i + size] for i in range(0, len(payload), size)]
    rng = KeyedCSPRNG(key_bytes, CTX_BLOCKS)
    order = rng.permutation(len(blocks))
    return "".join(blocks[i] for i in order)


def block_unshuffle(text: str, key_bytes: bytes, params: StructuralParams) -> str:
    """Exact inverse of :func:`block_shuffle`.

    Truncates to the recorded length rather than stripping padding characters,
    which is what makes a payload ending in ``'X'`` survive.
    """
    size = params.block_size
    if len(text) % size:
        raise DecodingError(
            f"ciphertext body length {len(text)} is not a multiple of block size {size}"
        )

    blocks = [text[i:i + size] for i in range(0, len(text), size)]
    rng = KeyedCSPRNG(key_bytes, CTX_BLOCKS)
    order = rng.permutation(len(blocks))

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

def apply_structural(text: str, key: str, params: StructuralParams) -> str:
    """Run stages 1-5 in Algorithm 1 order over an ``A-Z`` input."""
    key_bytes = key.encode("utf-8")
    stage = forward_map(text, params.shift_pattern)
    stage = vigenere(stage, key, encrypt=True)
    stage = transform_segments(stage, key_bytes, params)
    stage = insert_noise(stage, key_bytes, params)
    return block_shuffle(stage, key_bytes, params)


def invert_structural(text: str, key: str, params: StructuralParams) -> str:
    """Run the inverses of stages 5-1, recovering the original ``A-Z`` input."""
    key_bytes = key.encode("utf-8")
    stage = block_unshuffle(text, key_bytes, params)
    stage = remove_noise(stage, key_bytes, params)
    stage = invert_segments(stage, key_bytes, params)
    stage = vigenere(stage, key, encrypt=False)
    return inverse_map(stage, params.shift_pattern)
