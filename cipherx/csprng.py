"""Deterministic keyed CSPRNG (paper Section 4.4).

Reversibility of the whole structural layer rests on this one object: every
"random" decision made during encryption -- segment boundaries, rotation
offsets, noise spacing, block permutations -- is redrawn bit-identically during
decryption. That only works if the generator is a pure function of
``(key_material, context)``.

Construction, unchanged from the paper::

    PRK = HKDF-SHA256(key_material, salt=None, info=context, L=32)
    out = HMAC-SHA256(PRK, be64(1)) || HMAC-SHA256(PRK, be64(2)) || ...

``context`` provides domain separation, so the ``b"NOISE"``, ``b"BLOCKS"``,
``b"WORDS"`` and ``b"SEGMENT"`` streams are independent even though they are
all derived from the same structural key.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from typing import List, MutableSequence, Sequence, TypeVar

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .exceptions import ParameterError

__all__ = ["KeyedCSPRNG"]

T = TypeVar("T")

_BLOCK = 32          # HMAC-SHA256 output width
_REFILL_MIN = 64     # never ask for less than two blocks at a time
_WORD = 8            # bytes consumed per randint draw
_WORD_SPACE = 1 << (8 * _WORD)


class KeyedCSPRNG:
    """A deterministic, domain-separated stream of pseudorandom bytes.

    Two instances built with equal ``key_material`` and ``context`` emit
    identical sequences; that is the entire basis of decryption.

    >>> a = KeyedCSPRNG(b"k", b"NOISE")
    >>> b = KeyedCSPRNG(b"k", b"NOISE")
    >>> a.bytes(16) == b.bytes(16)
    True
    >>> KeyedCSPRNG(b"k", b"BLOCKS").bytes(16) == a.bytes(16)
    False
    """

    __slots__ = ("_key", "_counter", "_buf", "_pos")

    def __init__(self, key_material: bytes, context: bytes = b"") -> None:
        if not isinstance(key_material, (bytes, bytearray)):
            raise ParameterError("key_material must be bytes")
        self._key = HKDF(
            algorithm=hashes.SHA256(),
            length=_BLOCK,
            salt=None,
            info=context,
        ).derive(bytes(key_material))
        self._counter = 0
        self._buf = b""
        self._pos = 0

    # ------------------------------------------------------------------
    # byte stream
    # ------------------------------------------------------------------

    def _refill(self, need: int) -> None:
        """Extend the buffer with whole HMAC blocks until it covers ``need``.

        Any unread tail is carried forward, so a caller that reads in small
        irregular chunks sees exactly the same byte stream as one that reads it
        all at once.
        """
        chunks: List[bytes] = [self._buf[self._pos:]]
        have = len(chunks[0])
        while have < need:
            self._counter += 1
            chunks.append(
                hmac.new(self._key, struct.pack(">Q", self._counter), hashlib.sha256).digest()
            )
            have += _BLOCK
        self._buf = b"".join(chunks)
        self._pos = 0

    def bytes(self, n: int) -> bytes:
        """Return the next ``n`` pseudorandom bytes."""
        if n < 0:
            raise ParameterError("n must be non-negative")
        if n == 0:
            return b""
        if self._pos + n > len(self._buf):
            self._refill(max(n, _REFILL_MIN))
        out = self._buf[self._pos:self._pos + n]
        self._pos += n
        return out

    # ------------------------------------------------------------------
    # derived draws
    # ------------------------------------------------------------------

    def randint(self, a: int, b: int) -> int:
        """Uniform integer in ``[a, b]``, inclusive.

        Uses rejection sampling against the largest multiple of ``span`` that
        fits in 64 bits, so the result carries no modulo bias. Unbiasedness
        matters here: a skewed permutation or noise interval would itself be a
        structural fingerprint, which is precisely what this layer exists to
        remove.
        """
        if a > b:
            raise ParameterError(f"empty range [{a}, {b}]")
        span = b - a + 1
        if span == 1:
            return a
        limit = _WORD_SPACE // span * span
        while True:
            r = int.from_bytes(self.bytes(_WORD), "big")
            if r < limit:
                return a + (r % span)

    def shuffle(self, items: MutableSequence[T]) -> None:
        """Fisher-Yates shuffle, in place."""
        for i in range(len(items) - 1, 0, -1):
            j = self.randint(0, i)
            items[i], items[j] = items[j], items[i]

    def permutation(self, n: int) -> List[int]:
        """Return a shuffled ``[0, n)``.

        Read it as: ``perm[i]`` is the source index that lands at output
        position ``i``.
        """
        idx = list(range(n))
        self.shuffle(idx)
        return idx

    def sequence(self, items: Sequence[T]) -> List[T]:
        """Return a shuffled copy of ``items``."""
        out = list(items)
        self.shuffle(out)
        return out
