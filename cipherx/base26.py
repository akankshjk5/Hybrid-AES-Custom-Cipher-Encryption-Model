"""Reversible Base-26 alphabet-only codec (paper Sections 4.3 and 5.5).

AES-GCM emits binary. Channels like SMS gateways, SCADA links and text-only log
pipelines do not carry binary. The paper's answer is to read the whole packed
blob as one big integer and rewrite it in base 26 over ``A-Z``, prefixed by a
four-letter header holding the original byte length::

    header = 4 Base-26 digits  (big-endian) = len(data)
    body   = minimal Base-26 expansion of int.from_bytes(data, "big")

The header is what makes decoding exact: leading zero bytes vanish inside the
integer, and only the recorded length can restore them.

Performance note
----------------
The reference implementation peels digits off with ``divmod(n, 26)`` in a loop.
That is O(d) big-integer divisions on a shrinking d-digit number, i.e. O(d^2)
word operations -- about 22,000 divisions against an 80,000-bit integer for the
paper's 10 kB test case.

This module keeps the *identical* digit string but produces it by recursive
splitting at ``26 ** (d // 2)``, which is O(d^1.58)-ish with Python's
subquadratic big-integer arithmetic and measurably faster past a few hundred
bytes. The output is byte-for-byte what the naive loop produces, so paper
fidelity is exact; see ``tests/test_base26.py`` which asserts that equivalence
directly against a reference implementation.
"""

from __future__ import annotations

from typing import Dict, List

from .exceptions import DecodingError, PayloadTooLargeError

__all__ = [
    "ALPHABET",
    "HEADER_LEN",
    "MAX_PAYLOAD_BYTES",
    "encode",
    "decode",
]

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
BASE = 26
HEADER_LEN = 4

#: Hard ceiling imposed by the 4-digit length header: ``26**4 - 1``.
MAX_PAYLOAD_BYTES = BASE ** HEADER_LEN - 1

# Cache of BASE ** k, shared across calls; base conversion hits the same
# exponents repeatedly.
_POW_CACHE: Dict[int, int] = {0: 1, 1: BASE}

# Below this digit count the recursion costs more than it saves.
_SPLIT_THRESHOLD = 48


def _pow(k: int) -> int:
    cached = _POW_CACHE.get(k)
    if cached is None:
        cached = BASE ** k
        _POW_CACHE[k] = cached
    return cached


def _digit_count(n: int) -> int:
    """Number of Base-26 digits in ``n``; 0 for ``n == 0``.

    Seeds from the bit length (``log2(26) ~ 4.7``) then corrects, so there is
    no floating-point rounding risk at the boundaries.
    """
    if n == 0:
        return 0
    d = max(1, (n.bit_length() * 100) // 470)
    while _pow(d) <= n:
        d += 1
    while d > 1 and _pow(d - 1) > n:
        d -= 1
    return d


def _to_digits(n: int, width: int) -> List[int]:
    """Expand ``n`` into exactly ``width`` Base-26 digits, most significant first."""
    if width <= 0:
        return []
    if width == 1:
        return [n]
    if width <= _SPLIT_THRESHOLD:
        out = [0] * width
        for i in range(width - 1, -1, -1):
            n, out[i] = divmod(n, BASE)
        return out
    low = width // 2
    high, rest = divmod(n, _pow(low))
    return _to_digits(high, width - low) + _to_digits(rest, low)


def _from_digits(digits: List[int]) -> int:
    """Recombine Base-26 digits into an integer."""
    width = len(digits)
    if width == 0:
        return 0
    if width == 1:
        return digits[0]
    if width <= _SPLIT_THRESHOLD:
        n = 0
        for d in digits:
            n = n * BASE + d
        return n
    low = width // 2
    return _from_digits(digits[:width - low]) * _pow(low) + _from_digits(digits[width - low:])


def encode(data: bytes) -> str:
    """Encode ``data`` as a 4-letter length header followed by its Base-26 body.

    >>> encode(b"")
    'AAAA'
    >>> decode(encode(b"\\x00\\x01\\xff")) == b"\\x00\\x01\\xff"
    True

    Raises:
        PayloadTooLargeError: if ``len(data) > MAX_PAYLOAD_BYTES``.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes")
    length = len(data)
    if length > MAX_PAYLOAD_BYTES:
        raise PayloadTooLargeError(
            f"{length} bytes exceeds the {MAX_PAYLOAD_BYTES}-byte ceiling of a "
            f"{HEADER_LEN}-digit Base-26 length header"
        )

    header = "".join(ALPHABET[d] for d in _to_digits(length, HEADER_LEN))
    n = int.from_bytes(data, "big")
    body = "".join(ALPHABET[d] for d in _to_digits(n, _digit_count(n)))
    return header + body


def decode(text: str) -> bytes:
    """Inverse of :func:`encode`.

    Raises:
        DecodingError: on a short, non-alphabetic, or internally inconsistent
            encoding.
    """
    if len(text) < HEADER_LEN:
        raise DecodingError(
            f"encoded text is {len(text)} characters, shorter than the "
            f"{HEADER_LEN}-character length header"
        )

    digits: List[int] = []
    for i, ch in enumerate(text):
        d = ord(ch) - 65
        if d < 0 or d >= BASE:
            raise DecodingError(f"non-alphabetic character {ch!r} at offset {i}")
        digits.append(d)

    length = _from_digits(digits[:HEADER_LEN])
    n = _from_digits(digits[HEADER_LEN:])

    try:
        return n.to_bytes(length, "big")
    except OverflowError as exc:
        # The body encodes a larger integer than the header claims room for:
        # corruption, truncation, or a header/body mismatch.
        raise DecodingError(
            f"Base-26 body does not fit the {length}-byte length recorded in the header"
        ) from exc
