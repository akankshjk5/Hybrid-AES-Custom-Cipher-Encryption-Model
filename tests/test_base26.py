"""Base-26 codec: round-trip, framing, and equivalence with the paper's method."""

from __future__ import annotations

import pytest

from cipherx import base26
from cipherx.exceptions import DecodingError, PayloadTooLargeError

from .conftest import random_bytes


def naive_encode(data: bytes) -> str:
    """The paper's literal method: a 4-digit header, then repeated ``divmod``.

    Kept as the reference oracle. :mod:`cipherx.base26` replaces the O(d^2)
    digit loop with recursive splitting; this function is what proves the
    optimisation changed nothing observable.
    """
    length = len(data)
    header = ""
    for _ in range(4):
        header = chr(65 + (length % 26)) + header
        length //= 26
    if not data:
        return header + "A"
    n = int.from_bytes(data, "big")
    body = ""
    while n > 0:
        n, r = divmod(n, 26)
        body = chr(65 + r) + body
    return header + body


class TestEquivalence:
    def test_matches_naive_reference(self, rng):
        """The fast codec must be indistinguishable from the paper's method."""
        for _ in range(200):
            data = random_bytes(rng, 1, 600)
            assert base26.encode(data) == naive_encode(data)

    def test_matches_across_size_boundaries(self):
        """Including sizes that straddle the recursion threshold."""
        for size in (1, 2, 47, 48, 49, 96, 97, 300, 1024):
            data = bytes(range(256)) * (size // 256) + bytes(range(size % 256))
            assert base26.encode(data) == naive_encode(data)


class TestRoundTrip:
    def test_random_payloads(self, rng):
        for _ in range(300):
            data = random_bytes(rng, 0, 500)
            assert base26.decode(base26.encode(data)) == data

    def test_empty(self):
        assert base26.encode(b"") == "AAAA"
        assert base26.decode("AAAA") == b""

    @pytest.mark.parametrize(
        "data",
        [b"\x00", b"\x00\x00\x00", b"\x00\x01", b"\xff", b"\xff" * 32, bytes(64)],
    )
    def test_leading_zeros_survive(self, data):
        """Leading zero bytes vanish inside the integer; only the header restores them."""
        assert base26.decode(base26.encode(data)) == data

    def test_output_is_alphabet_only(self, rng):
        for _ in range(50):
            encoded = base26.encode(random_bytes(rng, 1, 200))
            assert set(encoded) <= set(base26.ALPHABET)


class TestFraming:
    def test_header_records_length(self, rng):
        for _ in range(50):
            data = random_bytes(rng, 1, 400)
            header = base26.encode(data)[:4]
            recovered = 0
            for ch in header:
                recovered = recovered * 26 + (ord(ch) - 65)
            assert recovered == len(data)

    def test_rejects_short_input(self):
        with pytest.raises(DecodingError, match="shorter than"):
            base26.decode("ABC")

    def test_rejects_non_alphabetic(self):
        with pytest.raises(DecodingError, match="non-alphabetic"):
            base26.decode("AAAA123")

    def test_rejects_body_longer_than_header_allows(self):
        """A body encoding a bigger integer than the declared length can hold."""
        with pytest.raises(DecodingError, match="does not fit"):
            base26.decode("AAAB" + "Z" * 40)

    def test_rejects_oversized_payload(self):
        with pytest.raises(PayloadTooLargeError, match="ceiling"):
            base26.encode(b"\x00" * (base26.MAX_PAYLOAD_BYTES + 1))

    def test_accepts_payload_at_the_ceiling_boundary(self):
        """``MAX_PAYLOAD_BYTES`` itself must be allowed."""
        data = b"\x01" * base26.MAX_PAYLOAD_BYTES
        assert base26.decode(base26.encode(data)) == data
