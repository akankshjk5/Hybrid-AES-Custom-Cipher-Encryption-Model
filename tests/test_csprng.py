"""The deterministic CSPRNG -- the component the whole layer's reversibility rests on."""

from __future__ import annotations

from collections import Counter

import pytest

from cipherx.csprng import KeyedCSPRNG
from cipherx.exceptions import ParameterError


class TestDeterminism:
    def test_same_key_and_context_agree(self):
        a = KeyedCSPRNG(b"key", b"CTX")
        b = KeyedCSPRNG(b"key", b"CTX")
        assert a.bytes(512) == b.bytes(512)

    def test_contexts_are_domain_separated(self):
        a = KeyedCSPRNG(b"key", b"NOISE").bytes(64)
        b = KeyedCSPRNG(b"key", b"BLOCKS").bytes(64)
        assert a != b

    def test_keys_are_separated(self):
        a = KeyedCSPRNG(b"key-one", b"CTX").bytes(64)
        b = KeyedCSPRNG(b"key-two", b"CTX").bytes(64)
        assert a != b

    def test_chunked_reads_match_a_single_read(self):
        """A caller reading 7 bytes at a time must see the same stream as one
        reading 210 at once -- otherwise encrypt and decrypt could diverge
        purely from differing read patterns."""
        a = KeyedCSPRNG(b"key", b"CTX")
        b = KeyedCSPRNG(b"key", b"CTX")
        chunked = b"".join(a.bytes(7) for _ in range(30))
        assert chunked == b.bytes(210)

    def test_irregular_chunk_sizes(self):
        a = KeyedCSPRNG(b"key", b"CTX")
        b = KeyedCSPRNG(b"key", b"CTX")
        sizes = [1, 31, 2, 64, 5, 100, 3]
        assert b"".join(a.bytes(n) for n in sizes) == b.bytes(sum(sizes))


class TestRandint:
    def test_within_bounds(self):
        rng = KeyedCSPRNG(b"key", b"CTX")
        for _ in range(2000):
            assert 3 <= rng.randint(3, 7) <= 7

    def test_degenerate_range(self):
        assert KeyedCSPRNG(b"key", b"CTX").randint(5, 5) == 5

    def test_rejects_empty_range(self):
        with pytest.raises(ParameterError, match="empty range"):
            KeyedCSPRNG(b"key", b"CTX").randint(7, 3)

    def test_distribution_is_roughly_flat(self):
        """Rejection sampling should leave no modulo bias.

        A biased interval or permutation would be exactly the structural
        fingerprint this layer exists to remove.
        """
        rng = KeyedCSPRNG(b"key", b"CTX")
        counts = Counter(rng.randint(0, 9) for _ in range(20000))
        assert len(counts) == 10
        assert max(counts.values()) / min(counts.values()) < 1.25


class TestPermutation:
    def test_is_a_permutation(self):
        rng = KeyedCSPRNG(b"key", b"CTX")
        for n in (0, 1, 2, 10, 257):
            assert sorted(rng.permutation(n)) == list(range(n))

    def test_deterministic(self):
        a = KeyedCSPRNG(b"key", b"CTX").permutation(64)
        b = KeyedCSPRNG(b"key", b"CTX").permutation(64)
        assert a == b

    def test_actually_shuffles(self):
        assert KeyedCSPRNG(b"key", b"CTX").permutation(128) != list(range(128))

    def test_sequence_does_not_mutate_input(self):
        rng = KeyedCSPRNG(b"key", b"CTX")
        original = list("ABCDEFGH")
        snapshot = list(original)
        rng.sequence(original)
        assert original == snapshot


class TestValidation:
    def test_rejects_non_bytes_key(self):
        with pytest.raises(ParameterError, match="must be bytes"):
            KeyedCSPRNG("a string", b"CTX")  # type: ignore[arg-type]

    def test_rejects_negative_length(self):
        with pytest.raises(ParameterError, match="non-negative"):
            KeyedCSPRNG(b"key", b"CTX").bytes(-1)

    def test_zero_length_read(self):
        assert KeyedCSPRNG(b"key", b"CTX").bytes(0) == b""
