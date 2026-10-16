"""Structural layer: per-stage invertibility, plus regressions for the four
defects described in :mod:`cipherx.structural`.
"""

from __future__ import annotations

import pytest

from cipherx import structural
from cipherx.exceptions import DecodingError, ParameterError
from cipherx.params import StructuralParams
from cipherx.structural import NONCE_LEN, StructuralContext

from .conftest import NONCE, PROBE_KEYS, make_ctx, random_letters

KEY = "structural-test-key"


class TestVigenere:
    def test_round_trip(self, rng):
        for _ in range(100):
            text = random_letters(rng, 0, 200)
            assert structural.vigenere(
                structural.vigenere(text, KEY, encrypt=True), KEY, encrypt=False
            ) == text

    def test_non_letters_pass_through_untouched(self):
        text = "AB12CD@EF"
        out = structural.vigenere(text, "KEY", encrypt=True)
        assert [c for c in out if not c.isalpha()] == ["1", "2", "@"]
        assert structural.vigenere(out, "KEY", encrypt=False) == text

    def test_key_with_no_letters_is_identity(self):
        assert structural.vigenere("HELLO", "1234", encrypt=True) == "HELLO"

    def test_key_index_advances_only_on_letters(self):
        """Non-letters must not consume key material, or decryption desyncs."""
        assert structural.vigenere("A1A", "BC", encrypt=True) == "B1C"


class TestStructuralContext:
    def test_rejects_wrong_length_nonce(self):
        with pytest.raises(ParameterError, match="exactly 16 characters"):
            StructuralContext(KEY, "TOOSHORT", StructuralParams())

    def test_rejects_non_alphabetic_nonce(self):
        with pytest.raises(ParameterError, match="only A-Z"):
            StructuralContext(KEY, "A" * 15 + "1", StructuralParams())

    def test_streams_are_domain_separated(self, ctx):
        """Each label must yield an independent stream under the same nonce."""
        draws = {
            label: ctx.rng(label).bytes(32)
            for label in (structural.CTX_SEGMENT, structural.CTX_WORDS,
                          structural.CTX_NOISE, structural.CTX_BLOCKS)
        }
        assert len(set(draws.values())) == 4

    def test_nonce_changes_every_stream(self, params):
        a = StructuralContext(KEY, "A" * 16, params)
        b = StructuralContext(KEY, "B" * 16, params)
        for label in (structural.CTX_SEGMENT, structural.CTX_NOISE,
                      structural.CTX_BLOCKS):
            assert a.rng(label).bytes(32) != b.rng(label).bytes(32)
        assert a.segment_rng(2).bytes(32) != b.segment_rng(2).bytes(32)


class TestNonceGeneration:
    def test_shape(self):
        for _ in range(50):
            nonce = structural.generate_nonce()
            assert len(nonce) == NONCE_LEN
            assert all("A" <= c <= "Z" for c in nonce)

    def test_fresh_each_call(self):
        assert len({structural.generate_nonce() for _ in range(200)}) == 200

    def test_distribution_is_unbiased(self):
        """Rejection sampling should leave no modulo bias across A-Z."""
        from collections import Counter
        counts = Counter("".join(structural.generate_nonce() for _ in range(2000)))
        assert len(counts) == 26
        assert max(counts.values()) / min(counts.values()) < 1.35


class TestSegmentation:
    def test_lengths_partition_the_string(self, ctx, params):
        for total in (1, 5, 37, 200, 4096):
            lengths = structural.segment_lengths(total, ctx)
            assert sum(lengths) == total
            assert all(1 <= n <= params.segment_max for n in lengths)

    def test_deterministic_for_same_key_nonce_and_length(self, ctx):
        assert structural.segment_lengths(500, ctx) == structural.segment_lengths(500, ctx)

    def test_differs_between_keys(self):
        assert structural.segment_lengths(500, make_ctx(key="key-one")) != \
               structural.segment_lengths(500, make_ctx(key="key-two"))

    def test_differs_between_nonces(self):
        """The partition is now per-message, not just per-key."""
        assert structural.segment_lengths(500, make_ctx(nonce="A" * 16)) != \
               structural.segment_lengths(500, make_ctx(nonce="B" * 16))

    def test_produces_many_segments(self, ctx):
        """Regression: the reference split on whitespace, so a Base-26 string
        (which has none) always yielded exactly one segment. That made the
        even-index CSPRNG rotation branch of Algorithm 1 unreachable."""
        assert len(structural.segment_lengths(500, ctx)) > 10

    def test_even_index_rotation_branch_actually_runs(self, ctx):
        """With >= 2 segments the even branch executes; prove it changes output."""
        text = "ABCDEFGHIJ" * 20
        transformed = structural.transform_segments(text, ctx)
        assert transformed != text
        assert transformed != text[::-1]
        assert structural.invert_segments(transformed, ctx) == text

    def test_round_trip(self, rng, ctx):
        for _ in range(200):
            text = random_letters(rng, 0, 300)
            assert structural.invert_segments(
                structural.transform_segments(text, ctx), ctx
            ) == text


class TestNoise:
    def test_round_trip(self, rng, ctx):
        for _ in range(200):
            text = random_letters(rng, 0, 300)
            assert structural.remove_noise(
                structural.insert_noise(text, ctx), ctx
            ) == text

    def test_inserts_characters_disjoint_from_letters(self, ctx, params):
        out = structural.insert_noise("A" * 60, ctx)
        assert len(out) > 60
        assert set(out) - set("A") <= set(params.noise_alphabet)

    def test_schedule_varies_with_nonce(self):
        """Regression for SECURITY.md Finding 1.

        The pool ordering and gap previously depended on the key alone, so
        every message under one key carried near-identical noise -- about 90%
        of noise positions matched across messages, letting an observer locate
        and strip the stage without any key.
        """
        text = "A" * 400
        a = structural.insert_noise(text, make_ctx(nonce="A" * 16))
        b = structural.insert_noise(text, make_ctx(nonce="B" * 16))
        assert a != b

    def test_detects_corrupted_noise_position(self, ctx, params):
        """A letter where a noise character belongs means the stream is corrupt."""
        noisy = structural.insert_noise("A" * 60, ctx)
        idx = next(i for i, c in enumerate(noisy) if c in params.noise_alphabet)
        with pytest.raises(DecodingError, match="noise character"):
            structural.remove_noise(noisy[:idx] + "Q" + noisy[idx + 1:], ctx)


class TestBlockPermutation:
    def test_round_trip(self, rng, ctx):
        for _ in range(200):
            text = random_letters(rng, 1, 300)
            assert structural.block_unshuffle(
                structural.block_shuffle(text, ctx), ctx
            ) == text

    def test_output_is_block_aligned(self, ctx, params):
        for n in range(1, 40):
            assert len(structural.block_shuffle("A" * n, ctx)) % params.block_size == 0

    def test_permutation_varies_with_nonce(self):
        text = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" * 4
        assert structural.block_shuffle(text, make_ctx(nonce="A" * 16)) != \
               structural.block_shuffle(text, make_ctx(nonce="B" * 16))

    # -- the padding regression --------------------------------------

    @pytest.mark.parametrize("n", range(1, 40))
    def test_payload_ending_in_x_survives(self, n, ctx):
        """Regression: the reference padded with ``'X'`` and unpadded with
        ``rstrip('X')``, silently eating any genuine trailing ``'X'``.

        ``'X'`` is a legal Base-26 character, so this corrupted real messages.
        Measured on the reference: 29/29 failures for inputs shaped like this
        one, and 19/500 on uniformly random letters.
        """
        text = "A" * (n - 1) + "X"
        assert structural.block_unshuffle(structural.block_shuffle(text, ctx), ctx) == text

    def test_all_x_payload(self, ctx):
        text = "X" * 50
        assert structural.block_unshuffle(structural.block_shuffle(text, ctx), ctx) == text

    def test_rejects_misaligned_body(self, ctx):
        with pytest.raises(DecodingError, match="multiple of block size"):
            structural.block_unshuffle("ABCDE", ctx)


class TestFullLayer:
    @pytest.mark.parametrize("key", PROBE_KEYS)
    def test_round_trip_across_probe_keys(self, key, rng):
        """The reference failed 0%-69% here depending on the key; this must be 0%."""
        ctx = make_ctx(key=key)
        for _ in range(100):
            text = random_letters(rng, 1, 250)
            assert structural.invert_structural(
                structural.apply_structural(text, ctx), ctx
            ) == text

    def test_round_trip_across_nonces(self, rng):
        for i in range(40):
            ctx = make_ctx(nonce=structural.generate_nonce())
            text = random_letters(rng, 1, 200)
            assert structural.invert_structural(
                structural.apply_structural(text, ctx), ctx
            ) == text

    def test_stage_order_matches_algorithm_1(self, ctx):
        """Vigenere (line 8) must precede segmentation (line 9)."""
        from cipherx.mapping import forward_map

        text = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG"
        expected = forward_map(text, ctx.params.shift_pattern)
        expected = structural.vigenere(expected, ctx.key, encrypt=True)
        expected = structural.transform_segments(expected, ctx)
        expected = structural.insert_noise(expected, ctx)
        expected = structural.block_shuffle(expected, ctx)
        assert structural.apply_structural(text, ctx) == expected

    def test_wrong_key_does_not_recover_plaintext(self):
        text = "THISISTHEORIGINALPLAINTEXTSTRING"
        out = structural.apply_structural(text, make_ctx(key="right-key"))
        try:
            recovered = structural.invert_structural(out, make_ctx(key="wrong-key"))
        except DecodingError:
            return  # rejected outright, also acceptable
        assert recovered != text

    def test_wrong_nonce_does_not_recover_plaintext(self):
        text = "THISISTHEORIGINALPLAINTEXTSTRING"
        out = structural.apply_structural(text, make_ctx(nonce="A" * 16))
        try:
            recovered = structural.invert_structural(out, make_ctx(nonce="B" * 16))
        except DecodingError:
            return
        assert recovered != text

    def test_block_size_one_degenerates_safely(self, rng):
        ctx = make_ctx(params=StructuralParams(block_size=1))
        text = random_letters(rng, 1, 60)
        assert structural.invert_structural(structural.apply_structural(text, ctx), ctx) == text
