"""Structural layer: per-stage invertibility, plus regressions for the three
defects described in :mod:`cipherx.structural`.
"""

from __future__ import annotations

import pytest

from cipherx import structural
from cipherx.exceptions import DecodingError
from cipherx.params import StructuralParams

from .conftest import PROBE_KEYS, random_letters

KEY = "structural-test-key"
KEY_BYTES = KEY.encode()


class TestVigenere:
    def test_round_trip(self, rng, params):
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


class TestSegmentation:
    def test_lengths_partition_the_string(self, params):
        for total in (1, 5, 37, 200, 4096):
            lengths = structural.segment_lengths(total, KEY_BYTES, params)
            assert sum(lengths) == total
            assert all(1 <= n <= params.segment_max for n in lengths)

    def test_deterministic_for_same_key_and_length(self, params):
        a = structural.segment_lengths(500, KEY_BYTES, params)
        b = structural.segment_lengths(500, KEY_BYTES, params)
        assert a == b

    def test_differs_between_keys(self, params):
        a = structural.segment_lengths(500, b"key-one", params)
        b = structural.segment_lengths(500, b"key-two", params)
        assert a != b

    def test_produces_many_segments(self, params):
        """Regression: the reference split on whitespace, so a Base-26 string
        (which has none) always yielded exactly one segment. That made the
        even-index CSPRNG rotation branch of Algorithm 1 unreachable."""
        lengths = structural.segment_lengths(500, KEY_BYTES, params)
        assert len(lengths) > 10, "segmentation must produce many segments"

    def test_even_index_rotation_branch_actually_runs(self, params):
        """With >= 2 segments the even branch executes; prove it changes output.

        A pure-reversal pipeline would leave a palindromic segment unchanged,
        so compare against reversal-only behaviour on a long input.
        """
        text = "ABCDEFGHIJ" * 20
        transformed = structural.transform_segments(text, KEY_BYTES, params)
        assert transformed != text
        assert transformed != text[::-1]
        assert structural.invert_segments(transformed, KEY_BYTES, params) == text

    def test_round_trip(self, rng, params):
        for _ in range(200):
            text = random_letters(rng, 0, 300)
            out = structural.transform_segments(text, KEY_BYTES, params)
            assert structural.invert_segments(out, KEY_BYTES, params) == text


class TestNoise:
    def test_round_trip(self, rng, params):
        for _ in range(200):
            text = random_letters(rng, 0, 300)
            out = structural.insert_noise(text, KEY_BYTES, params)
            assert structural.remove_noise(out, KEY_BYTES, params) == text

    def test_inserts_characters_disjoint_from_letters(self, params):
        out = structural.insert_noise("A" * 60, KEY_BYTES, params)
        assert len(out) > 60
        assert set(out) - set("A") <= set(params.noise_alphabet)

    def test_detects_corrupted_noise_position(self, params):
        """A letter where a noise character belongs means the stream is corrupt."""
        noisy = structural.insert_noise("A" * 60, KEY_BYTES, params)
        idx = next(i for i, c in enumerate(noisy) if c in params.noise_alphabet)
        corrupted = noisy[:idx] + "Q" + noisy[idx + 1:]
        with pytest.raises(DecodingError, match="noise character"):
            structural.remove_noise(corrupted, KEY_BYTES, params)


class TestBlockPermutation:
    def test_round_trip(self, rng, params):
        for _ in range(200):
            text = random_letters(rng, 1, 300)
            out = structural.block_shuffle(text, KEY_BYTES, params)
            assert structural.block_unshuffle(out, KEY_BYTES, params) == text

    def test_output_is_block_aligned(self, params):
        for n in range(1, 40):
            out = structural.block_shuffle("A" * n, KEY_BYTES, params)
            assert len(out) % params.block_size == 0

    # -- the headline regression -------------------------------------

    @pytest.mark.parametrize("n", range(1, 40))
    def test_payload_ending_in_x_survives(self, n, params):
        """Regression: the reference padded with ``'X'`` and unpadded with
        ``rstrip('X')``, silently eating any genuine trailing ``'X'``.

        ``'X'`` is a legal Base-26 character, so this corrupted real messages.
        Measured on the reference: 29/29 failures for inputs shaped like this
        one, and 19/500 on uniformly random letters.
        """
        text = "A" * (n - 1) + "X"
        out = structural.block_shuffle(text, KEY_BYTES, params)
        assert structural.block_unshuffle(out, KEY_BYTES, params) == text

    def test_all_x_payload(self, params):
        text = "X" * 50
        out = structural.block_shuffle(text, KEY_BYTES, params)
        assert structural.block_unshuffle(out, KEY_BYTES, params) == text

    def test_rejects_misaligned_body(self, params):
        with pytest.raises(DecodingError, match="multiple of block size"):
            structural.block_unshuffle("ABCDE", KEY_BYTES, params)


class TestFullLayer:
    @pytest.mark.parametrize("key", PROBE_KEYS)
    def test_round_trip_across_probe_keys(self, key, rng, params):
        """The reference failed 0%-69% here depending on the key; this must be 0%."""
        for _ in range(100):
            text = random_letters(rng, 1, 250)
            out = structural.apply_structural(text, key, params)
            assert structural.invert_structural(out, key, params) == text

    def test_stage_order_matches_algorithm_1(self, params):
        """Vigenere (line 8) must precede segmentation (line 9).

        Verified by reconstructing the pipeline stage by stage in the
        documented order and checking it reproduces ``apply_structural``.
        """
        from cipherx.mapping import forward_map

        text = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG"
        key_bytes = KEY.encode()
        expected = forward_map(text, params.shift_pattern)
        expected = structural.vigenere(expected, KEY, encrypt=True)
        expected = structural.transform_segments(expected, key_bytes, params)
        expected = structural.insert_noise(expected, key_bytes, params)
        expected = structural.block_shuffle(expected, key_bytes, params)
        assert structural.apply_structural(text, KEY, params) == expected

    def test_wrong_key_does_not_recover_plaintext(self, params):
        text = "THISISTHEORIGINALPLAINTEXTSTRING"
        out = structural.apply_structural(text, "right-key", params)
        try:
            recovered = structural.invert_structural(out, "wrong-key", params)
        except DecodingError:
            return  # rejected outright, also acceptable
        assert recovered != text

    def test_block_size_one_degenerates_safely(self, rng):
        params = StructuralParams(block_size=1)
        text = random_letters(rng, 1, 60)
        out = structural.apply_structural(text, KEY, params)
        assert structural.invert_structural(out, KEY, params) == text
