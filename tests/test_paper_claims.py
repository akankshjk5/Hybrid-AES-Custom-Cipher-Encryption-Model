"""Checks on the quantitative claims the paper makes.

These are the assertions a reviewer would want to re-run. Where a claim holds,
the test pins it; where the paper's framing is misleading, the test says so in
its docstring and asserts what is actually true instead of pretending otherwise.
"""

from __future__ import annotations

import math

import pytest

from cipherx import CipherX
from cipherx.analysis import (
    entropy_report,
    expansion_ratio,
    index_of_coincidence,
    shannon_entropy,
)
from cipherx.params import FAST_TEST

from .conftest import PASSPHRASE, STRUCTURAL_KEY

LOG2_26 = math.log2(26)


@pytest.fixture(scope="module")
def samples():
    """Six ciphertexts, matching the six rows of the paper's Table I."""
    cipher = CipherX(FAST_TEST)
    sizes = [12, 37, 44, 71, 1000, 10000]
    return [cipher.encrypt("A" * n, PASSPHRASE, STRUCTURAL_KEY) for n in sizes]


class TestEntropy:
    def test_exceeds_log2_26(self, samples):
        """Paper Table I: entropy 5.23-5.33 bits/char against log2(26) = 4.70."""
        for ciphertext in samples:
            assert shannon_entropy(ciphertext) > LOG2_26

    def test_in_the_published_band(self, samples):
        """Values should land near the paper's 5.23-5.33 range.

        This implementation sits slightly higher: the keyed segmentation makes
        the even-index rotation branch live, where the reference left it dead.
        The band is widened accordingly rather than tuned to match.
        """
        for ciphertext in samples:
            assert 5.0 <= shannon_entropy(ciphertext) <= 5.6

    def test_excess_over_log2_26_is_explained_by_alphabet_width(self, samples):
        """The paper attributes the >4.70 entropy to obfuscation strength.

        The real cause is arithmetic: noise injection widens the alphabet from
        26 to about 42 symbols, lifting the ceiling to log2(42) ~ 5.39. The
        honest statement is that entropy is close to the ceiling *for the
        alphabet actually used*, which is what this asserts.
        """
        for ciphertext in samples:
            report = entropy_report(ciphertext)
            assert report.distinct_symbols > 26, "noise must widen the alphabet"
            assert report.entropy <= report.ceiling_observed + 1e-9
            assert report.utilisation_pct > 90.0

    def test_index_of_coincidence_is_near_uniform(self, samples):
        """No exploitable single-character bias."""
        for ciphertext in samples[-2:]:  # long samples only; short ones are noisy
            distinct = len(set(ciphertext))
            assert index_of_coincidence(ciphertext) < (1.0 / distinct) * 1.5


class TestExpansion:
    def test_short_messages_expand_most(self):
        """Paper Section 6.2: up to ~7x for short inputs, dominated by fixed overhead."""
        cipher = CipherX(FAST_TEST)
        short = cipher.encrypt("A" * 12, PASSPHRASE, STRUCTURAL_KEY)
        assert expansion_ratio("A" * 12, short) > 4.0

    def test_large_messages_approach_a_stable_ratio(self):
        """Paper Section 6.2: stabilises near 1.5x-2x for inputs >= 1 kB."""
        cipher = CipherX(FAST_TEST)
        big = cipher.encrypt("A" * 10000, PASSPHRASE, STRUCTURAL_KEY)
        ratio = expansion_ratio("A" * 10000, big)
        assert 1.5 <= ratio <= 2.5

    def test_expansion_decreases_with_size(self):
        """Nonce pinned: per-message ``gap`` variation is larger than the gap
        between the 1 kB and 10 kB ratios, which are already nearly equal."""
        cipher = CipherX(FAST_TEST)
        ratios = [
            expansion_ratio("A" * n, cipher.encrypt(
                "A" * n, PASSPHRASE, STRUCTURAL_KEY, structural_nonce="A" * 16))
            for n in (12, 100, 1000, 10000)
        ]
        assert ratios == sorted(ratios, reverse=True)


class TestScaling:
    def test_ciphertext_length_is_linear_in_input(self):
        """Paper Section 6.1 claims linear-time, linear-size behaviour.

        The structural nonce is pinned so the noise interval is held constant
        across the three sizes; otherwise per-message ``gap`` variation
        (3..7) swamps the effect being measured.
        """
        cipher = CipherX(FAST_TEST)
        pinned = dict(structural_nonce="A" * 16)
        lengths = {
            n: len(cipher.encrypt("A" * n, PASSPHRASE, STRUCTURAL_KEY, **pinned))
            for n in (1000, 2000, 4000)
        }
        # Doubling input should roughly double output, once fixed overhead is small.
        r1 = lengths[2000] / lengths[1000]
        r2 = lengths[4000] / lengths[2000]
        assert 1.8 < r1 < 2.2 and 1.9 < r2 < 2.1

    def test_length_now_varies_between_messages(self):
        """Side benefit of the per-message nonce, relevant to Finding 6.

        ``gap`` is drawn per message from ``[3, 7]``, so the noise volume --
        and therefore the ciphertext length -- is no longer a deterministic
        function of plaintext size. Measured spread is roughly 10-16%. That
        does not hide length, but it does blur the exact mapping an observer
        could otherwise rely on.
        """
        cipher = CipherX(FAST_TEST)
        lengths = {len(cipher.encrypt("A" * 1000, PASSPHRASE, STRUCTURAL_KEY))
                   for _ in range(12)}
        assert len(lengths) > 1, "ciphertext length should vary between messages"
        assert (max(lengths) - min(lengths)) / min(lengths) > 0.02


class TestReversibility:
    def test_repetitive_telemetry_round_trips(self):
        """Paper Section 6.5: repetitive IoT-style input is a named test case."""
        cipher = CipherX(FAST_TEST)
        message = "sensor=1;temp=23.5;ts=1699999999;" * 100
        assert cipher.decrypt(
            cipher.encrypt(message, PASSPHRASE, STRUCTURAL_KEY), PASSPHRASE, STRUCTURAL_KEY
        ) == message

    def test_payload_positions_are_unrelated_across_encryptions(self):
        """Paper Section 3.B: repetition must not show through.

        Restricted to payload (``A-Z``) positions, agreement between two
        encryptions of the same repetitive message sits at chance -- about
        ``1/26 = 3.8%``. The AEAD and the structural layer do their job.
        """
        cipher = CipherX(FAST_TEST)
        message = "status=OK;" * 50
        a = cipher.encrypt(message, PASSPHRASE, STRUCTURAL_KEY)
        b = cipher.encrypt(message, PASSPHRASE, STRUCTURAL_KEY)
        shared = min(len(a), len(b))

        letter_positions = [i for i in range(shared) if a[i].isalpha() and b[i].isalpha()]
        matching = sum(1 for i in letter_positions if a[i] == b[i])
        rate = matching / len(letter_positions)
        assert rate < 0.08, f"payload positions agree at {rate:.1%}, above chance"

    def test_noise_layer_is_per_message_randomised(self):
        """SECURITY.md Finding 1, fixed: the noise stage no longer repeats.

        ``gap`` and the shuffled noise pool used to be drawn from
        ``CSPRNG(Kc, "NOISE")``, which depends on the structural key alone.
        Two messages under one key then carried nearly the same noise
        subsequence -- roughly **90%** agreement on noise positions. An
        observer with two ciphertexts could locate the noise, read off
        ``gap``, and strip the stage without knowing any key, undoing one of
        the paper's five obfuscation layers and contradicting the Section 3.B
        claim that repetition is concealed.

        A per-message structural nonce now feeds every generator, so noise
        positions agree at chance. Measured at ~0.7%.
        """
        from cipherx.params import NOISE_ALPHABET

        cipher = CipherX(FAST_TEST)
        message = "status=OK;" * 50
        a = cipher.encrypt(message, PASSPHRASE, STRUCTURAL_KEY)
        b = cipher.encrypt(message, PASSPHRASE, STRUCTURAL_KEY)
        shared = min(len(a), len(b))

        noise = set(NOISE_ALPHABET)
        noise_positions = [i for i in range(shared) if a[i] in noise or b[i] in noise]
        rate = sum(1 for i in noise_positions if a[i] == b[i]) / len(noise_positions)
        assert rate < 0.15, (
            f"noise positions agree at {rate:.1%}; the stage looks key-derived "
            "again rather than per-message. See docs/SECURITY.md Finding 1."
        )

    def test_whole_ciphertext_agrees_only_at_chance(self):
        """With the nonce in place, no position class leaks across messages."""
        cipher = CipherX(FAST_TEST)
        message = "status=OK;" * 50
        a = cipher.encrypt(message, PASSPHRASE, STRUCTURAL_KEY)
        b = cipher.encrypt(message, PASSPHRASE, STRUCTURAL_KEY)
        shared = min(len(a), len(b))
        rate = sum(1 for i in range(shared) if a[i] == b[i]) / shared
        assert rate < 0.10, f"ciphertexts agree at {rate:.1%}, above chance"
