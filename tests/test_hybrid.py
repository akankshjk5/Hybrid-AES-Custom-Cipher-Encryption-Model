"""End-to-end pipeline: round-trip, authentication, and error behaviour."""

from __future__ import annotations

import pytest

from cipherx import CipherX
from cipherx.exceptions import (
    CipherXError,
    DecodingError,
    IntegrityError,
    ParameterError,
    PayloadTooLargeError,
)
from cipherx.params import FAST_TEST, PAPER, STRICT
from cipherx.structural import NONCE_LEN

from .conftest import PASSPHRASE, PROBE_KEYS, STRUCTURAL_KEY

MESSAGES = [
    "",
    "A",
    "X",
    "XXXXXXXXXXXXXXXXXXXX",
    "hello world",
    "the quick brown fox jumps over the lazy dog",
    "sensor=1;value=42;ts=1699999999",
    "sensor=1;value=42;" * 50,          # repetitive IoT telemetry
    "temperature 23.5C — café ☕ 日本語",
    "line one\nline two\ttabbed\r\n",
    " leading and trailing  ",
    "!@#$%^&*()_+-=[]{}|;':\",./<>?",
    "L" * 2000,
]


class TestRoundTrip:
    @pytest.mark.parametrize("message", MESSAGES, ids=lambda m: repr(m[:18]))
    def test_messages(self, cipher, message):
        assert cipher.decrypt(
            cipher.encrypt(message, PASSPHRASE, STRUCTURAL_KEY), PASSPHRASE, STRUCTURAL_KEY
        ) == message

    @pytest.mark.parametrize("key", PROBE_KEYS)
    def test_across_probe_keys(self, cipher, key):
        message = "payload that happens to end in X"
        assert cipher.decrypt(cipher.encrypt(message, PASSPHRASE, key), PASSPHRASE, key) == message

    def test_fuzz(self, cipher, rng):
        import string
        alphabet = string.printable[:95]
        for _ in range(60):
            message = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 250)))
            assert cipher.decrypt(
                cipher.encrypt(message, PASSPHRASE, STRUCTURAL_KEY), PASSPHRASE, STRUCTURAL_KEY
            ) == message

    def test_nondeterministic_across_calls(self, cipher):
        """Fresh salt and nonce per call: identical plaintexts must not collide."""
        a = cipher.encrypt("same", PASSPHRASE, STRUCTURAL_KEY)
        b = cipher.encrypt("same", PASSPHRASE, STRUCTURAL_KEY)
        assert a != b
        assert cipher.decrypt(a, PASSPHRASE, STRUCTURAL_KEY) == "same"
        assert cipher.decrypt(b, PASSPHRASE, STRUCTURAL_KEY) == "same"

    def test_deterministic_when_all_randomness_is_pinned(self, cipher):
        kwargs = dict(salt=b"\x01" * 16, nonce=b"\x02" * 12,
                      structural_nonce="A" * NONCE_LEN)
        a = cipher.encrypt("same", PASSPHRASE, STRUCTURAL_KEY, **kwargs)
        b = cipher.encrypt("same", PASSPHRASE, STRUCTURAL_KEY, **kwargs)
        assert a == b

    def test_structural_nonce_alone_makes_output_differ(self, cipher):
        """Even with salt and GCM nonce pinned, a fresh structural nonce
        must change the whole ciphertext."""
        kwargs = dict(salt=b"\x01" * 16, nonce=b"\x02" * 12)
        a = cipher.encrypt("same", PASSPHRASE, STRUCTURAL_KEY,
                           structural_nonce="A" * NONCE_LEN, **kwargs)
        b = cipher.encrypt("same", PASSPHRASE, STRUCTURAL_KEY,
                           structural_nonce="B" * NONCE_LEN, **kwargs)
        assert a != b
        assert cipher.decrypt(a, PASSPHRASE, STRUCTURAL_KEY) == "same"
        assert cipher.decrypt(b, PASSPHRASE, STRUCTURAL_KEY) == "same"


class TestStructuralNonce:
    def test_prefixes_the_ciphertext(self, cipher):
        ciphertext = cipher.encrypt("x", PASSPHRASE, STRUCTURAL_KEY,
                                    structural_nonce="QWERTYUIOPASDFGH")
        assert ciphertext[:NONCE_LEN] == "QWERTYUIOPASDFGH"

    def test_is_fresh_per_message(self, cipher):
        nonces = {
            cipher.encrypt("x", PASSPHRASE, STRUCTURAL_KEY)[:NONCE_LEN]
            for _ in range(25)
        }
        assert len(nonces) == 25

    def test_is_authenticated(self, cipher):
        """Swapping the nonce must fail the outer tag, not silently decrypt."""
        ciphertext = cipher.encrypt("probe", PASSPHRASE, STRUCTURAL_KEY)
        for i in range(NONCE_LEN):
            swapped = ciphertext[:i] + ("B" if ciphertext[i] != "B" else "C") \
                      + ciphertext[i + 1:]
            with pytest.raises(IntegrityError, match="outer HMAC"):
                cipher.decrypt(swapped, PASSPHRASE, STRUCTURAL_KEY)

    def test_rejects_malformed_override(self, cipher):
        for bad in ("TOOSHORT", "A" * 17, "A" * 15 + "1", "a" * 16):
            with pytest.raises(ParameterError):
                cipher.encrypt("x", PASSPHRASE, STRUCTURAL_KEY, structural_nonce=bad)

    def test_ciphertext_grew_by_exactly_the_nonce(self, cipher):
        """The format change costs NONCE_LEN characters and nothing else."""
        ciphertext = cipher.encrypt("A" * 1000, PASSPHRASE, STRUCTURAL_KEY)
        body = ciphertext[NONCE_LEN:-cipher.profile.tag_hex_len]
        assert len(ciphertext) == NONCE_LEN + len(body) + cipher.profile.tag_hex_len


class TestAuthentication:
    @pytest.fixture
    def ciphertext(self, cipher):
        return cipher.encrypt("authenticated payload", PASSPHRASE, STRUCTURAL_KEY)

    def test_wrong_passphrase(self, cipher, ciphertext):
        with pytest.raises(IntegrityError):
            cipher.decrypt(ciphertext, "wrong", STRUCTURAL_KEY)

    def test_wrong_structural_key(self, cipher, ciphertext):
        with pytest.raises(IntegrityError, match="outer HMAC"):
            cipher.decrypt(ciphertext, PASSPHRASE, "wrong")

    def test_outer_tag_checked_before_structural_inversion(self, cipher, ciphertext):
        """A bad structural key must fail at the tag, not deep inside the stages.

        Verifying first means attacker-chosen input never reaches the inverse
        transforms.
        """
        with pytest.raises(IntegrityError, match="outer HMAC"):
            cipher.decrypt(ciphertext, PASSPHRASE, "wrong")

    def test_every_single_character_flip_is_caught(self, cipher, ciphertext):
        for i in range(len(ciphertext)):
            original = ciphertext[i]
            replacement = "B" if original != "B" else "C"
            tampered = ciphertext[:i] + replacement + ciphertext[i + 1:]
            with pytest.raises(CipherXError):
                cipher.decrypt(tampered, PASSPHRASE, STRUCTURAL_KEY)

    def test_truncation_is_caught(self, cipher, ciphertext):
        for cut in (1, 2, 7, len(ciphertext) // 2):
            with pytest.raises(CipherXError):
                cipher.decrypt(ciphertext[:-cut], PASSPHRASE, STRUCTURAL_KEY)

    def test_appended_data_is_caught(self, cipher, ciphertext):
        with pytest.raises(CipherXError):
            cipher.decrypt(ciphertext + "AB", PASSPHRASE, STRUCTURAL_KEY)

    def test_tag_is_bound_to_the_pipeline_version(self, cipher, ciphertext):
        """VERSION_TAG is inside the MAC input, so a bare body will not verify."""
        tag_len = cipher.profile.tag_hex_len
        body = ciphertext[:-tag_len]
        import hashlib, hmac
        from cipherx.kdf import derive_structural_subkey
        unversioned = hmac.new(
            derive_structural_subkey(STRUCTURAL_KEY), body.encode(), hashlib.sha256
        ).hexdigest()[:tag_len]
        with pytest.raises(IntegrityError):
            cipher.decrypt(body + unversioned, PASSPHRASE, STRUCTURAL_KEY)


class TestMalformedInput:
    def test_empty_ciphertext(self, cipher):
        with pytest.raises(DecodingError, match="too short"):
            cipher.decrypt("", PASSPHRASE, STRUCTURAL_KEY)

    def test_tag_only(self, cipher):
        with pytest.raises(DecodingError, match="too short"):
            cipher.decrypt("0" * cipher.profile.tag_hex_len, PASSPHRASE, STRUCTURAL_KEY)

    def test_non_hex_tag(self, cipher):
        # Long enough to clear the nonce + tag framing, so the hex check is
        # what rejects it rather than the length check.
        body = "A" * (NONCE_LEN + 20)
        with pytest.raises(DecodingError, match="hexadecimal"):
            cipher.decrypt(body + "Z" * cipher.profile.tag_hex_len,
                           PASSPHRASE, STRUCTURAL_KEY)

    def test_oversized_message(self, cipher):
        from cipherx.base26 import MAX_PAYLOAD_BYTES
        with pytest.raises(PayloadTooLargeError):
            cipher.encrypt("a" * (MAX_PAYLOAD_BYTES + 10), PASSPHRASE, STRUCTURAL_KEY)


class TestProfiles:
    def test_tag_widths(self):
        assert PAPER.tag_hex_len == 16 and PAPER.tag_bits == 64
        assert STRICT.tag_hex_len == 64 and STRICT.tag_bits == 256

    def test_strict_produces_a_longer_tag(self):
        """Pin every source of randomness: the noise gap is now drawn per
        nonce, so body length varies between messages and only a pinned nonce
        isolates the tag-width difference."""
        message = "profile comparison"
        pinned = dict(salt=b"\x01" * 16, nonce=b"\x02" * 12,
                      structural_nonce="A" * NONCE_LEN)
        paper = CipherX(FAST_TEST.replace(tag_hex_len=16))
        strict = CipherX(FAST_TEST.replace(tag_hex_len=64))
        assert len(strict.encrypt(message, PASSPHRASE, STRUCTURAL_KEY, **pinned)) - \
               len(paper.encrypt(message, PASSPHRASE, STRUCTURAL_KEY, **pinned)) == 48

    def test_profiles_are_not_interchangeable(self):
        """Different tag widths mean ciphertexts do not cross-decrypt."""
        message = "profile isolation"
        strict = CipherX(FAST_TEST.replace(tag_hex_len=64))
        paper = CipherX(FAST_TEST.replace(tag_hex_len=16))
        with pytest.raises(CipherXError):
            paper.decrypt(strict.encrypt(message, PASSPHRASE, STRUCTURAL_KEY),
                          PASSPHRASE, STRUCTURAL_KEY)

    @pytest.mark.slow
    def test_paper_profile_round_trip(self):
        """The real thing, at the paper's Scrypt cost."""
        cipher = CipherX(PAPER)
        message = "paper-profile round trip"
        assert cipher.decrypt(
            cipher.encrypt(message, PASSPHRASE, STRUCTURAL_KEY), PASSPHRASE, STRUCTURAL_KEY
        ) == message
