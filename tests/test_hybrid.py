"""End-to-end pipeline: round-trip, authentication, and error behaviour."""

from __future__ import annotations

import pytest

from cipherx import CipherX
from cipherx.exceptions import (
    CipherXError,
    DecodingError,
    IntegrityError,
    PayloadTooLargeError,
)
from cipherx.params import FAST_TEST, PAPER, STRICT

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

    def test_deterministic_when_salt_and_nonce_are_pinned(self, cipher):
        kwargs = dict(salt=b"\x01" * 16, nonce=b"\x02" * 12)
        a = cipher.encrypt("same", PASSPHRASE, STRUCTURAL_KEY, **kwargs)
        b = cipher.encrypt("same", PASSPHRASE, STRUCTURAL_KEY, **kwargs)
        assert a == b


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
        with pytest.raises(DecodingError, match="hexadecimal"):
            cipher.decrypt("AAAAAA" + "Z" * cipher.profile.tag_hex_len,
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
        message = "profile comparison"
        paper = CipherX(FAST_TEST.replace(tag_hex_len=16))
        strict = CipherX(FAST_TEST.replace(tag_hex_len=64))
        assert len(strict.encrypt(message, PASSPHRASE, STRUCTURAL_KEY)) - \
               len(paper.encrypt(message, PASSPHRASE, STRUCTURAL_KEY)) == 48

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
