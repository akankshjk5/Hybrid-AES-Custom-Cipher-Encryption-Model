"""The CipherX hybrid pipeline -- Algorithm 1 end to end.

Encryption::

    message --[AES-256-GCM over a Scrypt key]--> packed bytes
            --[Base-26]--> A-Z string
            --[structural layer]--> obfuscated string
            --[outer HMAC-SHA256]--> ciphertext

Decryption verifies the outer tag *before* touching any of the structural
stages, so a tampered ciphertext is rejected without running the inverse
transforms over attacker-chosen input.

Layered authentication, and why both layers are needed
------------------------------------------------------
GCM's tag covers the binary payload. The structural layer rewrites that payload
into something GCM has never seen, so on the wire the GCM tag authenticates
nothing an observer can check without first undoing the transforms. The outer
HMAC closes that gap: it is computed over the final string and verified first,
making tampering detectable at the layer where it actually occurs. GCM then
still guards the inner payload, so neither layer is redundant.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Optional

from . import base26
from .aead import seal, unseal
from .exceptions import DecodingError, IntegrityError
from .kdf import derive_structural_subkey
from .params import PAPER, Profile
from .structural import apply_structural, invert_structural

__all__ = ["VERSION_TAG", "CipherX", "encrypt", "decrypt"]

#: Bound into the outer tag so a ciphertext from one pipeline version cannot be
#: replayed against another.
VERSION_TAG = b"CIPHERX/v1"

_HEX_DIGITS = frozenset("0123456789abcdef")


class CipherX:
    """A configured CipherX instance.

    >>> c = CipherX()
    >>> ct = c.encrypt("hello", "passphrase", "structural-key")
    >>> c.decrypt(ct, "passphrase", "structural-key")
    'hello'

    Args:
        profile: parameter bundle; defaults to :data:`cipherx.params.PAPER`,
            which reproduces the published measurements. Use
            :data:`cipherx.params.STRICT` for a full-width outer tag.
    """

    def __init__(self, profile: Profile = PAPER) -> None:
        profile.validate()
        self.profile = profile

    # ------------------------------------------------------------------

    def _tag(self, body: str, structural_key: str) -> str:
        """Outer HMAC-SHA256 over ``VERSION_TAG || body``, hex, truncated."""
        key = derive_structural_subkey(structural_key)
        mac = hmac.new(key, VERSION_TAG + body.encode("utf-8"), hashlib.sha256)
        return mac.hexdigest()[:self.profile.tag_hex_len]

    # ------------------------------------------------------------------

    def encrypt(
        self,
        message: str,
        passphrase: str,
        structural_key: str,
        *,
        salt: Optional[bytes] = None,
        nonce: Optional[bytes] = None,
    ) -> str:
        """Encrypt ``message`` and return the hybrid ciphertext.

        Args:
            message: UTF-8 text. Any Unicode survives the round trip; the
                uppercasing in the structural layer applies to the *Base-26
                encoding* of the AES output, never to the message itself.
            passphrase: AES passphrase, stretched with Scrypt.
            structural_key: key for the structural layer and the outer tag.
            salt, nonce: test-vector overrides; see :func:`cipherx.aead.seal`.

        Raises:
            PayloadTooLargeError: past the Base-26 header's 456,975-byte ceiling.
        """
        packed = seal(
            message.encode("utf-8"),
            passphrase,
            self.profile.scrypt,
            salt=salt,
            nonce=nonce,
        )
        encoded = base26.encode(packed)
        body = apply_structural(encoded, structural_key, self.profile.structural)
        return body + self._tag(body, structural_key)

    def decrypt(self, ciphertext: str, passphrase: str, structural_key: str) -> str:
        """Invert :meth:`encrypt`.

        Raises:
            DecodingError: malformed ciphertext (too short, bad tag charset,
                corrupt internal framing).
            IntegrityError: the outer HMAC or the inner GCM tag did not verify.
        """
        tag_len = self.profile.tag_hex_len
        if len(ciphertext) <= tag_len:
            raise DecodingError(
                f"ciphertext is {len(ciphertext)} characters, too short to hold a "
                f"{tag_len}-character tag and a body"
            )

        body, tag = ciphertext[:-tag_len], ciphertext[-tag_len:]
        if not _HEX_DIGITS.issuperset(tag.lower()):
            raise DecodingError("ciphertext tag is not hexadecimal")

        # Constant-time: a timing-variable compare here would leak the tag one
        # character at a time and turn this into a forgery oracle.
        if not hmac.compare_digest(tag, self._tag(body, structural_key)):
            raise IntegrityError(
                "outer HMAC verification failed: wrong structural key or modified ciphertext"
            )

        encoded = invert_structural(body, structural_key, self.profile.structural)
        packed = base26.decode(encoded)
        return unseal(packed, passphrase, self.profile.scrypt).decode("utf-8")


# ----------------------------------------------------------------------
# Module-level convenience API
# ----------------------------------------------------------------------

def encrypt(
    message: str,
    passphrase: str,
    structural_key: str,
    profile: Profile = PAPER,
) -> str:
    """Encrypt with a one-off :class:`CipherX`."""
    return CipherX(profile).encrypt(message, passphrase, structural_key)


def decrypt(
    ciphertext: str,
    passphrase: str,
    structural_key: str,
    profile: Profile = PAPER,
) -> str:
    """Decrypt with a one-off :class:`CipherX`."""
    return CipherX(profile).decrypt(ciphertext, passphrase, structural_key)
