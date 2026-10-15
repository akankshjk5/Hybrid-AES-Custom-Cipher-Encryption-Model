"""AES-256-GCM layer and its wire packing (paper Sections 5.3 and 5.4).

The packed blob is the concatenation of Algorithm 1 line 5::

    salt(16) || nonce(12) || ciphertext || gcm_tag(16)

The salt and nonce travel in the clear -- neither is secret, and both are
needed before anything can be derived or decrypted. GCM appends its own 16-byte
tag to the ciphertext, so ``ciphertext || gcm_tag`` is what ``AESGCM.encrypt``
returns as one piece.

This is the layer that actually provides confidentiality. Everything after it
is structural obfuscation: valuable against traffic analysis, but not a
substitute for the AEAD.
"""

from __future__ import annotations

import os
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .exceptions import DecodingError, IntegrityError, ParameterError
from .kdf import derive_payload_keys
from .params import ScryptParams

__all__ = ["SALT_LEN", "NONCE_LEN", "GCM_TAG_LEN", "OVERHEAD", "seal", "unseal"]

SALT_LEN = 16
NONCE_LEN = 12
GCM_TAG_LEN = 16

#: Fixed bytes added to every payload, independent of message length.
OVERHEAD = SALT_LEN + NONCE_LEN + GCM_TAG_LEN


def seal(
    plaintext: bytes,
    passphrase: str,
    params: ScryptParams,
    *,
    salt: Optional[bytes] = None,
    nonce: Optional[bytes] = None,
) -> bytes:
    """Encrypt ``plaintext`` and return ``salt || nonce || ct || tag``.

    Args:
        plaintext: raw bytes to protect.
        passphrase: AES passphrase, stretched through Scrypt.
        params: Scrypt cost parameters.
        salt: override the random salt. **Tests and published test vectors
            only** -- reusing a salt across messages undoes Scrypt's per-message
            key separation.
        nonce: override the random nonce. **Tests only.** GCM fails
            catastrophically on nonce reuse under the same key: two messages
            sharing a nonce leak their XOR and expose the GHASH authentication
            key.
    """
    if salt is None:
        salt = os.urandom(SALT_LEN)
    elif len(salt) != SALT_LEN:
        raise ParameterError(f"salt must be exactly {SALT_LEN} bytes")

    if nonce is None:
        nonce = os.urandom(NONCE_LEN)
    elif len(nonce) != NONCE_LEN:
        raise ParameterError(f"nonce must be exactly {NONCE_LEN} bytes")

    aes_key, _mac_key = derive_payload_keys(passphrase, salt, params)
    body = AESGCM(aes_key).encrypt(nonce, plaintext, None)
    return salt + nonce + body


def unseal(packed: bytes, passphrase: str, params: ScryptParams) -> bytes:
    """Inverse of :func:`seal`.

    Raises:
        DecodingError: if the blob is too short to contain its own framing.
        IntegrityError: if the GCM tag does not verify -- wrong passphrase,
            tampering, or truncation. These are deliberately indistinguishable.
    """
    if len(packed) < OVERHEAD:
        raise DecodingError(
            f"packed payload is {len(packed)} bytes, below the {OVERHEAD}-byte minimum framing"
        )

    salt = packed[:SALT_LEN]
    nonce = packed[SALT_LEN:SALT_LEN + NONCE_LEN]
    body = packed[SALT_LEN + NONCE_LEN:]

    aes_key, _mac_key = derive_payload_keys(passphrase, salt, params)
    try:
        return AESGCM(aes_key).decrypt(nonce, body, None)
    except InvalidTag as exc:
        raise IntegrityError(
            "AES-GCM authentication failed: wrong passphrase or modified ciphertext"
        ) from exc
