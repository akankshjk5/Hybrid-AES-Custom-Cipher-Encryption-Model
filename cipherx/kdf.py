"""Key derivation (paper Section 5.2).

Two independent derivations feed the pipeline:

``derive_payload_keys``
    Scrypt over the AES passphrase and a fresh 16-byte salt. The paper asks for
    "a 32-byte AES-256 key" *and* "an additional 32-byte key for HMAC", so 64
    bytes are pulled and split. Scrypt is memory-hard (``N = 2**16, r = 8``
    costs roughly 67 MB), which is what makes an offline guessing attack on a
    weak passphrase expensive rather than trivial. It also dominates runtime --
    see ``benchmarks/reproduce_paper.py``.

``derive_structural_subkey``
    HKDF over the structural key. Cheap on purpose: it runs per message and
    protects no secret that Scrypt is not already protecting.

A note on the paper's own inconsistency
---------------------------------------
Algorithm 1 line 24 keys the outer tag with ``Kc`` directly, while Section 5.2
says the HMAC key comes out of Scrypt. Those cannot both hold. This
implementation keys the outer tag with ``HKDF(Kc, info="CIPHERX/v1/MAC")``:
still ``Kc`` material, as Algorithm 1 requires, but properly derived and
domain-separated, as Section 5.2 intends. The reference code used raw
``Kc.encode()`` as an HMAC key, which satisfies neither reading.
"""

from __future__ import annotations

from typing import Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .exceptions import ParameterError
from .params import ScryptParams

__all__ = [
    "AES_KEY_LEN",
    "MAC_KEY_LEN",
    "HKDF_MAC_INFO",
    "derive_payload_keys",
    "derive_structural_subkey",
]

AES_KEY_LEN = 32
MAC_KEY_LEN = 32

#: Domain-separation label for the outer-tag subkey. Versioned so a future
#: pipeline change cannot be confused with this one.
HKDF_MAC_INFO = b"CIPHERX/v1/MAC"


def derive_payload_keys(passphrase: str, salt: bytes, params: ScryptParams) -> Tuple[bytes, bytes]:
    """Derive ``(aes_key, inner_mac_key)`` from the passphrase and salt.

    Args:
        passphrase: user secret; may be low-entropy, which is the point of Scrypt.
        salt: 16 random bytes, transmitted in the clear with the ciphertext.
        params: Scrypt cost parameters.

    Returns:
        A 32-byte AES-256 key and a 32-byte reserved inner MAC key.
    """
    params.validate()
    if not isinstance(salt, (bytes, bytearray)) or not salt:
        raise ParameterError("salt must be non-empty bytes")

    material = Scrypt(
        salt=bytes(salt),
        length=params.length,
        n=params.n,
        r=params.r,
        p=params.p,
    ).derive(passphrase.encode("utf-8"))

    return material[:AES_KEY_LEN], material[AES_KEY_LEN:AES_KEY_LEN + MAC_KEY_LEN]


def derive_structural_subkey(
    structural_key: str,
    info: bytes = HKDF_MAC_INFO,
    length: int = MAC_KEY_LEN,
) -> bytes:
    """Derive a domain-separated subkey from the structural key."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=None,
        info=info,
    ).derive(structural_key.encode("utf-8"))
