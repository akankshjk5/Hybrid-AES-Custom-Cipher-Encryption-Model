"""CipherX -- a hybrid AES-256-GCM + custom structural cipher with Base-26 encoding.

Reference implementation for *"Secure Hybrid AES + Custom Cipher Encryption"*
(Akanksh J K, Sujal Sunil Badde; Dept. of Cyber Security, NMAM Institute of
Technology).

Quick start::

    from cipherx import CipherX

    cx = CipherX()
    ct = cx.encrypt("sensor reading 42", "passphrase", "structural-key")
    pt = cx.decrypt(ct, "passphrase", "structural-key")

For real deployments prefer the hardened profile, which keeps the outer tag at
its full 256-bit width::

    from cipherx import CipherX, STRICT
    cx = CipherX(STRICT)

See ``docs/PAPER_MAPPING.md`` for the clause-by-clause correspondence with the
paper, and ``docs/SECURITY.md`` for what this construction does and does not
guarantee.
"""

from .exceptions import (
    CipherXError,
    DecodingError,
    IntegrityError,
    ParameterError,
    PayloadTooLargeError,
)
from .hybrid import VERSION_TAG, CipherX, decrypt, encrypt
from .params import (
    FAST_TEST,
    PAPER,
    STRICT,
    Profile,
    ScryptParams,
    StructuralParams,
)

__version__ = "1.0.0"

__all__ = [
    "__version__",
    # pipeline
    "CipherX",
    "encrypt",
    "decrypt",
    "VERSION_TAG",
    # profiles
    "PAPER",
    "STRICT",
    "FAST_TEST",
    "Profile",
    "ScryptParams",
    "StructuralParams",
    # errors
    "CipherXError",
    "IntegrityError",
    "DecodingError",
    "ParameterError",
    "PayloadTooLargeError",
]
