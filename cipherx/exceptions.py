"""Typed exception hierarchy for CipherX.

Every failure path raises one of these rather than leaking a bare ``KeyError``
or ``ValueError`` from an internal stage, so callers can distinguish a tampered
ciphertext from a malformed one from a bad parameter.
"""

__all__ = [
    "CipherXError",
    "IntegrityError",
    "DecodingError",
    "ParameterError",
    "PayloadTooLargeError",
]


class CipherXError(Exception):
    """Base class for every error raised by CipherX."""


class IntegrityError(CipherXError):
    """Authentication failed: the outer HMAC tag or the inner GCM tag did not verify.

    Raised for tampering, truncation, and wrong keys alike.  The message is
    deliberately coarse: distinguishing "wrong key" from "modified ciphertext"
    would hand an attacker a decryption oracle.
    """


class DecodingError(CipherXError):
    """The ciphertext is structurally malformed and could not be parsed.

    Covers a short or non-hex tag, a corrupt Base-26 header, characters outside
    the expected alphabet, and block/length headers that disagree.
    """


class ParameterError(CipherXError):
    """A profile or tuning parameter is outside its permitted range."""


class PayloadTooLargeError(CipherXError):
    """Input exceeds what the 4-letter Base-26 length header can represent.

    The header encodes the packed byte length in four Base-26 digits, so the
    hard ceiling is ``26**4 - 1 == 456_975`` bytes (see :mod:`cipherx.base26`).
    """
