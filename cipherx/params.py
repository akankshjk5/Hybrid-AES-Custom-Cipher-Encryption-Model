"""Tunable parameters and the two shipped security profiles.

CipherX is published alongside an IEEE paper, so it has to do two things that
pull in opposite directions: reproduce the paper's measurements exactly, and be
safe to actually deploy.  That tension is resolved with *profiles*.

``PAPER``
    Byte-for-byte the parameters in the paper (Section 5.2, Algorithm 1),
    including the 16-hex-character truncated outer tag.  Use this to reproduce
    Table I and Table II.

``STRICT``
    Identical pipeline, but the outer HMAC tag is kept at its full 256-bit
    width.  Use this anywhere real data is involved.

The structural stages are identical in both profiles; only the authentication
strength differs.  See ``docs/SECURITY.md`` for the reasoning.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Tuple

from .exceptions import ParameterError

__all__ = [
    "ScryptParams",
    "StructuralParams",
    "Profile",
    "PAPER",
    "STRICT",
    "FAST_TEST",
    "NOISE_ALPHABET",
]

#: Characters injected by the deterministic noise stage (paper Section 5.6.4).
#: Deliberately disjoint from ``A-Z`` so noise is unambiguously separable from
#: payload during removal.
NOISE_ALPHABET = "0123456789@#$%&*"


@dataclass(frozen=True)
class ScryptParams:
    """Memory-hard KDF parameters.

    Defaults are the paper's: ``N = 2**16, r = 8, p = 2``, which costs roughly
    67 MB of RAM per derivation and dominates end-to-end runtime.
    """

    n: int = 2 ** 16
    r: int = 8
    p: int = 2
    #: Total bytes pulled from Scrypt, split into a 32-byte AES-256 key and a
    #: 32-byte inner MAC key (paper Section 5.2 asks for both).
    length: int = 64

    def validate(self) -> None:
        if self.n < 2 or (self.n & (self.n - 1)):
            raise ParameterError("scrypt N must be a power of two greater than 1")
        if self.r < 1 or self.p < 1:
            raise ParameterError("scrypt r and p must be >= 1")
        if self.length < 32:
            raise ParameterError("scrypt output must be at least 32 bytes")

    @property
    def approx_memory_bytes(self) -> int:
        """Rough working-set size, ``128 * N * r`` bytes."""
        return 128 * self.n * self.r


@dataclass(frozen=True)
class StructuralParams:
    """Parameters of the reversible structural-obfuscation layer."""

    #: Cycled over character position in the nonlinear mapping stage.
    shift_pattern: Tuple[int, ...] = (2, 3, 5, 7)
    #: Permutation block width; ``blk = 6`` in Algorithm 1 line 23.
    block_size: int = 6
    #: Inclusive bounds on keyed segment length (Algorithm 1 line 9).
    segment_min: int = 4
    segment_max: int = 12
    #: Inclusive bounds on the noise interval drawn once per key.
    noise_gap_min: int = 3
    noise_gap_max: int = 7
    noise_alphabet: str = NOISE_ALPHABET

    def validate(self) -> None:
        if not self.shift_pattern:
            raise ParameterError("shift_pattern must not be empty")
        if self.block_size < 1:
            raise ParameterError("block_size must be >= 1")
        if not 1 <= self.segment_min <= self.segment_max:
            raise ParameterError("require 1 <= segment_min <= segment_max")
        if not 1 <= self.noise_gap_min <= self.noise_gap_max:
            raise ParameterError("require 1 <= noise_gap_min <= noise_gap_max")
        if not self.noise_alphabet:
            raise ParameterError("noise_alphabet must not be empty")
        if any("A" <= c <= "Z" for c in self.noise_alphabet):
            raise ParameterError("noise_alphabet must not overlap A-Z")


@dataclass(frozen=True)
class Profile:
    """A named bundle of KDF, structural and authentication settings."""

    name: str
    scrypt: ScryptParams = field(default_factory=ScryptParams)
    structural: StructuralParams = field(default_factory=StructuralParams)
    #: Hex characters of outer HMAC-SHA256 retained. 64 == untruncated.
    tag_hex_len: int = 16

    def validate(self) -> None:
        self.scrypt.validate()
        self.structural.validate()
        if not 8 <= self.tag_hex_len <= 64:
            raise ParameterError("tag_hex_len must be between 8 and 64 hex characters")

    @property
    def tag_bits(self) -> int:
        return self.tag_hex_len * 4

    def replace(self, **kwargs) -> "Profile":
        """Return a copy with fields overridden."""
        return replace(self, **kwargs)


#: Exactly the paper's configuration, including the 64-bit truncated outer tag.
PAPER = Profile(name="paper", tag_hex_len=16)

#: Same pipeline, full-width 256-bit outer tag. Recommended for real use.
STRICT = Profile(name="strict", tag_hex_len=64)

#: Cheap KDF for tests and fuzzing only -- NOT a security profile.
FAST_TEST = Profile(
    name="fast-test",
    scrypt=ScryptParams(n=2 ** 8, r=8, p=1),
    tag_hex_len=64,
)
