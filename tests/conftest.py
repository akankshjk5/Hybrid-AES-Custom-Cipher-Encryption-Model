"""Shared fixtures.

Nearly every test uses :data:`cipherx.params.FAST_TEST`, whose Scrypt cost is
``N = 2**8`` rather than ``2**16``. The paper's parameters take roughly half a
second per derivation, which would make a few hundred round-trips unbearable.
The structural layer -- which is what these tests actually exercise -- is
byte-identical across profiles, so nothing is lost. Tests that genuinely need
the paper's cost are marked ``@pytest.mark.slow``.
"""

from __future__ import annotations

import random
import string

import pytest

from cipherx import CipherX
from cipherx.params import FAST_TEST, StructuralParams

PASSPHRASE = "test-passphrase"
STRUCTURAL_KEY = "test-structural-key"

#: Keys chosen to span the behaviour that broke the reference implementation.
#: ``akanksh-super-unique-key`` is its shipped default, under which the
#: trailing-'X' bug never fires; the rest trigger it at 6.5% to 69%.
PROBE_KEYS = [
    "akanksh-super-unique-key",
    "my-secret-m-key",
    "demo-key-2025",
    "MMMM",
    "Z",
    "a",
]


@pytest.fixture
def cipher() -> CipherX:
    return CipherX(FAST_TEST)


@pytest.fixture
def params() -> StructuralParams:
    return StructuralParams()


@pytest.fixture
def rng() -> random.Random:
    """Seeded RNG, so a failure reproduces exactly."""
    return random.Random(20251015)


def random_letters(rng: random.Random, lo: int, hi: int) -> str:
    return "".join(rng.choice(string.ascii_uppercase) for _ in range(rng.randint(lo, hi)))


def random_bytes(rng: random.Random, lo: int, hi: int) -> bytes:
    return bytes(rng.getrandbits(8) for _ in range(rng.randint(lo, hi)))
