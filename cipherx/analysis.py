"""Measurement tools for the paper's evaluation (paper Sections 6 and 7).

Everything here is descriptive statistics over ciphertext. These are useful
sanity checks and they are what the paper reports, but none of them is a
security proof -- a cipher can score perfectly on all of them and still be
broken. ``docs/SECURITY.md`` is explicit about what they do and do not show.

One claim deserves care. The paper reports entropy of 5.23-5.33 bits/char and
contrasts it with ``log2(26) ~ 4.70``, describing the excess as evidence of
obfuscation strength. The excess is real but its cause is mundane: the noise
stage injects characters from a 16-symbol pool disjoint from ``A-Z``, widening
the alphabet from 26 to 42 symbols. The ceiling for the *actual* alphabet is
``log2(42) ~ 5.39``, not 4.70. :func:`entropy_report` reports both ceilings so
the comparison is not misleading.
"""

from __future__ import annotations

import math
import time
from collections import Counter
from dataclasses import dataclass, field
from statistics import mean
from typing import Callable, Dict, List, Sequence

__all__ = [
    "shannon_entropy",
    "max_entropy",
    "index_of_coincidence",
    "chi_square_uniform",
    "expansion_ratio",
    "avalanche_ratio",
    "EntropyReport",
    "entropy_report",
    "TimingResult",
    "time_callable",
]


def shannon_entropy(text: str) -> float:
    """Shannon entropy in bits per character, ``H = -sum p_i log2 p_i``."""
    if not text:
        return 0.0
    n = len(text)
    return -sum(
        (c / n) * math.log2(c / n) for c in Counter(text).values()
    )


def max_entropy(symbols: int) -> float:
    """Entropy ceiling for an alphabet of ``symbols`` distinct characters."""
    return math.log2(symbols) if symbols > 0 else 0.0


def index_of_coincidence(text: str) -> float:
    """Probability that two characters drawn without replacement match.

    Uniform random text over an alphabet of size ``k`` gives ``~1/k``
    (``0.038`` for 26 letters); English prose gives about ``0.067``. A value
    near the uniform figure means no exploitable single-character bias.
    """
    n = len(text)
    if n < 2:
        return 0.0
    return sum(c * (c - 1) for c in Counter(text).values()) / (n * (n - 1))


def chi_square_uniform(text: str) -> float:
    """Chi-square statistic against a uniform distribution over the observed alphabet.

    Lower is flatter. Compare against the chi-square distribution with
    ``len(set(text)) - 1`` degrees of freedom.
    """
    if not text:
        return 0.0
    counts = Counter(text)
    expected = len(text) / len(counts)
    return sum((c - expected) ** 2 / expected for c in counts.values())


def expansion_ratio(plaintext: str, ciphertext: str) -> float:
    """Ciphertext length divided by plaintext length (0.0 for empty input)."""
    return len(ciphertext) / len(plaintext) if plaintext else 0.0


def avalanche_ratio(a: str, b: str) -> float:
    """Fraction of differing characters over the shared prefix of two ciphertexts.

    Encrypt two plaintexts differing in one character and compare: a healthy
    result sits near ``1 - 1/k`` for a ``k``-symbol alphabet (about 0.96 here),
    meaning a one-character change rewrites essentially the whole output.

    Note that CipherX uses a fresh random salt and nonce per call, so two
    encryptions of the *same* plaintext already differ completely. This metric
    therefore measures the pipeline's diffusion, not the AEAD's -- to isolate
    the structural layer, pin the salt and nonce.
    """
    if not a or not b:
        return 0.0
    shared = min(len(a), len(b))
    differing = sum(1 for i in range(shared) if a[i] != b[i])
    differing += abs(len(a) - len(b))
    return differing / max(len(a), len(b))


@dataclass
class EntropyReport:
    """Entropy measurements for one ciphertext."""

    length: int
    distinct_symbols: int
    entropy: float
    #: Ceiling for the alphabet actually present in this ciphertext.
    ceiling_observed: float
    #: ``log2(26)``, the figure the paper compares against.
    ceiling_base26: float = math.log2(26)
    index_of_coincidence: float = 0.0
    chi_square: float = 0.0

    @property
    def vs_base26_pct(self) -> float:
        """Percentage excess over ``log2(26)`` -- the paper's headline number."""
        return 100.0 * (self.entropy - self.ceiling_base26) / self.ceiling_base26

    @property
    def utilisation_pct(self) -> float:
        """Entropy as a percentage of the ceiling for the real alphabet."""
        return 100.0 * self.entropy / self.ceiling_observed if self.ceiling_observed else 0.0

    def __str__(self) -> str:
        return (
            f"len={self.length:<7} symbols={self.distinct_symbols:<3} "
            f"H={self.entropy:.3f} bits/char  "
            f"vs log2(26)={self.vs_base26_pct:+.1f}%  "
            f"of max({self.distinct_symbols})={self.utilisation_pct:.1f}%"
        )


def entropy_report(ciphertext: str) -> EntropyReport:
    """Full entropy / uniformity report for one ciphertext."""
    distinct = len(set(ciphertext))
    return EntropyReport(
        length=len(ciphertext),
        distinct_symbols=distinct,
        entropy=shannon_entropy(ciphertext),
        ceiling_observed=max_entropy(distinct),
        index_of_coincidence=index_of_coincidence(ciphertext),
        chi_square=chi_square_uniform(ciphertext),
    )


@dataclass
class TimingResult:
    """Wall-clock timings over repeated runs, in milliseconds."""

    label: str
    samples: List[float] = field(default_factory=list)

    @property
    def mean_ms(self) -> float:
        return mean(self.samples) if self.samples else 0.0

    @property
    def min_ms(self) -> float:
        return min(self.samples) if self.samples else 0.0

    @property
    def max_ms(self) -> float:
        return max(self.samples) if self.samples else 0.0

    def __str__(self) -> str:
        return (
            f"{self.label:<22} mean={self.mean_ms:7.1f} ms  "
            f"min={self.min_ms:7.1f}  max={self.max_ms:7.1f}  n={len(self.samples)}"
        )


def time_callable(label: str, fn: Callable[[], object], repeats: int = 3) -> TimingResult:
    """Time ``fn`` over ``repeats`` runs using a monotonic performance counter."""
    result = TimingResult(label=label)
    for _ in range(max(1, repeats)):
        start = time.perf_counter()
        fn()
        result.samples.append((time.perf_counter() - start) * 1000.0)
    return result


def symbol_histogram(text: str) -> Dict[str, int]:
    """Character frequency table, most common first."""
    return dict(Counter(text).most_common())


def summarise(ciphertexts: Sequence[str]) -> Dict[str, float]:
    """Aggregate entropy statistics across several ciphertexts."""
    if not ciphertexts:
        return {}
    reports = [entropy_report(c) for c in ciphertexts]
    entropies = [r.entropy for r in reports]
    return {
        "samples": len(reports),
        "entropy_mean": mean(entropies),
        "entropy_min": min(entropies),
        "entropy_max": max(entropies),
        "ioc_mean": mean(r.index_of_coincidence for r in reports),
    }
