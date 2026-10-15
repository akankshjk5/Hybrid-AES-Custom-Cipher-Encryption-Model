"""Nonlinear alphabet mapping (paper Sections 5.5.F and 5.6.1).

The paper fixes a deliberately non-monotonic letter-to-index table::

    A B C D E F G H I J  ->   9  8  7  6  5  4  3  2  1  0   (descending)
    K L M N O P Q R S T  ->  10 11 12 13 14 15 16 17 18 19   (ascending)
    U V W X Y Z          ->  25 24 23 22 21 20               (descending)

Three runs with alternating direction, so ordinary alphabetical adjacency
carries no ordering information into the numeric domain. The table is a
bijection onto ``{0..25}``, which is what makes the stage invertible.

On top of the table each character also absorbs its **position** and a value
cycled from the shift pattern, giving a position-dependent substitution rather
than a fixed monoalphabetic one.

Where this departs from the reference implementation
----------------------------------------------------
The original code applied the mapping inside a per-word loop and took the shift
from the *word* index. Its input is a Base-26 string, which contains no spaces,
so there was always exactly one word: only ``shift_pattern[0]`` was ever used
and the other three values were dead. Here the shift is cycled over character
position, so the whole pattern participates. See ``docs/PAPER_MAPPING.md``.
"""

from __future__ import annotations

from typing import Dict, Sequence

from .exceptions import DecodingError

__all__ = ["BASE_MAP", "INVERSE_MAP", "forward_map", "inverse_map"]


def _build_base_map() -> Dict[str, int]:
    mapping: Dict[str, int] = {}
    for letter, value in zip("ABCDEFGHIJ", range(9, -1, -1)):
        mapping[letter] = value
    for letter, value in zip("KLMNOPQRST", range(10, 20)):
        mapping[letter] = value
    for letter, value in zip("UVWXYZ", range(25, 19, -1)):
        mapping[letter] = value
    return mapping


#: Letter -> nonlinear index; a bijection onto ``{0..25}``.
BASE_MAP: Dict[str, int] = _build_base_map()

#: Residue (1..26) -> letter. Keyed on ``((v - 1) % 26) + 1`` so that value 0
#: folds onto 26 and the table stays a bijection.
INVERSE_MAP: Dict[int, str] = {((v - 1) % 26) + 1: ch for ch, v in BASE_MAP.items()}

if len(BASE_MAP) != 26 or len(INVERSE_MAP) != 26:  # pragma: no cover - structural invariant
    raise RuntimeError("BASE_MAP must be a bijection on the 26-letter alphabet")


def forward_map(text: str, shift_pattern: Sequence[int]) -> str:
    """Apply the nonlinear map with position- and pattern-dependent offsets.

    ``out[i] = letter(BASE_MAP[text[i]] + (i + 1) + shift_pattern[i % width])``

    Args:
        text: uppercase ``A-Z`` only.
        shift_pattern: cycled over character position.

    Raises:
        DecodingError: if ``text`` contains anything outside ``A-Z``.
    """
    width = len(shift_pattern)
    out = []
    append = out.append
    for i, ch in enumerate(text):
        value = BASE_MAP.get(ch)
        if value is None:
            raise DecodingError(f"non-alphabetic character {ch!r} at offset {i}")
        n = value + (i + 1) + shift_pattern[i % width]
        append(chr(64 + ((n - 1) % 26) + 1))
    return "".join(out)


def inverse_map(text: str, shift_pattern: Sequence[int]) -> str:
    """Exact inverse of :func:`forward_map`."""
    width = len(shift_pattern)
    out = []
    append = out.append
    for i, ch in enumerate(text):
        if not ("A" <= ch <= "Z"):
            raise DecodingError(f"non-alphabetic character {ch!r} at offset {i}")
        n = ord(ch) - 64  # 1..26
        base = ((n - (i + 1) - shift_pattern[i % width] - 1) % 26) + 1
        append(INVERSE_MAP[base])
    return "".join(out)
