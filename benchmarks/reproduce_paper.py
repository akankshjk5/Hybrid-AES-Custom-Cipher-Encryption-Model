#!/usr/bin/env python3
"""Regenerate the paper's Table I (entropy) and Table II (performance).

Run from the repository root::

    python benchmarks/reproduce_paper.py
    python benchmarks/reproduce_paper.py --repeats 5 --markdown

Uses the ``PAPER`` profile, so Scrypt runs at ``N = 2**16, r = 8, p = 2`` and
each row costs roughly a second. That cost is the point: the paper's headline
finding is that runtime is flat in message size because the memory-hard KDF
dominates everything else, and ``--breakdown`` shows that directly.

Absolute milliseconds will not match the paper -- different CPU, different
Python, different ``cryptography`` build. What should reproduce is the
*shape*: near-constant total time across three orders of magnitude of input,
entropy above ``log2(26)``, and expansion falling from about 7x to about 2x.
"""

from __future__ import annotations

import argparse
import statistics
import sys
import time
from pathlib import Path
from typing import List, NamedTuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cipherx import CipherX  # noqa: E402
from cipherx.aead import seal  # noqa: E402
from cipherx.analysis import entropy_report, expansion_ratio  # noqa: E402
from cipherx.params import PAPER  # noqa: E402

PASSPHRASE = "aes-strong-passphrase"
STRUCTURAL_KEY = "akanksh-super-unique-key"

#: The six rows of the paper's Table II.
PAPER_SIZES = [12, 71, 37, 44, 1000, 10000]

#: Paper Table II, for side-by-side comparison.
PAPER_TABLE_II = {
    12: (556, 525, 136),
    71: (496, 497, 256),
    37: (428, 466, 190),
    44: (447, 480, 202),
    1000: (470, 462, 2158),
    10000: (584, 499, 20536),
}


class Row(NamedTuple):
    size: int
    enc_ms: float
    dec_ms: float
    cipher_len: int
    expansion: float
    entropy: float


def _time(fn, repeats: int) -> float:
    """Median wall-clock milliseconds over ``repeats`` runs.

    Median, not mean: a single GC pause or scheduler hiccup should not move
    the number.
    """
    samples = []
    for _ in range(repeats):
        start = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - start) * 1000.0)
    return statistics.median(samples)


def measure(size: int, repeats: int) -> Row:
    cipher = CipherX(PAPER)
    message = "A" * size
    ciphertext = cipher.encrypt(message, PASSPHRASE, STRUCTURAL_KEY)
    return Row(
        size=size,
        enc_ms=_time(lambda: cipher.encrypt(message, PASSPHRASE, STRUCTURAL_KEY), repeats),
        dec_ms=_time(lambda: cipher.decrypt(ciphertext, PASSPHRASE, STRUCTURAL_KEY), repeats),
        cipher_len=len(ciphertext),
        expansion=expansion_ratio(message, ciphertext),
        entropy=entropy_report(ciphertext).entropy,
    )


def print_table_ii(rows: List[Row], markdown: bool) -> None:
    print("\nTable II -- Performance metrics")
    print("(paper figures in parentheses, measured on the authors' machine)\n")
    if markdown:
        print("| Input | Enc (ms) | Dec (ms) | Cipher len | Expansion | Paper enc/dec/len |")
        print("|------:|---------:|---------:|-----------:|----------:|------------------:|")
        for r in rows:
            pe, pd, pl = PAPER_TABLE_II.get(r.size, ("-", "-", "-"))
            print(f"| {r.size:,} | {r.enc_ms:.1f} | {r.dec_ms:.1f} | {r.cipher_len:,} "
                  f"| {r.expansion:.2f}x | {pe}/{pd}/{pl} |")
        return

    head = f"{'input':>8} {'enc ms':>9} {'dec ms':>9} {'ct len':>9} {'expand':>8}   paper enc/dec/len"
    print(head)
    print("-" * len(head))
    for r in rows:
        pe, pd, pl = PAPER_TABLE_II.get(r.size, ("-", "-", "-"))
        print(f"{r.size:>8,} {r.enc_ms:>9.1f} {r.dec_ms:>9.1f} {r.cipher_len:>9,} "
              f"{r.expansion:>7.2f}x   {pe}/{pd}/{pl}")


def print_table_i(rows: List[Row], markdown: bool) -> None:
    import math
    log2_26 = math.log2(26)
    print("\nTable I -- Entropy of hybrid ciphertext outputs\n")
    if markdown:
        print("| Sample | Entropy (bits/char) | vs log2(26) |")
        print("|-------:|--------------------:|------------:|")
        for i, r in enumerate(rows, 1):
            print(f"| {i} | {r.entropy:.2f} | {100*(r.entropy-log2_26)/log2_26:+.1f}% |")
        mean = statistics.mean(r.entropy for r in rows)
        print(f"| **Average** | **{mean:.2f}** | **{100*(mean-log2_26)/log2_26:+.1f}%** |")
        return

    print(f"{'sample':>7} {'entropy':>9} {'vs log2(26)':>13}")
    print("-" * 31)
    for i, r in enumerate(rows, 1):
        print(f"{i:>7} {r.entropy:>9.2f} {100*(r.entropy-log2_26)/log2_26:>12.1f}%")
    mean = statistics.mean(r.entropy for r in rows)
    print("-" * 31)
    print(f"{'average':>7} {mean:>9.2f} {100*(mean-log2_26)/log2_26:>12.1f}%")
    print(f"\npaper reports 5.23-5.33, average 5.28 (+12.4%)")


def print_breakdown(repeats: int) -> None:
    """Show that Scrypt, not the structural layer, dominates the clock."""
    print("\nWhere the time goes (10,000-character input)\n")
    message = "A" * 10000
    cipher = CipherX(PAPER)

    total = _time(lambda: cipher.encrypt(message, PASSPHRASE, STRUCTURAL_KEY), repeats)
    kdf_and_aead = _time(
        lambda: seal(message.encode(), PASSPHRASE, PAPER.scrypt), repeats
    )
    structural = total - kdf_and_aead

    print(f"  Scrypt + AES-GCM   {kdf_and_aead:7.1f} ms  ({100*kdf_and_aead/total:4.1f}%)")
    print(f"  Base-26 + layers   {structural:7.1f} ms  ({100*structural/total:4.1f}%)")
    print(f"  total              {total:7.1f} ms")
    print(f"\n  Scrypt working set ~{PAPER.scrypt.approx_memory_bytes // (1024*1024)} MB "
          f"(N=2^{PAPER.scrypt.n.bit_length()-1}, r={PAPER.scrypt.r}, p={PAPER.scrypt.p})")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repeats", type=int, default=3, help="runs per measurement")
    parser.add_argument("--sizes", type=int, nargs="+", default=PAPER_SIZES)
    parser.add_argument("--markdown", action="store_true", help="emit Markdown tables")
    parser.add_argument("--breakdown", action="store_true", default=True,
                        help="show the Scrypt / structural split")
    args = parser.parse_args()

    print("CipherX -- reproducing the published tables")
    print(f"profile=paper  repeats={args.repeats}  python={sys.version.split()[0]}")

    rows = []
    for size in args.sizes:
        print(f"  measuring {size:,} characters ...", end="", flush=True)
        rows.append(measure(size, args.repeats))
        print(" done")

    print_table_ii(rows, args.markdown)
    print_table_i(rows, args.markdown)
    if args.breakdown:
        print_breakdown(args.repeats)

    enc = [r.enc_ms for r in rows]
    print(f"\nFlatness check: encryption spans {min(enc):.0f}-{max(enc):.0f} ms "
          f"across {min(args.sizes):,}-{max(args.sizes):,} characters "
          f"({max(enc)/min(enc):.2f}x spread over a {max(args.sizes)//max(1,min(args.sizes))}x "
          f"input range).")
    print("The paper's linear-time claim rests on this: the memory-hard KDF is a")
    print("fixed cost that swamps the per-character work.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
