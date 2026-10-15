"""Command-line interface: ``python -m cipherx``.

Subcommands::

    encrypt    encrypt a message or file
    decrypt    decrypt a ciphertext or file
    entropy    entropy / uniformity report for a ciphertext
    benchmark  timing and expansion across input sizes
    selftest   round-trip, tamper and edge-case checks

Keys are read from the environment (``CIPHERX_PASSPHRASE``,
``CIPHERX_KEY``) or prompted for without echo. They are deliberately *not*
accepted as command-line flags: argv is visible to every process on the
machine and lands in shell history.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from typing import List, Optional, Sequence

from . import __version__
from .analysis import entropy_report, expansion_ratio, time_callable
from .exceptions import CipherXError
from .hybrid import CipherX
from .params import FAST_TEST, PAPER, STRICT, Profile

ENV_PASSPHRASE = "CIPHERX_PASSPHRASE"
ENV_KEY = "CIPHERX_KEY"

_PROFILES = {"paper": PAPER, "strict": STRICT, "fast-test": FAST_TEST}


def _resolve_profile(name: str) -> Profile:
    return _PROFILES[name]


def _get_secret(env_var: str, prompt: str, *, confirm: bool = False) -> str:
    """Read a secret from the environment, else prompt without echo."""
    value = os.environ.get(env_var)
    if value:
        return value
    if not sys.stdin.isatty():
        raise SystemExit(
            f"error: {env_var} is not set and stdin is not a terminal, so it "
            f"cannot be prompted for. Set {env_var} and retry."
        )
    value = getpass.getpass(prompt)
    if not value:
        raise SystemExit("error: empty secret")
    if confirm and getpass.getpass("Confirm: ") != value:
        raise SystemExit("error: secrets do not match")
    return value


def _read_input(text: Optional[str], path: Optional[str]) -> str:
    if text is not None:
        return text
    if path:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    data = sys.stdin.read()
    if not data:
        raise SystemExit("error: no input given (use --text, --in, or stdin)")
    return data


def _write_output(content: str, path: Optional[str]) -> None:
    if path:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        print(f"wrote {len(content)} characters to {path}", file=sys.stderr)
    else:
        print(content)


# ----------------------------------------------------------------------
# commands
# ----------------------------------------------------------------------

def cmd_encrypt(args: argparse.Namespace) -> int:
    message = _read_input(args.text, args.infile)
    cipher = CipherX(_resolve_profile(args.profile))
    passphrase = _get_secret(ENV_PASSPHRASE, "AES passphrase: ", confirm=args.confirm)
    key = _get_secret(ENV_KEY, "Structural key: ", confirm=args.confirm)

    ciphertext = cipher.encrypt(message, passphrase, key)
    _write_output(ciphertext, args.outfile)

    if args.stats:
        rep = entropy_report(ciphertext)
        print(
            f"\nplaintext  {len(message)} chars\n"
            f"ciphertext {len(ciphertext)} chars "
            f"({expansion_ratio(message, ciphertext):.2f}x expansion)\n{rep}",
            file=sys.stderr,
        )
    return 0


def cmd_decrypt(args: argparse.Namespace) -> int:
    ciphertext = _read_input(args.text, args.infile).strip()
    cipher = CipherX(_resolve_profile(args.profile))
    passphrase = _get_secret(ENV_PASSPHRASE, "AES passphrase: ")
    key = _get_secret(ENV_KEY, "Structural key: ")

    try:
        plaintext = cipher.decrypt(ciphertext, passphrase, key)
    except CipherXError as exc:
        print(f"decryption failed: {exc}", file=sys.stderr)
        return 1
    _write_output(plaintext, args.outfile)
    return 0


def cmd_entropy(args: argparse.Namespace) -> int:
    text = _read_input(args.text, args.infile).strip()
    rep = entropy_report(text)
    print(f"length               {rep.length}")
    print(f"distinct symbols     {rep.distinct_symbols}")
    print(f"Shannon entropy      {rep.entropy:.4f} bits/char")
    print(f"ceiling log2(26)     {rep.ceiling_base26:.4f}  -> {rep.vs_base26_pct:+.1f}%")
    print(f"ceiling log2({rep.distinct_symbols:<2})    {rep.ceiling_observed:.4f}  "
          f"-> {rep.utilisation_pct:.1f}% utilised")
    print(f"index of coincidence {rep.index_of_coincidence:.5f}  "
          f"(uniform over {rep.distinct_symbols} = {1/rep.distinct_symbols:.5f})")
    print(f"chi-square           {rep.chi_square:.2f} "
          f"(df = {rep.distinct_symbols - 1})")
    return 0


def cmd_benchmark(args: argparse.Namespace) -> int:
    cipher = CipherX(_resolve_profile(args.profile))
    passphrase, key = "benchmark-passphrase", "benchmark-structural-key"
    sizes: List[int] = args.sizes or [12, 37, 71, 1000, 10000]

    print(f"profile={args.profile}  repeats={args.repeats}  "
          f"scrypt N=2^{cipher.profile.scrypt.n.bit_length()-1} "
          f"r={cipher.profile.scrypt.r} p={cipher.profile.scrypt.p}\n")
    header = f"{'size':>8} {'enc (ms)':>10} {'dec (ms)':>10} {'ct len':>8} {'expand':>8} {'H':>7}"
    print(header)
    print("-" * len(header))

    for size in sizes:
        message = "A" * size
        enc = time_callable("enc", lambda: cipher.encrypt(message, passphrase, key), args.repeats)
        ciphertext = cipher.encrypt(message, passphrase, key)
        dec = time_callable("dec", lambda: cipher.decrypt(ciphertext, passphrase, key), args.repeats)
        rep = entropy_report(ciphertext)
        print(f"{size:>8} {enc.mean_ms:>10.1f} {dec.mean_ms:>10.1f} "
              f"{len(ciphertext):>8} {expansion_ratio(message, ciphertext):>7.2f}x "
              f"{rep.entropy:>7.3f}")
    return 0


def cmd_selftest(args: argparse.Namespace) -> int:
    profile = _resolve_profile(args.profile)
    cipher = CipherX(profile)
    passphrase, key = "selftest-passphrase", "selftest-structural-key"
    failures = 0

    cases = [
        ("empty string", ""),
        ("single char", "A"),
        ("ends in X", "XXXXXXXXXXXX"),
        ("ascii phrase", "the quick brown fox jumps over the lazy dog"),
        ("unicode", "temperature 23.5C — café ☕"),
        ("repetitive iot", "sensor=1;value=42;" * 40),
        ("1 kB", "L" * 1000),
    ]
    for label, message in cases:
        try:
            ok = cipher.decrypt(cipher.encrypt(message, passphrase, key), passphrase, key) == message
        except CipherXError as exc:
            ok = False
            label = f"{label} ({exc})"
        print(f"  [{'pass' if ok else 'FAIL'}] round-trip: {label}")
        failures += not ok

    ciphertext = cipher.encrypt("integrity probe", passphrase, key)
    checks = [
        ("wrong passphrase", lambda: cipher.decrypt(ciphertext, "wrong", key)),
        ("wrong structural key", lambda: cipher.decrypt(ciphertext, passphrase, "wrong")),
        ("truncated", lambda: cipher.decrypt(ciphertext[:-1], passphrase, key)),
        ("flipped char", lambda: cipher.decrypt(
            ("B" if ciphertext[0] != "B" else "C") + ciphertext[1:], passphrase, key)),
    ]
    for label, fn in checks:
        try:
            fn()
            rejected = False
        except CipherXError:
            rejected = True
        print(f"  [{'pass' if rejected else 'FAIL'}] rejected: {label}")
        failures += not rejected

    print(f"\n{'all checks passed' if not failures else f'{failures} check(s) FAILED'}")
    return 1 if failures else 0


# ----------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cipherx",
        description="Hybrid AES-256-GCM + custom structural cipher with Base-26 encoding.",
        epilog=f"Secrets are read from {ENV_PASSPHRASE} and {ENV_KEY}, "
               "or prompted for without echo.",
    )
    parser.add_argument("--version", action="version", version=f"cipherx {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--text", help="input given directly on the command line")
        p.add_argument("--in", dest="infile", help="read input from this file")
        p.add_argument("--out", dest="outfile", help="write output to this file")
        p.add_argument("--profile", choices=sorted(_PROFILES), default="paper",
                       help="parameter profile (default: paper)")

    p_enc = sub.add_parser("encrypt", help="encrypt a message")
    add_common(p_enc)
    p_enc.add_argument("--stats", action="store_true", help="print entropy and expansion")
    p_enc.add_argument("--confirm", action="store_true", help="confirm prompted secrets")
    p_enc.set_defaults(func=cmd_encrypt)

    p_dec = sub.add_parser("decrypt", help="decrypt a ciphertext")
    add_common(p_dec)
    p_dec.set_defaults(func=cmd_decrypt)

    p_ent = sub.add_parser("entropy", help="entropy report for a ciphertext")
    p_ent.add_argument("--text")
    p_ent.add_argument("--in", dest="infile")
    p_ent.set_defaults(func=cmd_entropy)

    p_bench = sub.add_parser("benchmark", help="timing and expansion across sizes")
    p_bench.add_argument("--sizes", type=int, nargs="+", help="plaintext sizes in characters")
    p_bench.add_argument("--repeats", type=int, default=3)
    p_bench.add_argument("--profile", choices=sorted(_PROFILES), default="paper")
    p_bench.set_defaults(func=cmd_benchmark)

    p_self = sub.add_parser("selftest", help="run round-trip and tamper checks")
    p_self.add_argument("--profile", choices=sorted(_PROFILES), default="fast-test")
    p_self.set_defaults(func=cmd_selftest)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except CipherXError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
