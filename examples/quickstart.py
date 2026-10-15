#!/usr/bin/env python3
"""Worked examples of the CipherX API.

    python examples/quickstart.py

Uses the FAST_TEST profile so it finishes quickly. Real code should use the
default PAPER profile, or STRICT for anything that matters.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cipherx import CipherX, CipherXError, IntegrityError  # noqa: E402
from cipherx.analysis import entropy_report, expansion_ratio  # noqa: E402
from cipherx.params import FAST_TEST, STRICT  # noqa: E402

PASSPHRASE = "aes-passphrase"
KEY = "structural-key"


def basic_round_trip() -> None:
    print("1. Basic round trip")
    cipher = CipherX(FAST_TEST)
    message = "sensor=1;temp=23.5;ts=1699999999"

    ciphertext = cipher.encrypt(message, PASSPHRASE, KEY)
    recovered = cipher.decrypt(ciphertext, PASSPHRASE, KEY)

    print(f"   plaintext  {message}")
    print(f"   ciphertext {ciphertext[:60]}...")
    print(f"   recovered  {recovered}")
    print(f"   match      {recovered == message}\n")


def repetitive_telemetry() -> None:
    """The motivating case: identical payloads must not look identical."""
    print("2. Repetitive IoT telemetry")
    cipher = CipherX(FAST_TEST)
    message = "status=OK;battery=98;" * 20

    a = cipher.encrypt(message, PASSPHRASE, KEY)
    b = cipher.encrypt(message, PASSPHRASE, KEY)

    letters = [i for i in range(min(len(a), len(b))) if a[i].isalpha() and b[i].isalpha()]
    agree = sum(1 for i in letters if a[i] == b[i]) / len(letters)

    print(f"   same plaintext encrypted twice")
    print(f"   payload positions agreeing: {agree:.1%} (chance is 3.8%)")
    print(f"   identical ciphertexts?      {a == b}\n")


def tamper_detection() -> None:
    print("3. Tamper detection")
    cipher = CipherX(FAST_TEST)
    ciphertext = cipher.encrypt("transfer 1000 to account 4471", PASSPHRASE, KEY)

    flipped = ("B" if ciphertext[5] != "B" else "C")
    tampered = ciphertext[:5] + flipped + ciphertext[6:]

    try:
        cipher.decrypt(tampered, PASSPHRASE, KEY)
        print("   ERROR: tampering went undetected\n")
    except IntegrityError as exc:
        print(f"   one character changed -> {type(exc).__name__}")
        print(f"   {exc}\n")


def wrong_keys() -> None:
    print("4. Wrong keys fail closed")
    cipher = CipherX(FAST_TEST)
    ciphertext = cipher.encrypt("confidential", PASSPHRASE, KEY)

    for label, args in [
        ("wrong passphrase", ("wrong-passphrase", KEY)),
        ("wrong structural key", (PASSPHRASE, "wrong-key")),
    ]:
        try:
            cipher.decrypt(ciphertext, *args)
            print(f"   ERROR: {label} was accepted")
        except CipherXError as exc:
            print(f"   {label:<22} -> {type(exc).__name__}")
    print()


def measure() -> None:
    print("5. Entropy and expansion")
    cipher = CipherX(FAST_TEST)
    for size in (12, 100, 1000):
        message = "A" * size
        ciphertext = cipher.encrypt(message, PASSPHRASE, KEY)
        report = entropy_report(ciphertext)
        print(f"   {size:>5} chars -> {len(ciphertext):>5} "
              f"({expansion_ratio(message, ciphertext):>5.2f}x)  "
              f"H={report.entropy:.3f} bits/char over {report.distinct_symbols} symbols")
    print()


def hardened_profile() -> None:
    print("6. STRICT profile (full-width outer tag)")
    strict = CipherX(STRICT.replace(scrypt=FAST_TEST.scrypt))
    paper = CipherX(FAST_TEST.replace(tag_hex_len=16))
    message = "profile comparison"

    print(f"   PAPER  tag {paper.profile.tag_bits:>3} bits -> "
          f"{len(paper.encrypt(message, PASSPHRASE, KEY))} chars")
    print(f"   STRICT tag {strict.profile.tag_bits:>3} bits -> "
          f"{len(strict.encrypt(message, PASSPHRASE, KEY))} chars")
    print("   Use STRICT for anything real; see docs/SECURITY.md Finding 2.\n")


if __name__ == "__main__":
    print("CipherX examples\n" + "=" * 50 + "\n")
    basic_round_trip()
    repetitive_telemetry()
    tamper_detection()
    wrong_keys()
    measure()
    hardened_profile()
