#!/usr/bin/env python3
"""
final_optimized_hybrid_cipher.py

Optimized, well-documented, production-minded academic implementation:
- Same algorithm as your IEEE paper
- Clearer structure, typed functions, docstrings
- Small safety improvements (hmac.compare_digest for integrity check)
- Argument parsing for demo/CLI usage
"""

import os
import hmac
import struct
import hashlib
import argparse
from typing import List
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ----- Constants -----
SRYPT_N = 2**16
SRYPT_R = 8
SRYPT_P = 2
AES_KEY_LEN = 32
SALT_LEN = 16
NONCE_LEN = 12
HMAC_TRUNC_HEX = 16  # hex chars appended to output
BLOCK_SIZE_DEFAULT = 6
SHIFT_PATTERN_DEFAULT = [2, 3, 5, 7]

# ----- Utilities -----
def _alpha_to_num(a: str) -> int:
    return ord(a) - 64

def _num_to_alpha(n: int) -> str:
    n = ((n - 1) % 26) + 1
    return chr(64 + n)

def _rot_right(s: str, k: int) -> str:
    if not s:
        return s
    k %= len(s)
    return s[-k:] + s[:-k]

def _rot_left(s: str, k: int) -> str:
    if not s:
        return s
    k %= len(s)
    return s[k:] + s[:k]

# ----- Base mapping (nonlinear mapping used in paper) -----
def build_base_mapping():
    mapping = {}
    letters1 = "ABCDEFGHIJ"; nums1 = list(range(9, -1, -1))
    for l, n in zip(letters1, nums1):
        mapping[l] = n
    letters2 = "KLMNOPQRST"; nums2 = list(range(10, 20))
    for l, n in zip(letters2, nums2):
        mapping[l] = n
    letters3 = "UVWXYZ"; nums3 = list(range(25, 19, -1))
    for l, n in zip(letters3, nums3):
        mapping[l] = n
    return mapping

BASE_MAP = build_base_mapping()
WRAP_INV = {((v - 1) % 26) + 1: ch for ch, v in BASE_MAP.items()}

# ----- Deterministic keyed CSPRNG using HKDF + HMAC-SHA256 -----
class KeyedCSPRNG:
    """Deterministic CSPRNG derived from key_material and context.
    Produces pseudo-random bytes using HMAC-SHA256 blocks.
    """
    def __init__(self, key_material: bytes, context: bytes = b""):
        self.key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=context
        ).derive(key_material)
        self.counter = 0
        self.buf = b""
        self.pos = 0

    def _refill(self, need: int):
        chunks = []
        while sum(len(x) for x in chunks) < need:
            self.counter += 1
            block = hmac.new(self.key, struct.pack(">Q", self.counter), hashlib.sha256).digest()
            chunks.append(block)
        self.buf = b"".join(chunks)
        self.pos = 0

    def bytes(self, n: int) -> bytes:
        if self.pos + n > len(self.buf):
            self._refill(max(n, 64))
        out = self.buf[self.pos:self.pos + n]
        self.pos += n
        return out

    def randint(self, a: int, b: int) -> int:
        span = b - a + 1
        while True:
            r = int.from_bytes(self.bytes(8), "big")
            m = (1 << 64) // span * span
            if r < m:
                return a + (r % span)

    def shuffle(self, items: list):
        for i in range(len(items) - 1, 0, -1):
            j = self.randint(0, i)
            items[i], items[j] = items[j], items[i]

# ----- Custom transformation layer -----
def _vigenerize(text: str, key: str, encrypt: bool) -> str:
    """Poly-alphabetic shift; preserves non-A-Z characters."""
    key = "".join(c for c in key.upper() if 'A' <= c <= 'Z')
    if not key:
        return text
    out, ki = [], 0
    for ch in text:
        if 'A' <= ch <= 'Z':
            k = _alpha_to_num(key[ki % len(key)]) - 1
            pi = _alpha_to_num(ch) - 1
            ci = (pi + k) % 26 if encrypt else (pi - k) % 26
            out.append(chr(65 + ci))
            ki += 1
        else:
            out.append(ch)
    return "".join(out)

def _map_word_to_letters(word: str, word_idx: int, shift_pattern: List[int]) -> str:
    """Map each letter via BASE_MAP, add position + shift, convert back to letter."""
    word_shift = shift_pattern[(word_idx - 1) % len(shift_pattern)]
    letters = []
    for pos, ch in enumerate(word, start=1):
        if 'A' <= ch <= 'Z':
            n = BASE_MAP[ch]
            n += pos + word_shift
            letters.append(_num_to_alpha(n))
    return "".join(letters)

def _keyed_word_transform(s: str, word_idx: int, rng_word: KeyedCSPRNG) -> str:
    """Odd word index -> reverse. Even -> rotate right by rng."""
    if word_idx % 2 == 1:
        return s[::-1]
    if not s:
        return s
    r = rng_word.randint(1, max(1, len(s)))
    return _rot_right(s, r)

def _insert_noise(text: str, rng: KeyedCSPRNG) -> str:
    """Insert deterministic noise characters to break frequency patterns."""
    noise_pool = list("0123456789@#$%&*")
    rng.shuffle(noise_pool)
    gap = rng.randint(3, 7)
    out, real_count, noise_idx = [], 0, 0
    for ch in text:
        out.append(ch)
        if 'A' <= ch <= 'Z':
            real_count += 1
            if real_count % gap == 0:
                out.append(noise_pool[noise_idx % len(noise_pool)])
                noise_idx += 1
    return "".join(out)

def _remove_noise(text: str, rng: KeyedCSPRNG) -> str:
    """Remove deterministic noise inserted by _insert_noise."""
    noise_pool = list("0123456789@#$%&*")
    rng.shuffle(noise_pool)
    gap = rng.randint(3, 7)
    out, real_count, i = [], 0, 0
    while i < len(text):
        ch = text[i]
        out.append(ch)
        if 'A' <= ch <= 'Z':
            real_count += 1
            if real_count % gap == 0 and i + 1 < len(text):
                i += 2
                continue
        i += 1
    return "".join(out)

def _block_shuffle(text: str, rng: KeyedCSPRNG, block_size: int) -> str:
    if block_size <= 0:
        return text
    padding = (-len(text)) % block_size
    text += 'X' * padding
    blocks = [text[i:i + block_size] for i in range(0, len(text), block_size)]
    idxs = list(range(len(blocks)))
    rng.shuffle(idxs)
    return ''.join(blocks[i] for i in idxs)

def _block_unshuffle(text: str, rng: KeyedCSPRNG, block_size: int) -> str:
    if block_size <= 0:
        return text
    blocks = [text[i:i + block_size] for i in range(0, len(text), block_size)]
    n = len(blocks)
    idxs = list(range(n))
    rng.shuffle(idxs)
    restored = [None] * n
    for i in range(n):
        restored[idxs[i]] = blocks[i]
    return ''.join(restored).rstrip('X')

def custom_encrypt(plaintext: str, custom_key: str,
                   shift_pattern: List[int] = None, block_size: int = BLOCK_SIZE_DEFAULT) -> str:
    """Full custom-layer encryption. Returns alphabet-only string + truncated HMAC tag."""
    if shift_pattern is None:
        shift_pattern = SHIFT_PATTERN_DEFAULT
    key_bytes = custom_key.encode('utf-8')
    rng_noise = KeyedCSPRNG(key_bytes, b"NOISE")
    rng_blocks = KeyedCSPRNG(key_bytes, b"BLOCKS")

    words = plaintext.upper().split()
    transformed = []
    for wi, w in enumerate(words, start=1):
        core = ''.join(ch for ch in w if 'A' <= ch <= 'Z')
        base_letters = _map_word_to_letters(core, wi, shift_pattern)
        rng_word = KeyedCSPRNG(key_bytes + struct.pack(">I", wi), b"WORDS")
        final_letters = _keyed_word_transform(base_letters, wi, rng_word)
        transformed.append(final_letters)

    stage = " ".join(transformed)
    stage = _vigenerize(stage, custom_key, encrypt=True)
    stage = _insert_noise(stage, rng_noise)
    stage = _block_shuffle(stage, rng_blocks, block_size)
    hmac_tag = hmac.new(key_bytes, stage.encode('utf-8'), hashlib.sha256).hexdigest()[:HMAC_TRUNC_HEX]
    return stage + hmac_tag

def custom_decrypt(ciphertext: str, custom_key: str,
                   shift_pattern: List[int] = None, block_size: int = BLOCK_SIZE_DEFAULT) -> str:
    """Reverse the custom-layer transformation. Verifies truncated HMAC."""
    if shift_pattern is None:
        shift_pattern = SHIFT_PATTERN_DEFAULT
    key_bytes = custom_key.encode('utf-8')
    tag = ciphertext[-HMAC_TRUNC_HEX:]
    ct_body = ciphertext[:-HMAC_TRUNC_HEX]
    expected = hmac.new(key_bytes, ct_body.encode('utf-8'), hashlib.sha256).hexdigest()[:HMAC_TRUNC_HEX]
    if not hmac.compare_digest(tag, expected):
        raise ValueError("Custom-layer HMAC verification failed.")

    rng_noise = KeyedCSPRNG(key_bytes, b"NOISE")
    rng_blocks = KeyedCSPRNG(key_bytes, b"BLOCKS")

    s = _block_unshuffle(ct_body, rng_blocks, block_size)
    s = _remove_noise(s, rng_noise)
    s = _vigenerize(s, custom_key, encrypt=False)

    words = s.split()
    restored = []
    for wi, w in enumerate(words, start=1):
        rng_word = KeyedCSPRNG(key_bytes + struct.pack(">I", wi), b"WORDS")
        if wi % 2 == 1:
            after = w[::-1]
        else:
            r = rng_word.randint(1, max(1, len(w))) if w else 0
            after = _rot_left(w, r)
        word_shift = shift_pattern[(wi - 1) % len(shift_pattern)]
        nums = [_alpha_to_num(ch) for ch in after]
        plain_chars = []
        for pos, n in enumerate(nums, start=1):
            base = ((n - pos - word_shift - 1) % 26) + 1
            ch_plain = WRAP_INV[base]
            plain_chars.append(ch_plain)
        restored.append("".join(plain_chars))
    return " ".join(restored)

# ----- AES-GCM + Base26 ----- 
def _kdf_scrypt(passphrase: str, salt: bytes) -> bytes:
    """Scrypt KDF with parameters from paper."""
    kdf = Scrypt(salt=salt, length=AES_KEY_LEN, n=SRYPT_N, r=SRYPT_R, p=SRYPT_P)
    return kdf.derive(passphrase.encode('utf-8'))

def aes_gcm_encrypt(plaintext: bytes, passphrase: str) -> bytes:
    """Return packed bytes: salt(16) || nonce(12) || AES-GCM(ct+tag)."""
    salt = os.urandom(SALT_LEN)
    key = _kdf_scrypt(passphrase, salt)
    nonce = os.urandom(NONCE_LEN)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return salt + nonce + ct

def aes_gcm_decrypt(packed: bytes, passphrase: str) -> bytes:
    if len(packed) < SALT_LEN + NONCE_LEN + 1:
        raise ValueError("Packed ciphertext too short.")
    salt = packed[:SALT_LEN]
    nonce = packed[SALT_LEN:SALT_LEN + NONCE_LEN]
    ct = packed[SALT_LEN + NONCE_LEN:]
    key = _kdf_scrypt(passphrase, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, associated_data=None)

def bytes_to_base26_with_header(b: bytes) -> str:
    blen = len(b)
    if blen >= 26**4:
        raise ValueError("data too large for 4-character header")
    L = blen
    header = ""
    for _ in range(4):
        header = chr(65 + (L % 26)) + header
        L //= 26
    if len(b) == 0:
        body = "A"
    else:
        n = int.from_bytes(b, 'big')
        body = ""
        while n > 0:
            n, r = divmod(n, 26)
            body = chr(65 + r) + body
    return header + body

def base26_with_header_to_bytes(s: str) -> bytes:
    header = s[:4]
    body = s[4:]
    blen = 0
    for ch in header:
        blen = blen * 26 + (ord(ch) - 65)
    if body == "A" and blen == 0:
        return b""
    n = 0
    for ch in body:
        n = n * 26 + (ord(ch) - 65)
    return n.to_bytes(blen, 'big')

# ----- High-level hybrid API -----
def hybrid_encrypt(plaintext: str, aes_passphrase: str, custom_key: str) -> str:
    aes_packed = aes_gcm_encrypt(plaintext.encode("utf-8"), aes_passphrase)
    base26 = bytes_to_base26_with_header(aes_packed)
    return custom_encrypt(base26, custom_key, shift_pattern=SHIFT_PATTERN_DEFAULT, block_size=BLOCK_SIZE_DEFAULT)

def hybrid_decrypt(ciphertext: str, aes_passphrase: str, custom_key: str) -> str:
    base26 = custom_decrypt(ciphertext, custom_key, shift_pattern=SHIFT_PATTERN_DEFAULT, block_size=BLOCK_SIZE_DEFAULT)
    aes_packed = base26_with_header_to_bytes(base26)
    pt_bytes = aes_gcm_decrypt(aes_packed, aes_passphrase)
    return pt_bytes.decode("utf-8", errors="strict")

# ----- CLI / Demo -----
def main():
    parser = argparse.ArgumentParser(description="Hybrid AES-GCM + Custom Cipher (paper-matched).")
    parser.add_argument("--mode", choices=["enc", "dec"], required=True, help="enc or dec")
    parser.add_argument("--aes-pass", required=False, default="aes-strong-passphrase", help="AES passphrase")
    parser.add_argument("--custom-key", required=False, default="akanksh-super-unique-key", help="Custom-layer key")
    parser.add_argument("--text", required=False, help="Plaintext (enc) or ciphertext (dec). If omitted, interactive input used.")
    args = parser.parse_args()

    if args.text:
        data = args.text
    else:
        if args.mode == "enc":
            data = input("Enter message to encrypt: ").strip()
        else:
            data = input("Enter ciphertext to decrypt: ").strip()

    if args.mode == "enc":
        ct = hybrid_encrypt(data, args.aes_pass, args.custom_key)
        print("\nCiphertext:\n", ct)
    else:
        try:
            pt = hybrid_decrypt(data, args.aes_pass, args.custom_key)
            print("\nDecrypted message:\n", pt)
        except Exception as e:
            print("Decryption failed:", e)

if __name__ == "__main__":
    main()
