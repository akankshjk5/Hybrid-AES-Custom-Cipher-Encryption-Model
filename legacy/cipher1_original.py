#!/usr/bin/env python3
"""
final_cleaned_cipher.py
Cleaned / formatted version of your original implementation.
Algorithm and behaviour are identical to cipher1.py / cipher2.py.
"""

import os
import hmac
import struct
import hashlib
from typing import List
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------- Helpers ----------
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

# ---------- Base mapping ----------
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

# ---------- Deterministic CSPRNG ----------
class KeyedCSPRNG:
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
        out = []
        while sum(len(x) for x in out) < need:
            self.counter += 1
            block = hmac.new(self.key, struct.pack(">Q", self.counter), hashlib.sha256).digest()
            out.append(block)
        self.buf = b"".join(out)
        self.pos = 0

    def bytes(self, n: int) -> bytes:
        if self.pos + n > len(self.buf):
            self._refill(max(n, 64))
        data = self.buf[self.pos:self.pos + n]
        self.pos += n
        return data

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

# ---------- Custom cipher pieces ----------
def _vigenerize(text: str, key: str, encrypt: bool) -> str:
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
    word_shift = shift_pattern[(word_idx - 1) % len(shift_pattern)]
    letters = []
    for pos, ch in enumerate(word, start=1):
        if 'A' <= ch <= 'Z':
            n = BASE_MAP[ch]
            n += pos + word_shift
            letters.append(_num_to_alpha(n))
    return "".join(letters)

def _keyed_word_transform(s: str, word_idx: int, rng_word: KeyedCSPRNG) -> str:
    rounds = 1
    for _ in range(rounds):
        if word_idx % 2 == 1:
            s = s[::-1]
        else:
            r = rng_word.randint(1, max(1, len(s))) if s else 0
            s = _rot_right(s, r)
    return s

def _insert_noise(text: str, rng: KeyedCSPRNG) -> str:
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
    blocks = [text[i:i+block_size] for i in range(0, len(text), block_size)]
    idxs = list(range(len(blocks)))
    rng.shuffle(idxs)
    return ''.join(blocks[i] for i in idxs)

def _block_unshuffle(text: str, rng: KeyedCSPRNG, block_size: int) -> str:
    if block_size <= 0:
        return text
    blocks = [text[i:i+block_size] for i in range(0, len(text), block_size)]
    n = len(blocks)
    idxs = list(range(n))
    rng.shuffle(idxs)
    inverse = [None] * n
    for new_pos, old_pos in enumerate(idxs):
        inverse[old_pos] = new_pos
    restored = [None] * n
    for old_pos in range(n):
        restored[old_pos] = blocks[inverse[old_pos]]
    return ''.join(restored).rstrip('X')

def custom_encrypt(plaintext: str, custom_key: str,
                   shift_pattern: List[int] = None, block_size: int = 6) -> str:
    if shift_pattern is None:
        shift_pattern = [2, 3, 5, 7]
    key_bytes = custom_key.encode('utf-8')
    rng_noise = KeyedCSPRNG(key_bytes, b"NOISE")
    rng_blocks = KeyedCSPRNG(key_bytes, b"BLOCKS")
    words = plaintext.upper().split()
    transformed_words = []
    for wi, w in enumerate(words, start=1):
        core = ''.join(ch for ch in w if 'A' <= ch <= 'Z')
        base_letters = _map_word_to_letters(core, wi, shift_pattern)
        rng_word = KeyedCSPRNG(key_bytes + struct.pack(">I", wi), b"WORDS")
        final_letters = _keyed_word_transform(base_letters, wi, rng_word)
        transformed_words.append(final_letters)
    stage = " ".join(transformed_words)
    stage = _vigenerize(stage, custom_key, encrypt=True)
    stage = _insert_noise(stage, rng_noise)
    stage = _block_shuffle(stage, rng_blocks, block_size)
    hmac_tag = hmac.new(key_bytes, stage.encode('utf-8'), hashlib.sha256).hexdigest()[:16]
    return stage + hmac_tag

def custom_decrypt(ciphertext: str, custom_key: str,
                   shift_pattern: List[int] = None, block_size: int = 6) -> str:
    if shift_pattern is None:
        shift_pattern = [2, 3, 5, 7]
    key_bytes = custom_key.encode('utf-8')
    hmac_tag = ciphertext[-16:]
    ct_body = ciphertext[:-16]
    expected_tag = hmac.new(key_bytes, ct_body.encode('utf-8'), hashlib.sha256).hexdigest()[:16]
    if hmac_tag != expected_tag:
        raise ValueError("Ciphertext integrity check failed.")
    rng_noise = KeyedCSPRNG(key_bytes, b"NOISE")
    rng_blocks = KeyedCSPRNG(key_bytes, b"BLOCKS")
    s = _block_unshuffle(ct_body, rng_blocks, block_size)
    s = _remove_noise(s, rng_noise)
    s = _vigenerize(s, custom_key, encrypt=False)
    words = s.split()
    restored_words = []
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
        restored_words.append("".join(plain_chars))
    return " ".join(restored_words)

# ---------- AES-GCM and Base26 ----------
def _kdf_scrypt(passphrase: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**16, r=8, p=2)
    return kdf.derive(passphrase.encode('utf-8'))

def aes_gcm_encrypt(plaintext: bytes, passphrase: str) -> bytes:
    salt = os.urandom(16)
    key = _kdf_scrypt(passphrase, salt)
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return salt + nonce + ct

def aes_gcm_decrypt(packed: bytes, passphrase: str) -> bytes:
    if len(packed) < 28:
        raise ValueError("ciphertext too short")
    salt, nonce, ct = packed[:16], packed[16:28], packed[28:]
    key = _kdf_scrypt(passphrase, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, associated_data=None)

def bytes_to_base26_with_header(b: bytes) -> str:
    blen = len(b)
    if blen >= 26**4:
        raise ValueError("data too large")
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

# ---------- High-level hybrid ----------
def hybrid_encrypt_aes_then_custom(plaintext: str, aes_passphrase: str, custom_key: str) -> str:
    aes_packed = aes_gcm_encrypt(plaintext.encode('utf-8'), aes_passphrase)
    base26 = bytes_to_base26_with_header(aes_packed)
    return custom_encrypt(base26, custom_key, shift_pattern=[2, 3, 5, 7], block_size=6)

def hybrid_decrypt_custom_then_aes(ciphertext: str, aes_passphrase: str, custom_key: str) -> str:
    base26 = custom_decrypt(ciphertext, custom_key, shift_pattern=[2, 3, 5, 7], block_size=6)
    aes_packed = base26_with_header_to_bytes(base26)
    pt_bytes = aes_gcm_decrypt(aes_packed, aes_passphrase)
    return pt_bytes.decode('utf-8', errors='strict')

# ---------- Demo ----------
if __name__ == "__main__":
    aes_pass = "aes-strong-passphrase"
    custom_key = "akanksh-super-unique-key"

    print("=== Secure Hybrid AES + Custom Cipher (cleaned) ===")
    mode = input("Choose mode:\n1. Encrypt new message\n2. Decrypt existing ciphertext\nEnter choice (1/2): ").strip()

    if mode == "1":
        msg = input("\nEnter message to encrypt: ")
        ct = hybrid_encrypt_aes_then_custom(msg, aes_pass, custom_key)
        print("\nCiphertext:\n", ct)
        choice = input("\nDo you want to decrypt it now? (y/n): ").strip().lower()
        if choice == "y":
            try:
                pt = hybrid_decrypt_custom_then_aes(ct, aes_pass, custom_key)
                print("\nDecrypted message:\n", pt)
            except Exception as e:
                print("\n❌ Decryption failed:", e)
        else:
            print("\nDecryption skipped. ✅")

    elif mode == "2":
        ciphertext = input("\nEnter ciphertext to decrypt: ").strip()
        try:
            pt = hybrid_decrypt_custom_then_aes(ciphertext, aes_pass, custom_key)
            print("\nDecrypted message:\n", pt)
        except Exception as e:
            print("\n❌ Decryption failed:", e)
    else:
        print("\nInvalid choice. Exiting.")
