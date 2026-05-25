"""
Cryptographic primitives for Envault.
AES-256-GCM for variable encryption, PBKDF2-SHA256 for key derivation.
Key never touches disk — lives in memory only.
"""
import base64
import hashlib
import os
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


# PBKDF2 parameters
_ITERATIONS = 600_000  # OWASP 2023 recommendation
_KEY_LENGTH  = 32      # 256-bit


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from a master password + salt via PBKDF2-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=_KEY_LENGTH,
        salt=salt,
        iterations=_ITERATIONS,
        backend=default_backend(),
    )
    return kdf.derive(password.encode('utf-8'))


def generate_salt() -> bytes:
    """Generate a cryptographically random 32-byte salt."""
    return os.urandom(32)


def encrypt_value(plaintext: str, key: bytes) -> str:
    """
    Encrypt a string value with AES-256-GCM.
    Returns base64-encoded nonce + ciphertext (nonce prepended).
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce for GCM
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
    blob = nonce + ciphertext
    return base64.b64encode(blob).decode('ascii')


def decrypt_value(encrypted_b64: str, key: bytes) -> str:
    """
    Decrypt a base64-encoded nonce+ciphertext blob.
    Raises ValueError on decryption failure (wrong key / tampered data).
    """
    try:
        blob = base64.b64decode(encrypted_b64)
        nonce = blob[:12]
        ciphertext = blob[12:]
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode('utf-8')
    except Exception:
        raise ValueError('Decryption failed — wrong master password or corrupted data.')


def hash_password(password: str, salt: bytes) -> str:
    """
    Hash the master password for verification storage.
    Uses a separate PBKDF2 pass so the stored hash cannot be used as the encryption key.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt + b'verify',  # domain separation from encryption salt
        iterations=_ITERATIONS,
        backend=default_backend(),
    )
    digest = kdf.derive(password.encode('utf-8'))
    return base64.b64encode(digest).decode('ascii')
