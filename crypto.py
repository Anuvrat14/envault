"""
Cryptographic primitives for Dotward.
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


def wrap_key_with_code(enc_key: bytes, code: str) -> dict:
    """
    Encrypt the master encryption key with a backup code.
    Returns a dict with salt/nonce/wrapped — safe to store in DB.
    Uses only 100k iterations (backup codes are random, not user passwords).
    """
    salt = os.urandom(16)
    kdf  = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                      iterations=100_000, backend=default_backend())
    code_key   = kdf.derive(code.encode('utf-8'))
    aesgcm     = AESGCM(code_key)
    nonce      = os.urandom(12)
    wrapped    = aesgcm.encrypt(nonce, enc_key, None)
    return {
        'salt':    base64.b64encode(salt).decode(),
        'nonce':   base64.b64encode(nonce).decode(),
        'wrapped': base64.b64encode(wrapped).decode(),
    }


def unwrap_key_with_code(data: dict, code: str) -> bytes:
    """
    Decrypt a wrapped master encryption key using a backup code.
    Raises ValueError on failure (wrong code / tampered data).
    """
    try:
        salt    = base64.b64decode(data['salt'])
        nonce   = base64.b64decode(data['nonce'])
        wrapped = base64.b64decode(data['wrapped'])
        kdf     = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                              iterations=100_000, backend=default_backend())
        code_key = kdf.derive(code.encode('utf-8'))
        aesgcm   = AESGCM(code_key)
        return aesgcm.decrypt(nonce, wrapped, None)
    except Exception:
        raise ValueError('Invalid backup code.')


def generate_backup_codes(n: int = 8) -> list:
    """Generate n random 8-character alphanumeric backup codes (no ambiguous chars)."""
    charset = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'  # no 0/O/1/I
    return [''.join(charset[b % len(charset)] for b in os.urandom(8)) for _ in range(n)]


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
