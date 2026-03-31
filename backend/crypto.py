import os
import hashlib
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_key() -> bytes:
    """Generate a random 256-bit key for AES-256-GCM."""
    return AESGCM.generate_key(bit_length=256)


def encrypt_file(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    """Encrypt using AES-256-GCM. Returns (encrypted_data, nonce)."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    encrypted_data = aesgcm.encrypt(nonce, plaintext, None)
    return encrypted_data, nonce


def decrypt_file(encrypted_data: bytes, key: bytes, nonce: bytes) -> bytes:
    """Decrypt using AES-256-GCM."""
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, encrypted_data, None)
    return plaintext


# --- PASSWORD HASHING (PBKDF2-SHA256 with random salt) ---

def hash_password(password: str) -> str:
    """Hash a password using PBKDF2-SHA256 with a random 16-byte salt.
    Returns a base64-encoded string containing salt + derived_key."""
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    return base64.b64encode(salt + key).decode("utf-8")


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a plaintext password against a stored PBKDF2 hash."""
    try:
        decoded = base64.b64decode(stored_hash.encode("utf-8"))
        salt = decoded[:16]
        stored_key = decoded[16:]
        key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
        return key == stored_key
    except Exception:
        return False
