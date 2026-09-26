"""Cryptographic primitives shared by every party.

Everything comes from the `cryptography` library; this module only pins the
parameters (key sizes, padding, hash) so Alice, Bob and Mallory agree on them.
"""

import hashlib
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Prefix of the signed data. Stops a signature Bob made for some other purpose
# from being replayed as a signature over his RSA public key.
SIGNATURE_CONTEXT = b"T1-SegSis/rsa-public-key/v1"

OAEP = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)

SESSION_KEY_SIZE = 32  # 256 bits
GCM_NONCE_SIZE = 12  # 96 bits, the size GCM is designed for


# --- RSA: delivering the session key -------------------------------------------

def generate_rsa_keypair() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def serialize_public_key(key: rsa.RSAPublicKey) -> bytes:
    return key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_public_key(der: bytes) -> rsa.RSAPublicKey:
    return serialization.load_der_public_key(der)


def wrap_key(public_key: rsa.RSAPublicKey, session_key: bytes) -> bytes:
    """Encrypt the AES key under the recipient's RSA public key."""
    return public_key.encrypt(session_key, OAEP)


def unwrap_key(private_key: rsa.RSAPrivateKey, wrapped: bytes) -> bytes:
    return private_key.decrypt(wrapped, OAEP)


# --- AES-256-GCM: encrypting messages -------------------------------------------

def generate_session_key() -> bytes:
    return AESGCM.generate_key(bit_length=SESSION_KEY_SIZE * 8)


def encrypt(key: bytes, seq: int, plaintext: str) -> tuple[bytes, bytes]:
    """Return (nonce, ciphertext with the tag appended).

    The sequence number is associated data: sent in the clear but covered by
    the tag, so reordered or replayed messages are detected. The nonce is
    random per message; reusing one under the same key would break GCM.
    """
    nonce = os.urandom(GCM_NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode(), _aad(seq))
    return nonce, ciphertext


def decrypt(key: bytes, seq: int, nonce: bytes, ciphertext: bytes) -> str:
    """Raise cryptography.exceptions.InvalidTag if anything was altered."""
    return AESGCM(key).decrypt(nonce, ciphertext, _aad(seq)).decode()


def _aad(seq: int) -> bytes:
    return seq.to_bytes(8, "big")


# --- Ed25519: authenticating the public key -------------------------------------

def generate_signing_key() -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.generate()


def sign_key(signing_key: ed25519.Ed25519PrivateKey, rsa_der: bytes) -> bytes:
    return signing_key.sign(SIGNATURE_CONTEXT + rsa_der)


def verify_key(
    public_key: ed25519.Ed25519PublicKey, signature: bytes, rsa_der: bytes
) -> bool:
    try:
        public_key.verify(signature, SIGNATURE_CONTEXT + rsa_der)
    except InvalidSignature:
        return False
    return True


# --- Display --------------------------------------------------------------------

def fingerprint(data: bytes) -> str:
    """First 8 bytes of the SHA-256, as "a1:b2:...".

    Lets the output show at a glance that two public keys differ.
    """
    return ":".join(f"{b:02x}" for b in hashlib.sha256(data).digest()[:8])
