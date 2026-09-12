"""
B-SEA Cryptographic Layer — MockKMS Interface

ARCHITECTURE NOTE:
─────────────────
This module implements the KMS abstraction interface for the PROTOTYPE.

The interface (KMSInterface) is the ONLY thing that application services
should call. The MockKMS implementation is a software-only prototype that
uses AES-256-GCM with keys derived from environment variables.

PRODUCTION UPGRADE PATH:
Replace MockKMS with CloudKMS or HSMBackedKMS that implement KMSInterface.
No other application code needs to change.

SECURITY WARNING:
The MockKMS is NOT suitable for production. It stores derived keys in memory
and derives them from a master key in environment variables. Production
MUST use certified HSM hardware (FIPS 140-2 Level 3 minimum) or a
government-approved Cloud KMS with hardware backing.

Cryptographic primitives used (all from the `cryptography` library):
- AES-256-GCM (authenticated encryption)
- HKDF-SHA256 (key derivation)
- Ed25519 (digital signatures)
- SHA-3-256 (integrity hashing)
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import struct
from abc import ABC, abstractmethod
from base64 import b64decode, b64encode
from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


# ── Data Structures ───────────────────────────────────────────────────────────

@dataclass
class EncryptedBlob:
    """Result of an AES-256-GCM encryption operation."""
    ciphertext_b64: str  # base64(nonce + ciphertext + tag)
    key_reference: str   # Opaque key reference (never the raw key)
    algorithm: str = "AES-256-GCM"

    def to_dict(self) -> dict:
        return {
            "ciphertext_b64": self.ciphertext_b64,
            "key_reference": self.key_reference,
            "algorithm": self.algorithm,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "EncryptedBlob":
        return cls(
            ciphertext_b64=data["ciphertext_b64"],
            key_reference=data["key_reference"],
            algorithm=data.get("algorithm", "AES-256-GCM"),
        )


@dataclass
class SignedPayload:
    """Result of an Ed25519 signature operation."""
    payload_b64: str
    signature_b64: str
    key_id: str
    algorithm: str = "Ed25519"


# ── KMS Interface (Abstract) ──────────────────────────────────────────────────

class KMSInterface(ABC):
    """
    Abstract interface for Key Management Service operations.

    All application code MUST use this interface.
    Never access raw cryptographic keys from application code.
    """

    @abstractmethod
    def encrypt(self, plaintext: bytes, context: str) -> EncryptedBlob:
        """Encrypt plaintext. context binds the ciphertext to a specific use."""

    @abstractmethod
    def decrypt(self, blob: EncryptedBlob, context: str) -> bytes:
        """Decrypt a blob. context must match encryption context."""

    @abstractmethod
    def sign(self, payload: bytes) -> SignedPayload:
        """Sign payload with the KMS signing key."""

    @abstractmethod
    def verify(self, signed: SignedPayload) -> bool:
        """Verify a signed payload."""

    @abstractmethod
    def derive_session_key(self, session_id: str, exam_id: str) -> bytes:
        """
        Derive a short-lived session key for candidate question delivery.
        This key is ephemeral — valid only for the session duration.
        Returns raw bytes (32 bytes / 256-bit AES key).
        """

    @abstractmethod
    def encrypt_with_session_key(
        self, plaintext: bytes, session_key: bytes
    ) -> str:
        """Encrypt using a session-derived key. Returns b64-encoded blob."""

    @abstractmethod
    def decrypt_with_session_key(
        self, ciphertext_b64: str, session_key: bytes
    ) -> bytes:
        """Decrypt using a session-derived key."""

    @abstractmethod
    def rotate_key(self, context: str) -> str:
        """Rotate the key for a given context. Returns new key_reference."""


# ── SHA-3-256 Integrity Hashing ───────────────────────────────────────────────

def compute_integrity_hash(data: bytes) -> str:
    """
    Compute SHA-3-256 integrity hash.
    Used for question object integrity verification.
    Returns hex-encoded hash.
    """
    digest = hashlib.sha3_256(data).hexdigest()
    return digest


def verify_integrity_hash(data: bytes, expected_hash: str) -> bool:
    """
    Constant-time comparison to prevent timing attacks.
    """
    actual = compute_integrity_hash(data)
    return hmac.compare_digest(actual, expected_hash)


# ── Audit Log Hash Chain ──────────────────────────────────────────────────────

def compute_audit_hash(event_data: str, prev_hash: str) -> str:
    """
    Compute hash for audit log chain.
    event_hash = SHA-256(event_data + prev_hash)

    This creates a Merkle-like chain where any historical modification
    invalidates all subsequent hashes.
    """
    combined = f"{event_data}{prev_hash}".encode("utf-8")
    return hashlib.sha256(combined).hexdigest()


GENESIS_HASH = "0" * 64  # Initial prev_hash for first audit log entry


# ── MockKMS Implementation (PROTOTYPE ONLY) ───────────────────────────────────

class MockKMS(KMSInterface):
    """
    PROTOTYPE Software KMS using AES-256-GCM + Ed25519 + HKDF.

    ⚠️  SECURITY WARNING: This is a PROTOTYPE implementation.
    ⚠️  Keys are derived from environment variables, stored in memory.
    ⚠️  DO NOT use in production. Replace with HSM/Cloud KMS.

    The interface is intentionally identical to what a production KMS would
    expose — making the production upgrade a drop-in replacement.
    """

    def __init__(self, master_key_str: str, signing_key_str: str):
        # Derive 32-byte master key from string (pad/truncate)
        self._master_key: bytes = self._normalize_key(master_key_str)

        # Ed25519 signing key from seed
        signing_seed = self._normalize_key(signing_key_str)
        self._signing_key: Ed25519PrivateKey = Ed25519PrivateKey.from_private_bytes(
            signing_seed
        )
        self._verify_key: Ed25519PublicKey = self._signing_key.public_key()
        self._key_id: str = "mock-kms-key-001"

    @staticmethod
    def _normalize_key(key_str: str) -> bytes:
        """Normalize a string to exactly 32 bytes for AES-256."""
        key_bytes = key_str.encode("utf-8")
        if len(key_bytes) < 32:
            key_bytes = key_bytes.ljust(32, b"\x00")
        return key_bytes[:32]

    def _derive_key(self, context: str) -> bytes:
        """
        Derive a context-specific AES key using HKDF-SHA256.
        Different contexts produce different keys, even with the same master key.
        This is the key hierarchy: master_key → context_key.
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=context.encode("utf-8"),
        )
        return hkdf.derive(self._master_key)

    def encrypt(self, plaintext: bytes, context: str) -> EncryptedBlob:
        """AES-256-GCM encryption with context-derived key."""
        key = self._derive_key(context)
        nonce = secrets.token_bytes(12)  # 96-bit GCM nonce
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, context.encode("utf-8"))
        # Store nonce + ciphertext (GCM tag is appended by library)
        blob = b64encode(nonce + ciphertext).decode("utf-8")
        return EncryptedBlob(
            ciphertext_b64=blob,
            key_reference=f"mock-kms:{hashlib.sha256(context.encode()).hexdigest()[:16]}",
        )

    def decrypt(self, blob: EncryptedBlob, context: str) -> bytes:
        """AES-256-GCM decryption with context-derived key."""
        key = self._derive_key(context)
        raw = b64decode(blob.ciphertext_b64)
        nonce = raw[:12]
        ciphertext = raw[12:]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, context.encode("utf-8"))

    def sign(self, payload: bytes) -> SignedPayload:
        """Ed25519 signature."""
        signature = self._signing_key.sign(payload)
        return SignedPayload(
            payload_b64=b64encode(payload).decode("utf-8"),
            signature_b64=b64encode(signature).decode("utf-8"),
            key_id=self._key_id,
        )

    def verify(self, signed: SignedPayload) -> bool:
        """Ed25519 signature verification."""
        try:
            payload = b64decode(signed.payload_b64)
            signature = b64decode(signed.signature_b64)
            self._verify_key.verify(signature, payload)
            return True
        except Exception:
            return False

    def derive_session_key(self, session_id: str, exam_id: str) -> bytes:
        """
        Derive a 256-bit ephemeral session key.
        This is the KEY CACHING architecture that reduces KMS calls.

        Instead of calling KMS for every question, we:
        1. Derive a session key at session start (one KMS call equivalent)
        2. Cache it encrypted in Redis
        3. Use it directly for subsequent question decryptions

        The session key is specific to (session_id, exam_id) — cannot be
        reused across sessions.
        """
        context = f"session:{session_id}:exam:{exam_id}"
        return self._derive_key(context)

    def encrypt_with_session_key(
        self, plaintext: bytes, session_key: bytes
    ) -> str:
        """Encrypt using a pre-derived session key."""
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(session_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return b64encode(nonce + ciphertext).decode("utf-8")

    def decrypt_with_session_key(
        self, ciphertext_b64: str, session_key: bytes
    ) -> bytes:
        """Decrypt using a pre-derived session key."""
        raw = b64decode(ciphertext_b64)
        nonce = raw[:12]
        ciphertext = raw[12:]
        aesgcm = AESGCM(session_key)
        return aesgcm.decrypt(nonce, ciphertext, None)

    def rotate_key(self, context: str) -> str:
        """
        MockKMS: key rotation is simulated by changing the context suffix.
        Production: triggers actual HSM key rotation.
        """
        new_ref = f"mock-kms-rotated:{secrets.token_hex(8)}"
        return new_ref

    def get_public_key_pem(self) -> str:
        """Export the Ed25519 public key for external verification."""
        return self._verify_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")


# ── Global KMS singleton (prototype) ─────────────────────────────────────────

_kms_instance: Optional[MockKMS] = None


def get_kms(master_key: str = "", signing_key: str = "") -> MockKMS:
    """
    Get or initialize the KMS singleton.
    In production, this would return the HSM-backed KMS client.
    """
    global _kms_instance
    if _kms_instance is None:
        if not master_key:
            master_key = os.environ.get(
                "MOCK_KMS_MASTER_KEY",
                "bsea_kms_master_key_change_me_xx"
            )
        if not signing_key:
            signing_key = os.environ.get(
                "MOCK_KMS_SIGNING_KEY",
                "bsea_ed25519_seed_32_bytes_chng"
            )
        _kms_instance = MockKMS(master_key, signing_key)
    return _kms_instance


def reset_kms() -> None:
    """Reset KMS singleton (for testing)."""
    global _kms_instance
    _kms_instance = None
