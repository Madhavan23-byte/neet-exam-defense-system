"""
B-SEA Cryptographic Layer — KMS Abstraction & Providers

ARCHITECTURE SPECIFICATION:
───────────────────────────
This module implements the core Key Management Service (KMS) abstraction
for the Bharat Secure Examination Architecture (B-SEA).

The KMSInterface is the strictly enforced boundary that application services
must interact with. All cryptographic operations (symmetric envelope encryption,
asymmetric Ed25519 digital signatures, ephemeral session-key generation) are
mediated through this interface.

CORE SECURITY INVARIANT:
────────────────────────
"No application process, administrator, database record, environment variable,
or compromised component should expose the private cryptographic key material
used to protect B-SEA."

PROVIDERS:
──────────
1. MockKMS / MockKMSProvider:
   Software-only reference prototype using AES-256-GCM and Ed25519.
   Used strictly for deterministic local development and continuous integration.

2. AWSKMSProvider:
   Production cloud implementation backed by AWS KMS Hardware Security Modules (HSMs).
   - Symmetric Encryption: AWS KMS Customer Managed Key with AES-256-GCM envelope encryption.
     Dual-bound using AWS KMS EncryptionContext and AES-GCM Authenticated Additional Data (AAD).
     Plaintext data keys are held for the minimum required lifetime, references/buffers are
     explicitly released after use, and plaintext data keys are never persisted or logged.
   - Asymmetric Signing: Native AWS KMS Ed25519 (KeySpec ECC_NIST_EDWARDS25519,
     SigningAlgorithm ED25519_SHA_512, MessageType RAW). Private keys remain strictly
     inside the AWS KMS HSM perimeter.
   - Historical Verification: Signed artifacts record the exact KMS Key ARN/ID used.
     Public keys are cached strictly by exact KMS Key ID/ARN (never by alias) for offline
     high-throughput verification.
   - Rotation: Symmetric rotation is managed automatically by AWS KMS (key material rotates,
     existing ciphertexts decrypt seamlessly). Ed25519 rotation is manual by provisioning
     a new key while retaining historical keys in Enabled state for verification.
   - Fail-Closed: Unreachable KMS, context mismatch, tampered ciphertext, unknown keys,
     or authorization errors fail closed immediately. Never falls back to plaintext or MockKMS.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import struct
from abc import ABC, abstractmethod
from base64 import b64decode, b64encode
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Union

import boto3
import botocore
from botocore.config import Config
from botocore.exceptions import ClientError
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

logger = logging.getLogger("bsea.security.kms")


# ── Exception Hierarchy ───────────────────────────────────────────────────────

class KMSError(Exception):
    """Base exception for all B-SEA KMS errors."""


class KMSConfigurationError(KMSError):
    """Raised when KMS provider or key configuration is invalid."""


class KMSEncryptionError(KMSError):
    """Raised when encryption fails."""


class KMSDecryptionError(KMSError):
    """Raised when decryption fails."""


class KMSContextMismatchError(KMSDecryptionError):
    """Raised when encryption context does not match during decryption."""


class KMSSigningError(KMSError):
    """Raised when digital signing fails."""


class KMSVerificationError(KMSError):
    """Raised when signature verification encounters an operational error."""


class KMSKeyUnavailableError(KMSVerificationError):
    """Raised when the requested signing key is disabled, deleted, or unavailable."""


class KMSAccessDeniedError(KMSError):
    """Raised when KMS operations are denied by IAM or key policy."""


# ── Data Structures ───────────────────────────────────────────────────────────

@dataclass
class EncryptedBlob:
    """Result of an authenticated encryption operation."""
    ciphertext_b64: str  # base64(encoded envelope or raw nonce+ciphertext+tag)
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
    algorithm: str = "ED25519_SHA_512"

    def to_dict(self) -> dict:
        return {
            "payload_b64": self.payload_b64,
            "signature_b64": self.signature_b64,
            "key_id": self.key_id,
            "algorithm": self.algorithm,
        }


@dataclass
class SignedBlob:
    """Compatibility representation for signed objects."""
    signature_b64: str
    key_reference: str = ""
    algorithm: str = "ED25519_SHA_512"


# ── KMS Interface (Abstract Base Class) ────────────────────────────────────────

class KMSInterface(ABC):
    """
    Abstract interface for Key Management Service operations.

    All application code MUST use this interface.
    Never access raw cryptographic keys from application code.
    """
    provider_name: str = "AbstractKMS"

    @abstractmethod
    def encrypt(self, plaintext: bytes, context: str) -> EncryptedBlob:
        """Encrypt plaintext. Context cryptographically binds the ciphertext to a specific use."""

    @abstractmethod
    def decrypt(self, blob: EncryptedBlob, context: str) -> bytes:
        """Decrypt a blob. Context must match encryption context exactly."""

    @abstractmethod
    def sign(self, payload: bytes, key_id: Optional[str] = None) -> SignedPayload:
        """Sign payload using an Ed25519 asymmetric key."""

    @abstractmethod
    def verify(
        self,
        signed_or_payload: Any,
        signature_or_blob: Any = None,
        key_id: Optional[str] = None,
    ) -> bool:
        """Verify an Ed25519 signature."""

    @abstractmethod
    def derive_session_key(self, session_id: str, exam_id: str) -> bytes:
        """
        Derive or generate a short-lived session key for candidate question delivery.
        Returns a 32-byte (256-bit) AES key.
        """

    @abstractmethod
    def encrypt_with_session_key(
        self, plaintext: bytes, session_key: bytes
    ) -> str:
        """Encrypt using an ephemeral session key. Returns base64-encoded blob."""

    @abstractmethod
    def decrypt_with_session_key(
        self, ciphertext_b64: str, session_key: bytes
    ) -> bytes:
        """Decrypt using an ephemeral session key."""

    @abstractmethod
    def rotate_key(self, context: str) -> str:
        """Query or trigger key rotation status."""

    @abstractmethod
    def get_public_key_pem(self, key_id: Optional[str] = None) -> str:
        """Export the Ed25519 public key in PEM format for external or client verification."""


# ── SHA-3-256 Integrity Hashing ───────────────────────────────────────────────

def compute_integrity_hash(data: bytes) -> str:
    """
    Compute SHA-3-256 integrity hash.
    Used for question object integrity verification.
    Returns hex-encoded hash.
    """
    return hashlib.sha3_256(data).hexdigest()


def verify_integrity_hash(data: bytes, expected_hash: str) -> bool:
    """Constant-time comparison to prevent timing attacks."""
    actual = compute_integrity_hash(data)
    return hmac.compare_digest(actual, expected_hash)


# ── Audit Log Hash Chain ──────────────────────────────────────────────────────

def compute_audit_hash(event_data: str, prev_hash: str) -> str:
    """
    Compute hash for audit log chain.
    event_hash = SHA-256(event_data + prev_hash)
    """
    combined = f"{event_data}{prev_hash}".encode("utf-8")
    return hashlib.sha256(combined).hexdigest()


GENESIS_HASH = "0" * 64


# ── Structured Audit Logging Helper ───────────────────────────────────────────

def _audit_kms_operation(
    operation: str,
    context: str,
    key_id: str,
    success: bool,
    error: Optional[str] = None,
    correlation_id: Optional[str] = None,
    cloudtrail_api: Optional[str] = None,
) -> None:
    """
    Structured security logging for KMS operations.
    Correlates with AWS CloudTrail KMS API activity via operation, key ID, and context.
    NEVER logs plaintext questions, answer keys, data keys, private key material, or secrets.
    """
    record = {
        "event_type": f"KMS_{operation.upper()}",
        "actor": "bsea-backend",
        "operation": operation,
        "context": context,
        "kms_key_id": key_id,
        "success": success,
        "error": str(error) if error else None,
        "correlation_id": correlation_id or "",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "cloudtrail_correlation": {
            "kms_api": cloudtrail_api or f"kms:{operation}",
            "encryption_context_keys": ["context"] if context else [],
        },
    }
    if success:
        logger.info("KMS_SECURITY_EVENT: %s", json.dumps(record))
    else:
        logger.warning("KMS_SECURITY_EVENT_FAILURE: %s", json.dumps(record))


# ── MockKMS Implementation (Local Development & CI Only) ───────────────────────

class MockKMS(KMSInterface):
    """
    PROTOTYPE Software KMS using AES-256-GCM + Ed25519 + HKDF.
    Strictly for deterministic local development and test environments.
    """
    provider_name: str = "MockKMS"

    def __init__(self, master_key_str: str, signing_key_str: str):
        self._master_key: bytes = self._normalize_key(master_key_str)
        signing_seed = self._normalize_key(signing_key_str)
        self._signing_key: Ed25519PrivateKey = Ed25519PrivateKey.from_private_bytes(signing_seed)
        self._verify_key: Ed25519PublicKey = self._signing_key.public_key()
        self._key_id: str = "mock-kms-key-001"

    @staticmethod
    def _normalize_key(key_str: str) -> bytes:
        key_bytes = key_str.encode("utf-8")
        if len(key_bytes) < 32:
            key_bytes = key_bytes.ljust(32, b"\x00")
        return key_bytes[:32]

    def _derive_key(self, context: str) -> bytes:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=context.encode("utf-8"),
        )
        return hkdf.derive(self._master_key)

    def encrypt(self, plaintext: bytes, context: str) -> EncryptedBlob:
        key = self._derive_key(context)
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, context.encode("utf-8"))
        blob = b64encode(nonce + ciphertext).decode("utf-8")
        _audit_kms_operation("ENCRYPT", context, self._key_id, success=True)
        return EncryptedBlob(
            ciphertext_b64=blob,
            key_reference=f"mock-kms:{hashlib.sha256(context.encode()).hexdigest()[:16]}",
            algorithm="AES-256-GCM",
        )

    def decrypt(self, blob: EncryptedBlob, context: str) -> bytes:
        try:
            key = self._derive_key(context)
            raw = b64decode(blob.ciphertext_b64)
            nonce = raw[:12]
            ciphertext = raw[12:]
            aesgcm = AESGCM(key)
            result = aesgcm.decrypt(nonce, ciphertext, context.encode("utf-8"))
            _audit_kms_operation("DECRYPT", context, self._key_id, success=True)
            return result
        except Exception as e:
            _audit_kms_operation("DECRYPT", context, self._key_id, success=False, error=str(e))
            raise KMSDecryptionError(f"MockKMS decryption failed: {e}") from e

    def sign(self, payload: bytes, key_id: Optional[str] = None) -> SignedPayload:
        signature = self._signing_key.sign(payload)
        used_key_id = key_id or self._key_id
        _audit_kms_operation("SIGN", "", used_key_id, success=True)
        return SignedPayload(
            payload_b64=b64encode(payload).decode("utf-8"),
            signature_b64=b64encode(signature).decode("utf-8"),
            key_id=used_key_id,
            algorithm="ED25519_SHA_512",
        )

    def verify(
        self,
        signed_or_payload: Any,
        signature_or_blob: Any = None,
        key_id: Optional[str] = None,
    ) -> bool:
        try:
            if isinstance(signed_or_payload, SignedPayload):
                payload = b64decode(signed_or_payload.payload_b64)
                signature = b64decode(signed_or_payload.signature_b64)
            elif isinstance(signed_or_payload, dict):
                payload = b64decode(signed_or_payload["payload_b64"])
                signature = b64decode(signed_or_payload["signature_b64"])
            elif isinstance(signature_or_blob, SignedBlob):
                payload = signed_or_payload if isinstance(signed_or_payload, bytes) else signed_or_payload.encode("utf-8")
                signature = b64decode(signature_or_blob.signature_b64)
            elif isinstance(signature_or_blob, (str, bytes)):
                payload = signed_or_payload if isinstance(signed_or_payload, bytes) else signed_or_payload.encode("utf-8")
                sig_str = signature_or_blob.decode("utf-8") if isinstance(signature_or_blob, bytes) else signature_or_blob
                signature = b64decode(sig_str)
            else:
                return False

            self._verify_key.verify(signature, payload)
            _audit_kms_operation("VERIFY", "", key_id or self._key_id, success=True)
            return True
        except Exception as e:
            _audit_kms_operation("VERIFY", "", key_id or self._key_id, success=False, error=str(e))
            return False

    def derive_session_key(self, session_id: str, exam_id: str) -> bytes:
        context = f"session:{session_id}:exam:{exam_id}"
        return self._derive_key(context)

    def encrypt_with_session_key(
        self, plaintext: bytes, session_key: bytes
    ) -> str:
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(session_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return b64encode(nonce + ciphertext).decode("utf-8")

    def decrypt_with_session_key(
        self, ciphertext_b64: str, session_key: bytes
    ) -> bytes:
        raw = b64decode(ciphertext_b64)
        nonce = raw[:12]
        ciphertext = raw[12:]
        aesgcm = AESGCM(session_key)
        return aesgcm.decrypt(nonce, ciphertext, None)

    def rotate_key(self, context: str) -> str:
        new_ref = f"mock-kms-rotated:{secrets.token_hex(8)}"
        return new_ref

    def get_public_key_pem(self, key_id: Optional[str] = None) -> str:
        return self._verify_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")


MockKMSProvider = MockKMS


# ── AWS KMS Production Provider ────────────────────────────────────────────────

class AWSKMSProvider(KMSInterface):
    """
    Production Hardware Security Module (HSM)-backed cryptographic provider
    utilizing AWS KMS.

    Security Architecture:
    - Envelope Encryption: AWS KMS Customer Master Key (CMK) generates 256-bit
      data keys for AES-256-GCM.
    - Python key material handling: Plaintext data keys are held for the minimum
      required lifetime, references/buffers are explicitly released after use,
      and plaintext data keys are never persisted or logged.
    - Dual Context Binding: EncryptionContext in KMS + Authenticated Additional Data
      (AAD) in AES-256-GCM. Transposition across questions/exams fails closed.
    - Asymmetric Digital Signatures: Native AWS KMS Ed25519 signing. Private key
      never leaves KMS HSM boundary.
    - Offline High-Throughput Verification: Ed25519 public keys are cached strictly
      by exact KMS Key ID/ARN (never by alias) for constant-time local verification.
    - Fail-Closed: Unauthorized operations, context mismatch, key deletion, or
      tampered ciphertexts fail closed immediately. Zero fallback to plaintext or MockKMS.
    """
    provider_name: str = "AWS-KMS"
    ENVELOPE_VERSION: int = 1

    def __init__(
        self,
        encryption_key_id: str,
        signing_key_id: str,
        region_name: str = "ap-south-1",
        endpoint_url: Optional[str] = None,
        client: Optional[Any] = None,
    ):
        if not encryption_key_id or not str(encryption_key_id).strip():
            raise KMSConfigurationError("AWS KMS encryption_key_id must be provided")
        if not signing_key_id or not str(signing_key_id).strip():
            raise KMSConfigurationError("AWS KMS signing_key_id must be provided")

        self._encryption_key_id = str(encryption_key_id).strip()
        self._signing_key_id = str(signing_key_id).strip()
        self._region_name = region_name
        self._endpoint_url = endpoint_url

        # Cache of public keys keyed strictly by exact KMS key ARN/ID (NEVER by alias)
        self._public_keys: Dict[str, Ed25519PublicKey] = {}

        if client is not None:
            self._client = client
        else:
            boto_config = Config(
                retries={"max_attempts": 3, "mode": "standard"},
                connect_timeout=3.0,
                read_timeout=3.0,
            )
            self._client = boto3.client(
                "kms",
                region_name=self._region_name,
                endpoint_url=self._endpoint_url,
                config=boto_config,
            )

    def encrypt(self, plaintext: bytes, context: str) -> EncryptedBlob:
        """
        AES-256-GCM envelope encryption backed by AWS KMS GenerateDataKey.
        Cryptographically bound to context via KMS EncryptionContext and AES-GCM AAD.
        """
        if not isinstance(plaintext, bytes):
            plaintext = bytes(plaintext)

        kms_context = {"context": context}
        try:
            response = self._client.generate_data_key(
                KeyId=self._encryption_key_id,
                KeySpec="AES_256",
                EncryptionContext=kms_context,
            )
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            _audit_kms_operation("ENCRYPT", context, self._encryption_key_id, success=False, error=str(e), cloudtrail_api="kms:GenerateDataKey")
            if code == "AccessDeniedException":
                raise KMSAccessDeniedError(f"AWS KMS GenerateDataKey access denied: {e}") from e
            raise KMSEncryptionError(f"AWS KMS GenerateDataKey failed: {e}") from e
        except Exception as e:
            _audit_kms_operation("ENCRYPT", context, self._encryption_key_id, success=False, error=str(e), cloudtrail_api="kms:GenerateDataKey")
            raise KMSEncryptionError(f"AWS KMS GenerateDataKey failed: {e}") from e

        # Plaintext data keys are held for the minimum required lifetime,
        # references/buffers are explicitly released after use, and
        # plaintext data keys are never persisted or logged.
        plaintext_key = response["Plaintext"]
        encrypted_data_key = response["CiphertextBlob"]
        edk_len = len(encrypted_data_key)

        try:
            nonce = secrets.token_bytes(12)
            aesgcm = AESGCM(plaintext_key)
            ciphertext_and_tag = aesgcm.encrypt(
                nonce, plaintext, associated_data=context.encode("utf-8")
            )

            # Envelope binary format:
            # 1 byte version (0x01) + 2 bytes big-endian edk_len + encrypted_data_key + 12 bytes nonce + ciphertext_and_tag
            header = struct.pack(">BH", self.ENVELOPE_VERSION, edk_len)
            packed = header + encrypted_data_key + nonce + ciphertext_and_tag
            blob_b64 = b64encode(packed).decode("utf-8")

            _audit_kms_operation("ENCRYPT", context, self._encryption_key_id, success=True, cloudtrail_api="kms:GenerateDataKey")
            return EncryptedBlob(
                ciphertext_b64=blob_b64,
                key_reference=self._encryption_key_id,
                algorithm="AES-256-GCM-KMS-Envelope",
            )
        finally:
            del plaintext_key

    def decrypt(self, blob: EncryptedBlob, context: str) -> bytes:
        """
        AES-256-GCM envelope decryption backed by AWS KMS Decrypt.
        Fails closed on context mismatch, corrupted envelope, or tag failure.
        """
        try:
            packed = b64decode(blob.ciphertext_b64)
        except Exception as e:
            _audit_kms_operation("DECRYPT", context, self._encryption_key_id, success=False, error="Base64 decoding failed")
            raise KMSDecryptionError("Ciphertext payload is not valid base64") from e

        if len(packed) < 3:
            _audit_kms_operation("DECRYPT", context, self._encryption_key_id, success=False, error="Truncated envelope header")
            raise KMSDecryptionError("Ciphertext payload is truncated (missing envelope header)")

        version, edk_len = struct.unpack(">BH", packed[:3])
        if version != self.ENVELOPE_VERSION:
            _audit_kms_operation("DECRYPT", context, self._encryption_key_id, success=False, error=f"Unsupported envelope version {version}")
            raise KMSDecryptionError(f"Unsupported envelope format version: {version}")

        min_len = 3 + edk_len + 12 + 16  # header + edk + nonce(12) + min tag(16)
        if len(packed) < min_len:
            _audit_kms_operation("DECRYPT", context, self._encryption_key_id, success=False, error="Malformed envelope payload")
            raise KMSDecryptionError("Ciphertext payload is malformed or truncated")

        encrypted_data_key = packed[3:3 + edk_len]
        nonce = packed[3 + edk_len:3 + edk_len + 12]
        ciphertext_and_tag = packed[3 + edk_len + 12:]

        kms_context = {"context": context}
        try:
            response = self._client.decrypt(
                CiphertextBlob=encrypted_data_key,
                EncryptionContext=kms_context,
            )
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            _audit_kms_operation("DECRYPT", context, self._encryption_key_id, success=False, error=str(e), cloudtrail_api="kms:Decrypt")
            if code in ("InvalidCiphertextException", "SerializationException"):
                raise KMSContextMismatchError(f"KMS EncryptionContext mismatch or invalid ciphertext: {e}") from e
            elif code == "AccessDeniedException":
                raise KMSAccessDeniedError(f"AWS KMS Decrypt access denied: {e}") from e
            raise KMSDecryptionError(f"AWS KMS Decrypt failed: {e}") from e
        except Exception as e:
            _audit_kms_operation("DECRYPT", context, self._encryption_key_id, success=False, error=str(e), cloudtrail_api="kms:Decrypt")
            raise KMSDecryptionError(f"AWS KMS Decrypt failed: {e}") from e

        # Plaintext data keys are held for the minimum required lifetime,
        # references/buffers are explicitly released after use, and
        # plaintext data keys are never persisted or logged.
        plaintext_key = response["Plaintext"]
        try:
            aesgcm = AESGCM(plaintext_key)
            plaintext = aesgcm.decrypt(
                nonce, ciphertext_and_tag, associated_data=context.encode("utf-8")
            )
            _audit_kms_operation("DECRYPT", context, self._encryption_key_id, success=True, cloudtrail_api="kms:Decrypt")
            return plaintext
        except Exception as e:
            _audit_kms_operation("DECRYPT", context, self._encryption_key_id, success=False, error="Authenticated decryption AAD mismatch")
            raise KMSContextMismatchError(f"Authenticated decryption failed (AAD or ciphertext corrupted): {e}") from e
        finally:
            del plaintext_key

    def sign(self, payload: bytes, key_id: Optional[str] = None) -> SignedPayload:
        """
        Asymmetric digital signature using native AWS KMS Ed25519 (RAW / ED25519_SHA_512).
        Private key remains strictly inside the AWS KMS HSM perimeter.
        """
        if not isinstance(payload, bytes):
            payload = bytes(payload)

        target_key_id = key_id or self._signing_key_id
        try:
            response = self._client.sign(
                KeyId=target_key_id,
                Message=payload,
                MessageType="RAW",
                SigningAlgorithm="ED25519_SHA_512",
            )
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            _audit_kms_operation("SIGN", "", target_key_id, success=False, error=str(e), cloudtrail_api="kms:Sign")
            if code == "AccessDeniedException":
                raise KMSAccessDeniedError(f"AWS KMS Sign access denied: {e}") from e
            raise KMSSigningError(f"AWS KMS Sign operation failed: {e}") from e
        except Exception as e:
            _audit_kms_operation("SIGN", "", target_key_id, success=False, error=str(e), cloudtrail_api="kms:Sign")
            raise KMSSigningError(f"AWS KMS Sign operation failed: {e}") from e

        signature = response["Signature"]
        exact_key_id = response.get("KeyId", target_key_id)

        _audit_kms_operation("SIGN", "", exact_key_id, success=True, cloudtrail_api="kms:Sign")
        return SignedPayload(
            payload_b64=b64encode(payload).decode("utf-8"),
            signature_b64=b64encode(signature).decode("utf-8"),
            key_id=exact_key_id,
            algorithm="ED25519_SHA_512",
        )

    def _resolve_public_key(self, key_id: str) -> Ed25519PublicKey:
        """
        Resolve Ed25519 public key by exact KMS key ID/ARN.
        Keys are cached strictly by exact KMS key ID/ARN (never by alias).
        """
        if not key_id or not str(key_id).strip():
            raise KMSVerificationError("Empty or invalid KMS key ID provided for verification")

        exact_key = str(key_id).strip()
        if exact_key in self._public_keys:
            return self._public_keys[exact_key]

        try:
            response = self._client.get_public_key(KeyId=exact_key)
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in ("NotFoundException", "DisabledException", "KeyUnavailableException"):
                raise KMSKeyUnavailableError(f"Historical KMS signing key '{exact_key}' is unavailable: {e}") from e
            elif code == "AccessDeniedException":
                raise KMSAccessDeniedError(f"AWS KMS GetPublicKey access denied for key '{exact_key}': {e}") from e
            raise KMSVerificationError(f"Failed to retrieve KMS public key for '{exact_key}': {e}") from e

        der_bytes = response["PublicKey"]
        try:
            pub_key = serialization.load_der_public_key(der_bytes)
            if not isinstance(pub_key, Ed25519PublicKey):
                raise KMSVerificationError(f"Key '{exact_key}' is not an Ed25519 public key")
            self._public_keys[exact_key] = pub_key
            return pub_key
        except Exception as e:
            raise KMSVerificationError(f"Failed to parse Ed25519 public key DER for '{exact_key}': {e}") from e

    def verify(
        self,
        signed_or_payload: Any,
        signature_or_blob: Any = None,
        key_id: Optional[str] = None,
    ) -> bool:
        """
        Verify an Ed25519 signature locally using the cached public key.
        Historical verification resolves the exact historical key ID from the signed artifact.
        Fails closed on tampered payload, signature mismatch, or unknown/deleted key.
        """
        try:
            # 1. Extract payload, signature, and key_id
            if isinstance(signed_or_payload, SignedPayload):
                payload = b64decode(signed_or_payload.payload_b64)
                signature = b64decode(signed_or_payload.signature_b64)
                target_key_id = signed_or_payload.key_id
            elif isinstance(signed_or_payload, dict):
                payload = b64decode(signed_or_payload["payload_b64"])
                signature = b64decode(signed_or_payload["signature_b64"])
                target_key_id = signed_or_payload.get("key_id", key_id or self._signing_key_id)
            elif isinstance(signature_or_blob, SignedBlob):
                payload = signed_or_payload if isinstance(signed_or_payload, bytes) else signed_or_payload.encode("utf-8")
                signature = b64decode(signature_or_blob.signature_b64)
                target_key_id = signature_or_blob.key_reference or key_id or self._signing_key_id
            elif isinstance(signature_or_blob, (str, bytes)):
                payload = signed_or_payload if isinstance(signed_or_payload, bytes) else signed_or_payload.encode("utf-8")
                sig_str = signature_or_blob.decode("utf-8") if isinstance(signature_or_blob, bytes) else signature_or_blob
                signature = b64decode(sig_str)
                target_key_id = key_id or self._signing_key_id
            else:
                _audit_kms_operation("VERIFY", "", key_id or "unknown", success=False, error="Unrecognized signature payload type")
                return False

            if not target_key_id:
                _audit_kms_operation("VERIFY", "", "missing_key_id", success=False, error="No key ID provided")
                return False

            # 2. Resolve public key by exact key ID
            public_key = self._resolve_public_key(target_key_id)

            # 3. Perform constant-time local Ed25519 signature verification
            public_key.verify(signature, payload)
            _audit_kms_operation("VERIFY", "", target_key_id, success=True, cloudtrail_api="local:Ed25519Verify")
            return True
        except (InvalidSignature, KMSKeyUnavailableError, KMSVerificationError, KMSAccessDeniedError) as e:
            _audit_kms_operation("VERIFY", "", str(key_id or "unknown"), success=False, error=str(e), cloudtrail_api="local:Ed25519Verify")
            return False
        except Exception as e:
            _audit_kms_operation("VERIFY", "", str(key_id or "unknown"), success=False, error=f"Unexpected verification failure: {e}", cloudtrail_api="local:Ed25519Verify")
            return False

    def derive_session_key(self, session_id: str, exam_id: str) -> bytes:
        """
        Generate an ephemeral 256-bit AES session key for candidate question delivery.
        AWS KMS does not natively provide application session derivation logic;
        we implement it by generating an ephemeral data key bound to the session context.
        """
        context = f"session:{session_id}:exam:{exam_id}"
        try:
            response = self._client.generate_data_key(
                KeyId=self._encryption_key_id,
                KeySpec="AES_256",
                EncryptionContext={"context": context},
            )
            # The returned 32-byte Plaintext key is ephemeral and held strictly in candidate session
            # process memory for question decryptions during the exam. Redis is NEVER used to store session keys.
            raw_key: bytes = response["Plaintext"]
            del response
            return raw_key
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            _audit_kms_operation("DERIVE_SESSION_KEY", context, self._encryption_key_id, success=False, error=str(e), cloudtrail_api="kms:GenerateDataKey")
            if code == "AccessDeniedException":
                raise KMSAccessDeniedError(f"AWS KMS GenerateDataKey session key access denied: {e}") from e
            raise KMSEncryptionError(f"AWS KMS session key derivation failed: {e}") from e
        except Exception as e:
            _audit_kms_operation("DERIVE_SESSION_KEY", context, self._encryption_key_id, success=False, error=str(e), cloudtrail_api="kms:GenerateDataKey")
            raise KMSEncryptionError(f"AWS KMS session key derivation failed: {e}") from e

    def encrypt_with_session_key(
        self, plaintext: bytes, session_key: bytes
    ) -> str:
        """Encrypt using an ephemeral session key."""
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(session_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        return b64encode(nonce + ciphertext).decode("utf-8")

    def decrypt_with_session_key(
        self, ciphertext_b64: str, session_key: bytes
    ) -> bytes:
        """Decrypt using an ephemeral session key."""
        raw = b64decode(ciphertext_b64)
        nonce = raw[:12]
        ciphertext = raw[12:]
        aesgcm = AESGCM(session_key)
        return aesgcm.decrypt(nonce, ciphertext, None)

    def rotate_key(self, context: str) -> str:
        """
        Key rotation semantics:
        - Symmetric KMS key rotation rotates KMS cryptographic material automatically
          (enable_key_rotation = true). Existing encrypted data keys are not themselves
          automatically re-encrypted; they continue to decrypt seamlessly under historical backing keys.
        - Ed25519 rotation is manual by provisioning a new KMS key.
        - Historical signing keys remain enabled for verification.
        Returns the active encryption key reference.
        """
        _audit_kms_operation("ROTATE_KEY_QUERY", context, self._encryption_key_id, success=True)
        return self._encryption_key_id

    def set_active_signing_key(self, new_signing_key_id: str) -> None:
        """
        Manual rotation procedure for asymmetric signing:
        Updates active signing key ID for all future signatures.
        Historical keys remain cached/resolvable for verification.
        """
        if not new_signing_key_id or not str(new_signing_key_id).strip():
            raise KMSConfigurationError("Invalid new signing key ID")
        old_key = self._signing_key_id
        self._signing_key_id = str(new_signing_key_id).strip()
        _audit_kms_operation("SIGNING_KEY_ROTATED", f"from:{old_key}:to:{self._signing_key_id}", self._signing_key_id, success=True)

    def get_public_key_pem(self, key_id: Optional[str] = None) -> str:
        """Export Ed25519 public key in PEM format."""
        target_key_id = key_id or self._signing_key_id
        pub_key = self._resolve_public_key(target_key_id)
        return pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

    def readiness_check(self) -> bool:
        """
        Internal readiness check for /health/ready.
        Validates client initialization and key existence without exposing sensitive AWS errors.
        """
        try:
            self._client.describe_key(KeyId=self._encryption_key_id)
            self._client.describe_key(KeyId=self._signing_key_id)
            return True
        except Exception:
            return False


# ── Global KMS Singleton & Factory ─────────────────────────────────────────────

_kms_instance: Optional[KMSInterface] = None


def get_kms(master_key: str = "", signing_key: str = "") -> KMSInterface:
    """
    Get or initialize the KMS singleton based on environment configuration.
    - If KMS_PROVIDER='aws', initializes production AWSKMSProvider.
      Fails closed if configuration is missing. Never falls back to MockKMS.
    - If KMS_PROVIDER='mock', initializes MockKMS for local/CI tests.
    """
    global _kms_instance
    if _kms_instance is None:
        from app.core.config import get_settings
        settings = get_settings()

        provider_choice = getattr(settings, "kms_provider", "mock").lower().strip()

        if provider_choice == "aws":
            enc_key = getattr(settings, "kms_encryption_key_id", "")
            sign_key = getattr(settings, "kms_signing_key_id", "")
            if not enc_key or not sign_key:
                raise KMSConfigurationError(
                    "AWS KMS provider configured ('kms_provider=aws') but "
                    "KMS_ENCRYPTION_KEY_ID or KMS_SIGNING_KEY_ID is missing"
                )
            _kms_instance = AWSKMSProvider(
                encryption_key_id=enc_key,
                signing_key_id=sign_key,
                region_name=getattr(settings, "aws_region", "ap-south-1"),
                endpoint_url=getattr(settings, "kms_endpoint_url", None),
            )
        elif provider_choice == "mock":
            m_key = master_key or getattr(settings, "mock_kms_master_key", "")
            s_key = signing_key or getattr(settings, "mock_kms_signing_key", "")
            if not m_key:
                m_key = os.environ.get("MOCK_KMS_MASTER_KEY", "bsea_kms_master_key_change_me_xx")
            if not s_key:
                s_key = os.environ.get("MOCK_KMS_SIGNING_KEY", "bsea_ed25519_seed_32_bytes_chng")
            _kms_instance = MockKMS(m_key, s_key)
        else:
            raise KMSConfigurationError(f"Unsupported KMS provider: '{provider_choice}'")

    return _kms_instance


def set_kms(instance: KMSInterface) -> None:
    """Set KMS singleton instance (for testing/dependency injection)."""
    global _kms_instance
    _kms_instance = instance


def reset_kms() -> None:
    """Reset KMS singleton (for testing)."""
    global _kms_instance
    _kms_instance = None
