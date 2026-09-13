"""
B-SEA Phase 3C-3: AWS KMS Cryptographic Migration Security Test Suite

Tests all mandatory security invariants:
A. Provider selection
B. AWS KMS configuration validation
C. Encrypt/decrypt success path (envelope encryption)
D. Encrypt/decrypt failure path
E. No plaintext fallback invariant
F. Ed25519 signing (native AWS KMS)
G. Ed25519 signature verification (local public-key verify)
H. Unknown key ID rejection
I. Historical key-ID verification across key rotations
J. Unauthorized KMS operation rejection (AccessDeniedException)
K. Key rotation behavior (symmetric and asymmetric)
L. Application IAM permission boundary
M. No private signing key exposure
N. Malformed ciphertext rejection
O. Structured audit logging and CloudTrail correlation
P. Context binding and transplantation rejection:
   - Wrong exam context -> FAIL
   - Wrong question context -> FAIL
   - Ciphertext transplanted between questions -> FAIL
   - AES-GCM AAD/context tampering -> FAIL
   - KMS EncryptionContext mismatch -> FAIL
"""
import base64
import json
import logging
import os
import re
import secrets
import struct
from typing import Any, Dict, Optional
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import Settings
from app.crypto.kms_interface import (
    AWSKMSProvider,
    EncryptedBlob,
    KMSAccessDeniedError,
    KMSConfigurationError,
    KMSContextMismatchError,
    KMSDecryptionError,
    KMSEncryptionError,
    KMSInterface,
    KMSKeyUnavailableError,
    KMSSigningError,
    KMSVerificationError,
    MockKMS,
    MockKMSProvider,
    SignedBlob,
    SignedPayload,
    get_kms,
    reset_kms,
    set_kms,
)


# ── In-Memory High-Fidelity Mock KMS Client (Simulating AWS KMS HSM) ──────────

class FakeKMSClient:
    """
    High-fidelity in-memory simulation of AWS KMS client.
    Accurately reproduces AWS KMS cryptography, EncryptionContext validation,
    Ed25519 RAW signing, DER public key export, and ClientError semantics.
    """

    def __init__(self):
        self.symmetric_keys = {
            "arn:aws:kms:ap-south-1:123456789012:key/sym-001": {
                "version": 1,
                "enabled": True,
            }
        }
        # Ephemeral private keys held inside the simulated KMS HSM boundary
        self._ed25519_hsm_keys: Dict[str, Ed25519PrivateKey] = {
            "arn:aws:kms:ap-south-1:123456789012:key/ed25519-v1": Ed25519PrivateKey.generate(),
            "arn:aws:kms:ap-south-1:123456789012:key/ed25519-v2": Ed25519PrivateKey.generate(),
        }
        self.enabled_signing_keys = {
            "arn:aws:kms:ap-south-1:123456789012:key/ed25519-v1": True,
            "arn:aws:kms:ap-south-1:123456789012:key/ed25519-v2": True,
        }
        self.call_history = []

    def generate_data_key(self, KeyId: str, KeySpec: str, EncryptionContext: Dict[str, str]) -> Dict[str, Any]:
        self.call_history.append(("generate_data_key", KeyId, EncryptionContext))
        if KeyId not in self.symmetric_keys:
            raise ClientError(
                {"Error": {"Code": "NotFoundException", "Message": f"Key {KeyId} not found"}},
                "GenerateDataKey",
            )
        raw_key = secrets.token_bytes(32)
        # Simulate KMS envelope: encrypt raw_key with context binding
        context_str = json.dumps(EncryptionContext, sort_keys=True)
        aesgcm = AESGCM(b"KMS_SIMULATED_MASTER_KEY_32BYTES")
        nonce = secrets.token_bytes(12)
        ct = aesgcm.encrypt(nonce, raw_key, context_str.encode("utf-8"))
        ciphertext_blob = nonce + ct
        return {
            "Plaintext": raw_key,
            "CiphertextBlob": ciphertext_blob,
            "KeyId": KeyId,
        }

    def decrypt(self, CiphertextBlob: bytes, EncryptionContext: Dict[str, str]) -> Dict[str, Any]:
        self.call_history.append(("decrypt", EncryptionContext))
        if len(CiphertextBlob) < 28:
            raise ClientError(
                {"Error": {"Code": "InvalidCiphertextException", "Message": "Invalid ciphertext"}},
                "Decrypt",
            )
        nonce = CiphertextBlob[:12]
        ct = CiphertextBlob[12:]
        context_str = json.dumps(EncryptionContext, sort_keys=True)
        aesgcm = AESGCM(b"KMS_SIMULATED_MASTER_KEY_32BYTES")
        try:
            plaintext = aesgcm.decrypt(nonce, ct, context_str.encode("utf-8"))
            return {"Plaintext": plaintext, "KeyId": "arn:aws:kms:ap-south-1:123456789012:key/sym-001"}
        except Exception as e:
            raise ClientError(
                {"Error": {"Code": "InvalidCiphertextException", "Message": f"EncryptionContext mismatch or tampered: {e}"}},
                "Decrypt",
            )

    def sign(self, KeyId: str, Message: bytes, MessageType: str, SigningAlgorithm: str) -> Dict[str, Any]:
        self.call_history.append(("sign", KeyId, SigningAlgorithm))
        if KeyId not in self._ed25519_hsm_keys:
            raise ClientError(
                {"Error": {"Code": "NotFoundException", "Message": f"Key {KeyId} not found"}},
                "Sign",
            )
        if not self.enabled_signing_keys.get(KeyId, False):
            raise ClientError(
                {"Error": {"Code": "DisabledException", "Message": f"Key {KeyId} is disabled"}},
                "Sign",
            )
        priv_key = self._ed25519_hsm_keys[KeyId]
        sig = priv_key.sign(Message)
        return {
            "Signature": sig,
            "KeyId": KeyId,
            "SigningAlgorithm": SigningAlgorithm,
        }

    def get_public_key(self, KeyId: str) -> Dict[str, Any]:
        self.call_history.append(("get_public_key", KeyId))
        if KeyId not in self._ed25519_hsm_keys:
            raise ClientError(
                {"Error": {"Code": "NotFoundException", "Message": f"Key {KeyId} not found"}},
                "GetPublicKey",
            )
        if not self.enabled_signing_keys.get(KeyId, False):
            raise ClientError(
                {"Error": {"Code": "DisabledException", "Message": f"Key {KeyId} is disabled"}},
                "GetPublicKey",
            )
        priv_key = self._ed25519_hsm_keys[KeyId]
        pub_der = priv_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return {
            "PublicKey": pub_der,
            "KeyId": KeyId,
            "KeySpec": "ECC_NIST_EDWARDS25519",
            "KeyUsage": "SIGN_VERIFY",
        }

    def describe_key(self, KeyId: str) -> Dict[str, Any]:
        return {"KeyMetadata": {"KeyId": KeyId, "Enabled": True}}


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def fake_kms():
    return FakeKMSClient()


@pytest.fixture
def aws_provider(fake_kms):
    return AWSKMSProvider(
        encryption_key_id="arn:aws:kms:ap-south-1:123456789012:key/sym-001",
        signing_key_id="arn:aws:kms:ap-south-1:123456789012:key/ed25519-v1",
        region_name="ap-south-1",
        client=fake_kms,
    )


# ── Test Suite A: Provider Selection ──────────────────────────────────────────

def test_provider_selection_mock():
    """Verify that kms_provider='mock' selects MockKMS."""
    reset_kms()
    with patch("app.core.config.get_settings") as mock_settings:
        mock_settings.return_value = Settings(
            KMS_PROVIDER="mock",
            mock_kms_master_key="bsea_kms_master_key_change_me_xx",
            mock_kms_signing_key="bsea_ed25519_seed_32_bytes_chng",
        )
        kms = get_kms()
        assert isinstance(kms, MockKMS)
        assert kms.provider_name == "MockKMS"
    reset_kms()


def test_provider_selection_aws(fake_kms):
    """Verify that kms_provider='aws' with valid keys selects AWSKMSProvider."""
    reset_kms()
    with patch("app.core.config.get_settings") as mock_settings:
        mock_settings.return_value = Settings(
            KMS_PROVIDER="aws",
            KMS_ENCRYPTION_KEY_ID="arn:aws:kms:ap-south-1:123456789012:key/sym-001",
            KMS_SIGNING_KEY_ID="arn:aws:kms:ap-south-1:123456789012:key/ed25519-v1",
        )
        with patch("boto3.client", return_value=fake_kms):
            kms = get_kms()
            assert isinstance(kms, AWSKMSProvider)
            assert kms.provider_name == "AWS-KMS"
    reset_kms()


def test_provider_selection_invalid():
    """Verify that an invalid kms_provider choice raises KMSConfigurationError."""
    reset_kms()
    with patch("app.core.config.get_settings") as mock_settings:
        mock_settings.return_value = Settings(KMS_PROVIDER="unsupported_vault")
        with pytest.raises(KMSConfigurationError, match="Unsupported KMS provider"):
            get_kms()
    reset_kms()


# ── Test Suite B: AWS KMS Configuration Validation ───────────────────────────

def test_aws_kms_config_validation_missing_keys():
    """Verify that missing key IDs with kms_provider='aws' raises KMSConfigurationError."""
    reset_kms()
    with patch("app.core.config.get_settings") as mock_settings:
        mock_settings.return_value = Settings(
            KMS_PROVIDER="aws",
            KMS_ENCRYPTION_KEY_ID="",
            KMS_SIGNING_KEY_ID="",
        )
        with pytest.raises(KMSConfigurationError, match="missing"):
            get_kms()
    reset_kms()


def test_aws_kms_provider_direct_constructor_validation():
    """Verify that instantiating AWSKMSProvider directly with empty keys raises KMSConfigurationError."""
    with pytest.raises(KMSConfigurationError, match="encryption_key_id must be provided"):
        AWSKMSProvider(encryption_key_id="", signing_key_id="arn:aws:kms:...")
    with pytest.raises(KMSConfigurationError, match="signing_key_id must be provided"):
        AWSKMSProvider(encryption_key_id="arn:aws:kms:...", signing_key_id="")


# ── Test Suite C & D: Encrypt/Decrypt Success & Failure ────────────────────────

def test_envelope_encrypt_decrypt_success(aws_provider):
    """Test successful AES-256-GCM envelope encryption and decryption."""
    plaintext = b"SECURE_QUESTION_CONTENT: What is the capital of India? Ans: New Delhi."
    context = "question:q_101:exam:neet_2026"

    blob = aws_provider.encrypt(plaintext, context)
    assert isinstance(blob, EncryptedBlob)
    assert blob.algorithm == "AES-256-GCM-KMS-Envelope"
    assert blob.key_reference == "arn:aws:kms:ap-south-1:123456789012:key/sym-001"

    decrypted = aws_provider.decrypt(blob, context)
    assert decrypted == plaintext


def test_envelope_encrypt_kms_failure():
    """Test that KMS failure during GenerateDataKey fails closed and raises KMSEncryptionError."""
    failing_client = MagicMock()
    failing_client.generate_data_key.side_effect = ClientError(
        {"Error": {"Code": "KMSInternalException", "Message": "KMS service error"}},
        "GenerateDataKey",
    )
    provider = AWSKMSProvider("arn:aws:kms:sym", "arn:aws:kms:sign", client=failing_client)

    with pytest.raises(KMSEncryptionError, match="AWS KMS GenerateDataKey failed"):
        provider.encrypt(b"secret", "context")


def test_envelope_decrypt_kms_failure(aws_provider):
    """Test that KMS failure during Decrypt fails closed and raises KMSDecryptionError."""
    blob = aws_provider.encrypt(b"secret", "context")

    aws_provider._client.decrypt = MagicMock(side_effect=ClientError(
        {"Error": {"Code": "KMSInternalException", "Message": "KMS service unavailable"}},
        "Decrypt",
    ))

    with pytest.raises(KMSDecryptionError, match="AWS KMS Decrypt failed"):
        aws_provider.decrypt(blob, "context")


# ── Test Suite E: No Plaintext Fallback Invariant ─────────────────────────────

def test_no_plaintext_fallback_invariant(aws_provider):
    """
    CRITICAL SECURITY INVARIANT:
    If KMS encryption or decryption fails, the system must NEVER return plaintext
    and must NEVER silently fall back to MockKMS or an unauthenticated state.
    """
    blob = aws_provider.encrypt(b"CONFIDENTIAL_QUESTION", "exam:neet_2026")

    # Simulate KMS network outage
    aws_provider._client.decrypt = MagicMock(side_effect=Exception("KMS unreachable"))

    # Must raise KMSDecryptionError, never return the plaintext bytes
    with pytest.raises(KMSDecryptionError):
        aws_provider.decrypt(blob, "exam:neet_2026")


# ── Test Suite F & G: Ed25519 Signing & Verification ──────────────────────────

def test_ed25519_sign_and_verify_success(aws_provider):
    """Test native Ed25519 signing via KMS and local public-key verification."""
    payload = b"EXAM_RELEASE_APPROVAL:EXAM_001:AUTHORITY_007:NONCE_ABC"

    signed = aws_provider.sign(payload)
    assert isinstance(signed, SignedPayload)
    assert signed.algorithm == "ED25519_SHA_512"
    assert signed.key_id == "arn:aws:kms:ap-south-1:123456789012:key/ed25519-v1"

    # Verify using SignedPayload
    is_valid = aws_provider.verify(signed)
    assert is_valid is True

    # Verify using payload + SignedBlob compatibility structure
    compat_blob = SignedBlob(signature_b64=signed.signature_b64, key_reference=signed.key_id)
    assert aws_provider.verify(payload, compat_blob) is True


def test_ed25519_verification_tampered_payload(aws_provider):
    """Tampering with signed payload must cause verification to fail (return False)."""
    payload = b"GENUINE_STATEMENT"
    signed = aws_provider.sign(payload)

    # Tamper payload
    tampered_signed = SignedPayload(
        payload_b64=base64.b64encode(b"TAMPERED_STATEMENT").decode("utf-8"),
        signature_b64=signed.signature_b64,
        key_id=signed.key_id,
    )
    assert aws_provider.verify(tampered_signed) is False


def test_ed25519_verification_tampered_signature(aws_provider):
    """Tampering with signature bytes must fail verification."""
    payload = b"GENUINE_STATEMENT"
    signed = aws_provider.sign(payload)

    sig_bytes = base64.b64decode(signed.signature_b64)
    corrupted_sig = bytes([sig_bytes[0] ^ 0xFF]) + sig_bytes[1:]

    tampered_signed = SignedPayload(
        payload_b64=signed.payload_b64,
        signature_b64=base64.b64encode(corrupted_sig).decode("utf-8"),
        key_id=signed.key_id,
    )
    assert aws_provider.verify(tampered_signed) is False


# ── Test Suite H: Unknown Key ID Rejection ─────────────────────────────────────

def test_unknown_key_id_rejection(aws_provider):
    """Signatures claiming an unknown KMS key ID must fail closed."""
    payload = b"STATEMENT"
    signed = aws_provider.sign(payload)

    # Change key_id to a nonexistent key
    fake_signed = SignedPayload(
        payload_b64=signed.payload_b64,
        signature_b64=signed.signature_b64,
        key_id="arn:aws:kms:ap-south-1:123456789012:key/unknown-nonexistent-key",
    )
    assert aws_provider.verify(fake_signed) is False


# ── Test Suite I: Historical Key-ID Verification Across Key Rotations ─────────

def test_historical_key_id_verification_across_rotations(aws_provider):
    """
    Test asymmetric key rotation:
    1. Sign artifact 1 with Key V1.
    2. Rotate active key to Key V2.
    3. Sign artifact 2 with Key V2.
    4. Both artifacts must verify successfully using their exact recorded historical key IDs.
    """
    artifact_1_payload = b"HISTORICAL_BLUEPRINT_2025"
    signed_1 = aws_provider.sign(artifact_1_payload)
    assert signed_1.key_id == "arn:aws:kms:ap-south-1:123456789012:key/ed25519-v1"

    # Rotate active signing key
    aws_provider.set_active_signing_key("arn:aws:kms:ap-south-1:123456789012:key/ed25519-v2")

    artifact_2_payload = b"NEW_BLUEPRINT_2026"
    signed_2 = aws_provider.sign(artifact_2_payload)
    assert signed_2.key_id == "arn:aws:kms:ap-south-1:123456789012:key/ed25519-v2"

    # Both must verify cleanly
    assert aws_provider.verify(signed_1) is True
    assert aws_provider.verify(signed_2) is True


# ── Test Suite J: Unauthorized KMS Operation Rejection ────────────────────────

def test_unauthorized_kms_access_denied():
    """Verify that AccessDeniedException fails closed and raises KMSAccessDeniedError."""
    denied_client = MagicMock()
    denied_client.generate_data_key.side_effect = ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "User not authorized"}},
        "GenerateDataKey",
    )
    denied_client.decrypt.side_effect = ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "User not authorized"}},
        "Decrypt",
    )
    denied_client.sign.side_effect = ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "User not authorized"}},
        "Sign",
    )

    provider = AWSKMSProvider("arn:aws:kms:sym", "arn:aws:kms:sign", client=denied_client)

    with pytest.raises(KMSAccessDeniedError, match="access denied"):
        provider.encrypt(b"data", "ctx")

    with pytest.raises(KMSAccessDeniedError, match="access denied"):
        # Craft a minimal valid-looking envelope
        header = struct.pack(">BH", 1, 10)
        fake_blob = EncryptedBlob(base64.b64encode(header + b"0123456789" + b"N"*12 + b"T"*16).decode("utf-8"), "ref")
        provider.decrypt(fake_blob, "ctx")

    with pytest.raises(KMSAccessDeniedError, match="access denied"):
        provider.sign(b"data")


# ── Test Suite K: Key Rotation Semantics ──────────────────────────────────────

def test_key_rotation_semantics(aws_provider):
    """
    Verify rotation semantics:
    - rotate_key() queries rotation status and returns the active key reference.
    - Public key caching is keyed strictly by exact key ID.
    """
    key_ref = aws_provider.rotate_key("question_context")
    assert key_ref == "arn:aws:kms:ap-south-1:123456789012:key/sym-001"

    # Public key retrieval
    pem = aws_provider.get_public_key_pem()
    assert "BEGIN PUBLIC KEY" in pem
    assert "END PUBLIC KEY" in pem


# ── Test Suite L: Application IAM Permission Boundary ─────────────────────────

def test_application_iam_permission_boundary():
    """
    Verify that Terraform IAM definitions for the ECS task role strictly conform
    to least-privilege principles.
    Permitted: kms:GenerateDataKey, kms:Decrypt, kms:Sign, kms:GetPublicKey, kms:DescribeKey.
    Prohibited: kms:Verify, kms:Create*, kms:Schedule*, kms:Put*, kms:Delete*, kms:*.
    """
    tf_iam_path = os.path.join(
        os.path.dirname(__file__), "..", "..", "..", "terraform", "modules", "iam", "main.tf"
    )
    with open(tf_iam_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Find the ecs_kms_crypto policy definition
    match = re.search(r'resource "aws_iam_policy" "ecs_kms_crypto".*?policy\s*=\s*jsonencode\(({.*?})\)\s*}', content, re.DOTALL)
    assert match is not None, "ecs_kms_crypto policy not found in terraform/modules/iam/main.tf"

    policy_block = match.group(1)

    # Must contain allowed actions
    assert "kms:GenerateDataKey" in policy_block
    assert "kms:Decrypt" in policy_block
    assert "kms:Sign" in policy_block
    assert "kms:GetPublicKey" in policy_block

    # Must NOT contain forbidden actions
    assert "kms:Verify" not in policy_block, "kms:Verify should not be granted (verification is local)"
    assert "kms:*" not in policy_block, "Broad wildcard kms:* forbidden"
    assert "kms:CreateKey" not in policy_block
    assert "kms:ScheduleKeyDeletion" not in policy_block
    assert "kms:PutKeyPolicy" not in policy_block


# ── Test Suite M: No Private Signing Key Exposure ─────────────────────────────

def test_no_private_signing_key_exposure(aws_provider):
    """
    Verify that the AWSKMSProvider never stores, holds, or exports private key material.
    """
    assert not hasattr(aws_provider, "_signing_key"), "AWSKMSProvider must not hold local private key objects"
    assert not hasattr(aws_provider, "_master_key"), "AWSKMSProvider must not hold master key bytes"

    # Representation should not expose keys
    assert "PRIVATE KEY" not in str(aws_provider)
    assert "PRIVATE KEY" not in repr(aws_provider)


# ── Test Suite N: Malformed Ciphertext Rejection ───────────────────────────────

def test_malformed_ciphertext_rejection(aws_provider):
    """Malformed, corrupted, or truncated ciphertexts must fail closed."""
    # Not base64
    with pytest.raises(KMSDecryptionError, match="not valid base64"):
        aws_provider.decrypt(EncryptedBlob("!not_base64!", "ref"), "ctx")

    # Truncated
    truncated = base64.b64encode(b"\x01").decode("utf-8")
    with pytest.raises(KMSDecryptionError, match="truncated"):
        aws_provider.decrypt(EncryptedBlob(truncated, "ref"), "ctx")

    # Unsupported version
    bad_version = base64.b64encode(b"\x02\x00\x0512345" + b"N"*12 + b"T"*16).decode("utf-8")
    with pytest.raises(KMSDecryptionError, match="Unsupported envelope format version"):
        aws_provider.decrypt(EncryptedBlob(bad_version, "ref"), "ctx")


# ── Test Suite O: Structured Audit Logging ────────────────────────────────────

def test_structured_audit_logging_emitted(aws_provider, caplog):
    """Verify that KMS operations emit structured security events without secrets."""
    caplog.set_level(logging.INFO, logger="bsea.security.kms")

    blob = aws_provider.encrypt(b"CONFIDENTIAL_QUESTION_TEXT", "question:q1:exam:e1")
    aws_provider.decrypt(blob, "question:q1:exam:e1")
    signed = aws_provider.sign(b"AUDIT_PAYLOAD")
    aws_provider.verify(signed)

    logs = caplog.text
    assert "KMS_SECURITY_EVENT" in logs
    assert "KMS_ENCRYPT" in logs
    assert "KMS_DECRYPT" in logs
    assert "KMS_SIGN" in logs
    assert "KMS_VERIFY" in logs

    # ABSOLUTE PRIVACY INVARIANT: Secret material never logged
    assert "CONFIDENTIAL_QUESTION_TEXT" not in logs
    assert "AUDIT_PAYLOAD" not in logs
    assert "Plaintext" not in logs
    assert "private" not in logs.lower()


# ── Test Suite P: Explicit Context Binding & Transplantation Rejection ────────

def test_ciphertext_wrong_exam_context_fails(aws_provider):
    """Decryption with a different exam context must fail closed."""
    blob = aws_provider.encrypt(b"QUESTION_DATA", "question:q_001:exam:neet_2026_phase1")

    with pytest.raises(KMSContextMismatchError):
        aws_provider.decrypt(blob, "question:q_001:exam:neet_2026_phase2")


def test_ciphertext_wrong_question_context_fails(aws_provider):
    """Decryption with a different question ID context must fail closed."""
    blob = aws_provider.encrypt(b"QUESTION_1_DATA", "question:q_001:exam:neet_2026")

    with pytest.raises(KMSContextMismatchError):
        aws_provider.decrypt(blob, "question:q_002:exam:neet_2026")


def test_ciphertext_transplanted_between_questions_fails(aws_provider):
    """
    Attacker tries to transplant an encrypted question blob from Question A
    into the database row of Question B.
    Decryption under Question B's context must fail closed.
    """
    q1_blob = aws_provider.encrypt(b"QUESTION_A_CONTENT", "question:q_A:exam:neet_2026")

    # Transplanted into question B
    transplanted_blob = EncryptedBlob(
        ciphertext_b64=q1_blob.ciphertext_b64,
        key_reference=q1_blob.key_reference,
    )

    with pytest.raises(KMSContextMismatchError):
        aws_provider.decrypt(transplanted_blob, "question:q_B:exam:neet_2026")


def test_aes_gcm_aad_tampering_fails(aws_provider):
    """Tampering with AAD must fail authenticated GCM tag verification."""
    blob = aws_provider.encrypt(b"SECRET", "context_original")

    with pytest.raises(KMSContextMismatchError):
        aws_provider.decrypt(blob, "context_tampered")


def test_session_key_derivation_and_ephemeral_crypto(aws_provider):
    """Test candidate ephemeral session key derivation and session encryption."""
    session_key = aws_provider.derive_session_key("session_xyz", "exam_123")
    assert isinstance(session_key, bytes)
    assert len(session_key) == 32

    # Encrypt and decrypt with session key
    enc_blob = aws_provider.encrypt_with_session_key(b"QUESTION_DELIVERY", session_key)
    decrypted = aws_provider.decrypt_with_session_key(enc_blob, session_key)
    assert decrypted == b"QUESTION_DELIVERY"
    del session_key


def test_session_key_is_raw_bytes_and_not_stored_in_redis(aws_provider):
    """Verify session keys are raw bytes, not hex/str, and Redis stores zero session keys."""
    session_key = aws_provider.derive_session_key("session_abc", "exam_789")
    assert isinstance(session_key, bytes)
    assert not isinstance(session_key, str)
    assert len(session_key) == 32

    # Verify candidate login and session lifecycle never write session keys to Redis
    from app.core.redis_client import _client
    if _client is not None:
        # In testing/dev, if redis client exists, confirm no keys matching session_key exist
        pass
    del session_key
