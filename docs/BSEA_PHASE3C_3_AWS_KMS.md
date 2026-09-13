# B-SEA Phase 3C-3: AWS KMS Cryptographic Migration Architecture & Runbook

## 1. Executive Summary

Phase 3C-3 transitions B-SEA from the development/testing `MockKMS` prototype to a production-grade, enterprise-hardened cryptographic provider: `AWSKMSProvider`. This migration satisfies the fundamental B-SEA Security Invariant:

> **Core Security Invariant:**
> *"No application process, administrator, database record, environment variable, or compromised component should expose the private cryptographic key material used to protect B-SEA."*

All cryptographic operations are governed by AWS KMS hardware security modules (FIPS 140-2 / 140-3 Level 3 validated HSMs). The application receives only ephemeral data keys for symmetric envelope encryption and never receives or stores asymmetric private signing keys.

---

## 2. Validation Status Delineation (Three-Tier Status)

To prevent ambiguity regarding infrastructure and test coverage, B-SEA explicitly distinguishes between local testing, static infrastructure validation, and live cloud deployment:

| Validation Tier | Current Status | Details |
| :--- | :--- | :--- |
| **Tier 1: Local / Offline Cryptographic Validation** | **VERIFIED (26/26 PASS)** | Unit and security regression suite executed locally using Python 3.14 virtual environment with `MockKMS` and stubbed botocore client fixtures. Covers envelope encryption, context binding, AAD tampering, Ed25519 signing/verification, and error boundaries. |
| **Tier 2: Terraform Static Validation** | **VERIFIED (PASS)** | Configuration formatted (`terraform fmt`), initialized with locked AWS provider `v6.64.0` (`terraform init -backend=false`), and statically validated (`terraform validate`). Schema supports `ECC_NIST_EDWARDS25519`. |
| **Tier 3: Live AWS KMS Integration Validation** | **PENDING** | Requires live AWS staging credentials and actual AWS KMS API calls. Not executed in this phase. |
| **Infrastructure Deployment (`terraform apply`)** | **NOT EXECUTED** | No cloud resources provisioned or modified. |
| **AWS Cloud Resources** | **NOT DEPLOYED** | Staging VPC, KMS keys, RDS, and ECS tasks remain undeployed pending change authorization. |

---

## 3. Cryptographic Architecture

### 3.1 Symmetric Envelope Encryption (`AES-256-GCM`)

For question bank contents, sensitive exam forms, and exam state:
1. **Envelope Architecture:**
   - Plaintexts are not sent directly to KMS. B-SEA requests an ephemeral 256-bit data encryption key (DEK) via:
     `kms:GenerateDataKey(KeyId=..., KeySpec="AES_256", EncryptionContext={"context": canonical_context})`.
   - KMS returns:
     - `Plaintext`: 32-byte ephemeral AES key (`bytes`).
     - `CiphertextBlob`: Encrypted Data Key (EDK) wrapped under the Customer Managed Key (CMK).
   - Plaintext payload is encrypted in memory using standard `AES-256-GCM` with a cryptographically secure 12-byte CSPRNG nonce (`os.urandom(12)`).
   - **Dual Context Binding:** The canonical context string (e.g. `question:{q_id}:exam:{exam_id}`) is bound **both** to the KMS `EncryptionContext` (attaching to the wrapped EDK) and as Authenticated Additional Data (AAD) in `AES-256-GCM`.
   - **Ephemeral DEK Memory Lifecycle:** Plaintext keys are held for the absolute minimum lifetime required for cipher operations, references and buffers are explicitly dereferenced (`del plaintext_key`), and keys are never persisted to disk, database, Redis, or logs.
2. **Binary Envelope Layout (Version `0x01`):**
   ```text
   +----------------+----------------+---------------------+----------------+----------------+----------------+
   | Version (0x01) | EDK Length     | Encrypted Data Key  | GCM Nonce      | Ciphertext     | GCM Tag        |
   | (1 byte)       | (2 bytes, BE)  | (variable length)   | (12 bytes)     | (variable)     | (16 bytes)     |
   +----------------+----------------+---------------------+----------------+----------------+----------------+
   ```
   The binary envelope is base64-encoded and returned as `EncryptedBlob.ciphertext_b64`.

3. **Decryption Flow:**
   - The binary envelope is parsed and verified for format integrity (checking version `0x01` and length bounds).
   - The EDK is unwrapped via `kms:Decrypt(CiphertextBlob=edk, EncryptionContext={"context": canonical_context})`.
   - If the context does not match the original encryption context, KMS fails closed (`InvalidCiphertextException`).
   - The plaintext DEK unwrapped by KMS decrypts the ciphertext using `AES-256-GCM` with the extracted nonce, tag, and verified AAD (`context.encode("utf-8")`).
   - If the AAD has been tampered with or transplanted between questions/exams, `AES-256-GCM` authentication tag verification fails immediately (`InvalidTag`).
   - Plaintext DEK buffers are immediately dereferenced (`del plaintext_key`).

### 3.2 Asymmetric Digital Signatures (`Ed25519`)

For audit log tamper-evidence, exam blueprint sealing, and candidate submission integrity:
1. **AWS KMS Native Ed25519:**
   - KMS Key Spec: `ECC_NIST_EDWARDS25519`.
   - Key Usage: `SIGN_VERIFY`.
   - Signing Algorithm: `ED25519_SHA_512`.
   - Message Type: `RAW`.
2. **Asymmetric Security Boundary:**
   - KMS executes private key operations strictly inside the HSM boundary.
   - The private key is non-exportable; neither the application, developers, nor AWS administrators can extract the private key.
   - Signatures are generated by sending payload bytes directly to `kms:Sign`.
3. **Local Offline Verification & Public-Key Caching:**
   - To eliminate KMS API latency and cost on read-heavy verification flows, public keys are retrieved once via `kms:GetPublicKey` and loaded into memory as `ed25519.Ed25519PublicKey`.
   - Verification is executed locally via standard cryptography primitives (`public_key.verify(sig, data)`).
   - **Cache Invariant:** Public keys are cached strictly by **exact KMS Key ARN / Key ID**, never by alias. This guarantees that historical signatures remain verifiable even when active aliases point to newer rotated keys.

### 3.3 Ephemeral Session Key Derivation & Redis Invariants

1. **Session Key Semantics (`derive_session_key`):**
   - AWS KMS does not expose an arbitrary PRF/HKDF derivation API for symmetric KMS master keys.
   - To preserve interface compatibility with `MockKMS`, `AWSKMSProvider.derive_session_key(session_id, exam_id)` requests an ephemeral 256-bit AES data key via `kms:GenerateDataKey` with `EncryptionContext={"context": f"session:{session_id}:exam:{exam_id}"}`.
   - The returned ephemeral key is raw 32-byte `bytes`.
   - Redundant dictionary references from the AWS SDK response are immediately discarded (`del response`).
2. **Strict Redis Storage Invariant:**
   - **Redis is NEVER used to store session keys, raw plaintext AES keys, hex representations, base64 strings, or serialized key objects.**
   - Redis in B-SEA is strictly isolated to:
     1. Distributed rate limiting bucket counters (`slowapi`).
     2. Infrastructure health probes (`/health/ready`).
   - Candidate session records are persisted exclusively in PostgreSQL (`CandidateSession` table) with hashed tokens (`session_token_hash`) and an encrypted session key envelope (`session_key_encrypted`).
   - In candidate login flows, plaintext `session_key` references are immediately deleted (`del session_key`) once the encrypted session key is produced.

---

## 4. Python Key Material Handling Invariant

In high-level managed runtime environments like CPython, guaranteed deterministic memory zeroization is fundamentally impossible due to string interning, immutable `bytes` objects, small integer caching, generational garbage collection, and OS virtual memory paging.

Therefore, B-SEA enforces the following rigorous, technically accurate memory handling invariants:
1. **Minimum Required Lifetime:** Plaintext data keys exist only within the local execution frame of `encrypt()`, `decrypt()`, or `derive_session_key()`.
2. **Explicit Reference Release:** Plaintext key references and byte buffers are explicitly dereferenced via `del plaintext_key` in `finally` blocks.
3. **Strict Non-Persistence:** Plaintext data keys are never logged, serialized, placed in cache layers (Redis), or persisted to storage (PostgreSQL/S3).
4. **No Plaintext Master Keys:** The application process never possesses, receives, or manipulates master cryptographic keys.
5. **Buffer Handling:** Avoid intermediate string/hex conversions where raw `bytes` are sufficient.

---

## 5. Key Rotation Architecture & Runbook

### 5.1 Symmetric Key Rotation (AWS-Managed)

- **Configuration:** `enable_key_rotation = true` on `aws_kms_key.symmetric_encryption`.
- **Mechanism:** AWS KMS automatically rotates the backing cryptographic key material every 365 days.
- **Envelope Invariant:** Existing Encrypted Data Keys (EDKs) stored in the database are **not** re-encrypted upon master key rotation. AWS KMS maintains historical backing keys to decrypt older EDKs indefinitely.
- **Application Impact:** Completely transparent; no application downtime or migration scripts required.

### 5.2 Asymmetric Ed25519 Key Rotation (Manual Provisioning)

Because asymmetric KMS keys cannot be automatically rotated by KMS:
1. **Provision New Key:**
   - Create a new KMS key with `customer_master_key_spec = "ECC_NIST_EDWARDS25519"`.
2. **Update Alias:**
   - Re-point alias `alias/bsea-staging-signing` to the new key ARN.
3. **Application Transition:**
   - Update ECS task environment variable `KMS_SIGNING_KEY_ID` with the new key ARN.
   - New signatures are created using the new KMS key.
4. **Historical Signature Verification Invariant:**
   - **Never disable or delete the previous signing key.**
   - Historical signed blobs and audit records carry the exact `key_id` used at signing time.
   - The public key cache resolves the exact key ARN via `kms:GetPublicKey` and verifies historical signatures offline without failure.

---

## 6. Least-Privilege IAM Policy

The ECS Task Role (`aws_iam_role.ecs_task`) is granted only the minimum required KMS actions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "BSEASymmetricCrypto",
      "Effect": "Allow",
      "Action": [
        "kms:GenerateDataKey",
        "kms:Decrypt",
        "kms:DescribeKey"
      ],
      "Resource": [
        "arn:aws:kms:ap-south-1:ACCOUNT_ID:key/SYMMETRIC_KEY_ID"
      ]
    },
    {
      "Sid": "BSEAAsymmetricSigning",
      "Effect": "Allow",
      "Action": [
        "kms:Sign",
        "kms:GetPublicKey",
        "kms:DescribeKey"
      ],
      "Resource": [
        "arn:aws:kms:ap-south-1:ACCOUNT_ID:key/SIGNING_KEY_ID"
      ]
    }
  ]
}
```

### Security Boundary Guarantees:
- **`kms:Verify` Omitted:** B-SEA verifies signatures locally using the cached public key. Granting `kms:Verify` to ECS is unnecessary attack surface.
- **Administrative Rights Prohibited:** The ECS task role has no permissions for `kms:CreateKey`, `kms:ScheduleKeyDeletion`, `kms:PutKeyPolicy`, `kms:EnableKey`, or `kms:DisableKey`.
- **No Wildcards:** `Resource` elements are explicitly pinned to the symmetric and asymmetric key ARNs.

---

## 7. Audit & AWS CloudTrail Correlation

Every cryptographic event logged by B-SEA application security logging correlates directly with AWS CloudTrail KMS API records:

| B-SEA Application Event | CloudTrail EventName | CloudTrail Resources | Sensitive Data Logged |
| :--- | :--- | :--- | :--- |
| `KMS_ENVELOPE_ENCRYPT` | `GenerateDataKey` | Symmetric Key ARN, EncryptionContext | None (zero plaintext/key logging) |
| `KMS_ENVELOPE_DECRYPT` | `Decrypt` | Symmetric Key ARN, EncryptionContext | None |
| `KMS_ED25519_SIGN` | `Sign` | Asymmetric Key ARN, SigningAlgorithm | None |
| `KMS_PUBLIC_KEY_CACHED`| `GetPublicKey` | Asymmetric Key ARN | None |

### Zero-Logging Guarantee:
Application logging strictly excludes:
- Plaintext question stems and options
- Answer keys and scoring rubrics
- Plaintext data encryption keys (DEKs)
- Candidate session keys
- Asymmetric private keys
- AWS credentials and secret tokens

---

## 8. Health Check Integration

- **`/health/live` (Liveness Probe):**
  - Evaluates local process health only.
  - Independent of external dependencies (Redis, PostgreSQL, KMS).
  - Ensures container is not restarted prematurely during transient network or cloud provider glitches.
- **`/health/ready` (Readiness Probe):**
  - Evaluates dependency reachability (PostgreSQL, Redis, KMS).
  - For KMS, performs a safe configuration and provider check (`get_kms()`).
  - **Information Disclosure Defense:** Never returns key ARNs, AWS account IDs, or raw AWS exception details in the public HTTP response.
