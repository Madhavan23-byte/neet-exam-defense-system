# B-SEA Security Audit V1

## 1. Executive Summary
This document provides a post-implementation security validation of the B-SEA reference architecture. The objective is to verify that the claimed security properties (Zero Trust, Cryptographic Isolation, Threshold Authorization, Tamper-Evident Auditing) are actually enforced by the system backend, rather than just being presented in the UI.

## 2. Existing Security Controls

| Security Control | Description | Status |
| :--- | :--- | :--- |
| Authentication | JWT-based Auth with TOTP MFA support. | **REAL** |
| Authorization (RBAC) | Role-based matrix enforced via FastAPI dependencies. | **REAL** |
| Cryptography (KMS) | AES-256-GCM encryption with per-resource keys. | **SIMULATED** (MockKMS used instead of Cloud HSM) |
| Threshold Authorization | Ed25519 multi-party approval required for exam release. | **SIMULATED** (Uses mock KMS signing, not true MPC/HSM) |
| Time-Locked Release | Exam release blocked before scheduled time. | **REAL** (Enforced by backend API) |
| Audit Trail | Hash-chained event log with tampering detection. | **REAL** |
| CBT Isolation | Candidate environment with heartbeat & anomaly tracking. | **SIMULATED** (Uses browser API restrictions, not OS-level lockdown) |

## 3. Security Evidence Matrix

| Security Claim | Implementation Location | Test | Result | Evidence | Status |
| -------------- | ----------------------- | ---- | ------ | -------- | ------ |
| Candidate Privilege Escalation | `app/api/v1/candidates.py` vs `app/core/dependencies.py` | | | | |
| Question Setter Cross-Access | `app/api/v1/questions.py` | | | | |
| IDOR Bypass | `app/core/dependencies.py` (ownership checks) | | | | |
| Bulk Question Extraction | (Missing Rate Limiter) | | | | |
| Answer-Key Exposure | `app/api/v1/candidates.py` (content mapping) | | | | |
| Early Exam Release | `app/api/v1/release.py` & `app/modules/release/service.py` | | | | |
| Threshold Bypass | `app/modules/release/service.py` | | | | |
| Question Tampering | `app/api/v1/candidates.py` (integrity hash check) | | | | |
| Audit-Log Tampering | `app/modules/audit/service.py` | | | | |
| CBT Security Violations | `app/api/v1/candidates.py` (heartbeat & events) | | | | |

## 4. Question Confidentiality Audit

**Target Property:** Before authorized release, no retrievable complete plaintext master examination paper should exist.

| Component | Plaintext Exists? | Duration | Who Can Access? | Risk |
| :--- | :--- | :--- | :--- | :--- |
| Authoring UI | Yes | Active session | Question Setter | LOW (Role isolated) |
| API Layer (`/questions`) | Yes | Request lifecycle | Setter, Reviewer, Moderator | LOW (Role isolated) |
| Database Storage | **NO** | N/A | None (Stored AES-256-GCM encrypted) | NONE |
| Exam Generation | **NO** | N/A | None (Uses encrypted IDs) | NONE |
| Release Auth | **NO** | N/A | None (Signs release payloads) | NONE |
| Candidate CBT | Yes | Render time | Candidate | HIGH (Requires Lockdown Browser) |

## 5. Key Management Audit (SIMULATED)

- **Where are keys generated?** In memory via `MockKMS.derive_session_key()` or random bytes.
- **Where are keys stored?** `MockKMS` stores them in an in-memory dictionary.
- **Can database compromise reveal keys?** No, keys are not in the DB.
- **Production Gap:** `MockKMS` must be replaced with AWS KMS, Azure KeyVault, or an on-premise Thales/Luna HSM.

*(The rest of this document will be populated after automated test execution and remediation).*
