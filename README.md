# B-SEA — Bharat Secure Examination Architecture

> **Protect the Question. Protect the Examination. Protect Every Candidate.**

## Overview

High-stakes examinations require protection across the entire question-paper lifecycle, from question creation through controlled release and examination delivery. Traditional approaches rely heavily on physical security and trusted individuals, which creates single points of failure.

B-SEA (Bharat Secure Examination Architecture) is a security-focused reference implementation designed around a core zero-trust principle:

**"No single person, account, server, examination centre, administrator, or compromised component should be sufficient to obtain the complete examination paper before authorized release."**

## Key Security Principles

- **Zero Trust:** Continuous validation of identity, context, and cryptographic state.
- **Least Privilege:** Granular access controls ensuring actors only access what they explicitly require.
- **RBAC:** Role-Based Access Control enforcing strict operational boundaries.
- **MFA-Ready Authentication:** Framework supporting multi-factor identity verification.
- **Question Compartmentalization:** Questions are encrypted and managed individually; there is no monolithic "master paper" artifact prior to CBT rendering.
- **Individual Question Encryption:** AES-256-GCM encryption for each question and its options.
- **Integrity Verification:** Cryptographic hashing detects tampering at rest and in transit.
- **Digital Signatures:** Ed25519 signatures to ensure questions originate from authorized setters.
- **Threshold Release Authorization:** Cryptographic threshold (e.g., 3-of-5 authorities) required to release the decryption key to examination centres.
- **Time-Controlled Release:** The examination cannot be opened before the exact scheduled global start time.
- **Secure CBT Delivery:** The candidate client receives encrypted questions; decryption happens ephemerally in memory.
- **Audit Integrity:** Cryptographically chained audit logs (hash chain) to detect post-event tampering or log deletion.
- **Anomaly Detection:** Monitoring for unexpected behavior, such as bulk extraction attempts or irregular tab switching.
- **Blast-Radius Containment:** Compromise of one centre's network or one candidate's device does not expose the entire question bank.
- **Answer-Key Isolation:** Answer keys are stored separately and are completely inaccessible to candidates, proctors, and even local exam delivery servers during the examination.

## Architecture

The architecture separates concerns strictly:

`Frontend (React/Vite)` → `API (FastAPI)` → `Services` → `Repositories` → `Database (PostgreSQL) / Object Storage (MinIO)`

**Secure Question Lifecycle:**
1. **Authoring:** Setter drafts the question. It is encrypted client-side or immediately at the API boundary. A digital signature is applied.
2. **Review/Moderation:** Reviewers can decrypt individual questions they are assigned to, but cannot see the full exam.
3. **Assembly:** The exam blueprint selects encrypted question objects. Still, no plaintext master paper exists.
4. **Distribution:** Encrypted blobs are distributed to examination centres.
5. **Threshold Release:** Release Authorities submit their individual cryptographic approvals. Once the threshold is met, the decryption key is released to centres exactly at the start time.
6. **Delivery:** Candidate devices fetch encrypted questions and decrypt them ephemerally in memory using the securely distributed key.

## Question Security Model

Questions are represented as standalone encrypted objects, not as documents.

An object includes:
- **Question ID** & **Version**
- **Encrypted Content** (Question text/images)
- **Encrypted Answer** (Isolated)
- **Key Reference** (Identifier for the KMS key used)
- **Integrity Hash** (SHA-256)
- **Digital Signature** (Ed25519)
- **Lifecycle State** (Draft, Approved, Selected)
- **Metadata** (Topic, Difficulty)

## Release Security

The release process ensures no individual administrator can leak the paper:

`Blueprint` → `Eligible Question Pool` → `Secure Selection` → `Candidate/Form Assignment` → `Multi-party Authorization` → `Controlled Release` → `CBT Delivery`

## Roles

B-SEA implements strict Role-Based Access Control:

- **System Administrator:** Manages infrastructure and roles (cannot see questions).
- **Exam Administrator:** Schedules exams and assigns candidates.
- **Question Setter:** Creates and signs questions.
- **Release Authority:** One of N individuals holding a threshold key share required for exam release.
- **Candidate:** The test-taker.
- **Security/Audit Role:** Read-only access to immutable security logs and audit chains.

## Security Testing

B-SEA has been validated against a suite of simulated attack scenarios.

**Status:** 21/21 Security Assertions Passed.

Tests confirm:
- Setters cannot access audit logs.
- Administrators cannot see plaintext questions.
- Candidates cannot access other candidates' sessions.
- Bulk extraction attempts trigger rate-limiting defenses.
- Early exam release is cryptographically blocked.
- Single administrators cannot bypass threshold release.
- Tampered questions are detected via signature validation.
- The audit hash chain correctly detects tampering.

*Note: This is a security-focused reference implementation. While 21/21 automated attack simulations passed in the test environment, this does not mean the system is "100% secure" or "impossible to leak". Real-world deployment requires professional penetration testing and secure infrastructure.*

## Performance Testing

Performance and scalability have been baselined in three phases:

- **Phase 3A:** Baseline assessment against SQLite, revealing file-level locking bottlenecks under concurrent load.
- **Phase 3B:** Performance optimization, offloading CPU-bound tasks (Argon2) and implementing asynchronous audit queues.
- **Phase 3C (PostgreSQL Validation):** The data layer has been successfully refactored for PostgreSQL (using `asyncpg` and Alembic) with row-level locking for atomic transactions. **Note: PostgreSQL implementation exists, but full PostgreSQL runtime validation remains pending due to local environment constraints.** Tests were verified against the SQLite fallback layer.

## Prototype vs Production

| Capability | Current Implementation | Production Requirement |
|---|---|---|
| KMS | Prototype (MockKMS) | Cloud KMS / Hardware Security Module (HSM) |
| Database | Prototype/Testing (SQLite) | PostgreSQL 16+ |
| Rate Limiter | Prototype (In-memory) | Distributed Redis-backed limiter |
| Audit Queue | Prototype (Process-local queue) | Durable event streaming (Kafka) + SIEM |
| Release Auth | Prototype (Simulated threshold) | Production-grade threshold cryptography / HSM |
| Hosting | Local Docker / uvicorn | Kubernetes / multi-worker gunicorn behind PgBouncer |

## Threat Model

B-SEA is designed to mitigate the following primary threats:

- **Insider Threat:** Mitigated by least privilege, RBAC, and threshold release.
- **Credential Compromise:** Mitigated by MFA-ready architecture.
- **Privilege Escalation & IDOR:** Mitigated by strict resource-level authorization boundaries.
- **Bulk Extraction:** Mitigated by layered rate limiting and anomaly detection.
- **Question Tampering:** Mitigated by Ed25519 digital signatures.
- **Early Release:** Mitigated by time-locks and multi-party threshold authorization.
- **Answer-Key Exposure:** Answer keys are isolated and not transmitted during the exam.
- **Audit Tampering:** Mitigated by a cryptographic hash chain of all critical events.

## Limitations

No software-only architecture can guarantee absolute zero leakage once authorized plaintext is displayed to a trusted human or device (e.g., photographing a screen).

B-SEA focuses on minimizing exposure, compartmentalizing access, detecting unauthorized behavior, protecting integrity, and limiting the blast radius of any single compromised component.

## Future Production Architecture

To reach production readiness, the architecture must be deployed with:
- PostgreSQL (Primary/Replica) with PgBouncer
- Redis for distributed caching and rate limiting
- Kafka / Event Streaming for durable audit logs
- WAF / CDN for DDoS protection
- SIEM / SOC integration for anomaly alerting
- Immutable / WORM audit storage
- FIDO2 / WebAuthn for strong authentication
- mTLS for service-to-service identity

## License

[LICENSE PLACEHOLDER - A definitive open-source license must be selected before public release.]
