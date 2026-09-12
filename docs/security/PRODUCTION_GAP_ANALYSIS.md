# B-SEA Production Gap Analysis

**Date:** 2026-09-12
**Scope:** Bharat Secure Examination Architecture (B-SEA) Reference Implementation

While the current B-SEA reference implementation successfully enforces all 17 core security scenarios in an automated test environment, it remains a prototype. Transitioning this architecture to a national-scale production environment requires addressing several critical gaps.

---

## 1. Cryptography & Key Management

**Current Implementation:**
* Mock KMS (`mock_kms.py`) using symmetric keys derived from hardcoded secrets.
* Keys stored in memory or alongside the database.

**Production Gap:**
* **Hardware Security Modules (HSM):** Must transition to physical/cloud HSMs (e.g., AWS KMS, Azure Key Vault, Thales) to ensure keys never leave the hardware boundary.
* **Key Rotation:** No automated key rotation for active exams or historical data.
* **Envelope Encryption:** Currently encrypting entire payloads with a single KMS call. Production should use envelope encryption (DEK + KEK) to improve performance and limit exposure.
* **Post-Quantum Cryptography (PQC):** The current suite (AES-256-GCM / SHA-256) is strong, but a national system with 50-year data retention requirements should plan for PQC algorithms (e.g., Kyber/ML-KEM) for key exchange.

---

## 2. Distributed Audit & Tamper Resistance

**Current Implementation:**
* In-database SQLite table with sequential cryptographic hash chaining.
* Mutex lock used to ensure sequential writes (`asyncio.Lock()`).

**Production Gap:**
* **Distributed Ledger Technology (DLT):** A single relational database is insufficient to guarantee non-repudiation against an insider threat with DBA access. The audit log must be written to an append-only distributed ledger or immutable storage (e.g., AWS QLDB, WORM storage).
* **Throughput:** A global mutex lock will severely bottleneck a system serving millions of candidates concurrently. Audit logs must be decoupled using message queues (e.g., Kafka) with micro-batch hashing to support high throughput without sacrificing cryptographic integrity.

---

## 3. High Availability & Scalability

**Current Implementation:**
* Single monolithic FastAPI process running against a local SQLite database.

**Production Gap:**
* **Distributed Architecture:** The system must be broken into microservices (Authentication, Question Delivery, Audit, Release).
* **Database Scaling:** SQLite must be replaced with a horizontally scalable, globally distributed, relational database (e.g., CockroachDB, Aurora PostgreSQL) to support cross-region failover.
* **Caching:** No caching layer exists. Question delivery for millions of candidates will require secure edge caching or distributed caching (Redis) that preserves end-to-end encryption.

---

## 4. Rate Limiting & DDoS Mitigation

**Current Implementation:**
* In-memory `slowapi` rate limiting.

**Production Gap:**
* **Stateful Distributed Limits:** Rate limits are currently per-instance and in-memory. They must be backed by a distributed store (Redis) to enforce global limits across thousands of application servers.
* **Edge Protection:** The application relies on application-layer rate limiting. Production requires edge protection (WAF, Cloudflare, AWS Shield) to absorb volumetric DDoS attacks before they hit the API layer.

---

## 5. Client-Side Security & CBT Environment

**Current Implementation:**
* Assumes a secure client is making API calls.

**Production Gap:**
* **Secure Browser:** The API cannot trust a standard web browser. It requires a locked-down client (e.g., Safe Exam Browser integration) that performs local environment attestation.
* **Proctoring Integration:** No APIs currently exist to ingest continuous biometric or environmental proctoring telemetry.

---

## 6. Access Control & Zero Trust

**Current Implementation:**
* JWT-based authentication with simple RBAC.

**Production Gap:**
* **Short-Lived Credentials:** Long-lived JWTs (even 1 hour) are risky. Implementation should enforce short-lived access tokens (5 minutes) with rotating refresh tokens, or mTLS for service-to-service communication.
* **Continuous Authorization:** Authorization is currently checked once per request. Production should support continuous authorization evaluating device posture and contextual risk (e.g., IP velocity) on every action.
