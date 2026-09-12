# B-SEA Security Inspection Report (Phase 1)
**Version:** 1.0
**Status:** Inspection Complete (Preliminary)
**Phase:** Security Audit, Attack Simulation & Hardening

## 1. Current Implementation Summary
The B-SEA (Bharat Secure Examination Architecture) prototype has been successfully inspected. The system implements a robust layered architecture combining a FastAPI backend, a React frontend, and a simulated cryptographic KMS layer. The core objective—preventing unauthorized access to examination content—is structurally present, but several critical gaps exist in the enforcement of these policies. 

The application successfully demonstrates the *concept* of zero-trust examination delivery, but relies on several simulated mechanisms (like `MockKMS`) and contains implementation flaws (like missing role-based decorators) that must be hardened before it can be considered a secure reference implementation.

## 2. Architecture Actually Implemented
- **Frontend:** React + Vite SPA, utilizing JWT for authentication. Role-based routing is present.
- **Backend:** FastAPI with SQLAlchemy (async). 
- **Database:** SQLite (prototype) with `JSON` column support. UUIDs are used for all primary keys.
- **Cryptography:** A `MockKMS` interface implements AES-256-GCM for encryption, Ed25519 for signatures, and SHA-3-256 for integrity hashing. 
- **Delivery:** Candidate CBT is implemented with a session-based, per-question delivery model that successfully decouples the answer key from the question payload.

## 3. REAL / SIMULATED / UI-ONLY / MISSING Matrix

| Security Mechanism | Status | Notes |
| :--- | :--- | :--- |
| **1. Frontend structure** | REAL | React SPA with proper routing. |
| **2. Backend structure** | REAL | FastAPI + SQLAlchemy async architecture. |
| **3. Database/models** | REAL | Complete schema with UUIDs, relationships, and indexes. |
| **4. Authentication** | REAL | JWT-based authentication implemented. |
| **5. RBAC and permissions** | REAL / INCOMPLETE | `UserRoleEnum` exists, but decorators (`require_role`) are missing on critical endpoints (e.g., Audit logs). |
| **6. Question authoring** | REAL | Questions stored as plaintext only while in DRAFT status. |
| **7. Question encryption** | REAL | `MockKMS` encrypts approved questions and clears plaintext from the database. |
| **8. Question storage** | REAL | Ciphertext stored with integrity hashes and Ed25519 signatures. |
| **9. Exam blueprint** | SIMULATED | JSON config stored and signed, but lacks structural enforcement. |
| **10. Form generation** | SIMULATED | Question/option randomization exists, but lacks cryptographic isolation (no per-form keys). |
| **11. Release workflow** | REAL | Automated release engine verifies time, thresholds, and conditions. |
| **12. Threshold approval** | SIMULATED | Uses individual signed records rather than true Shamir's Secret Sharing (SSS) or HSM consensus. |
| **13. Time-lock enforcement** | REAL | Backend strictly verifies `server_time >= scheduled_start_utc`. |
| **14. Candidate CBT** | REAL | Session tokens, per-question delivery, and heartbeat implemented. |
| **15. Answer-key protection** | REAL | Answer keys stored in a completely separate table; isolated from Candidate APIs. |
| **16. Audit logging** | REAL | Comprehensive audit logs written for major events. |
| **17. Hash-chain implementation** | SIMULATED | Sequential hashing (`prev_hash` + `event_hash`) exists, but lacks DB-level concurrency locks. |
| **18. Security console** | REAL | Frontend dashboard and backend `/events` API exist. |
| **19. Anomaly detection** | SIMULATED | Basic checks (e.g., tab switches from heartbeat) flag the session. |
| **20. Incident response** | SIMULATED | Incidents can be logged, but automated system lockdown is limited. |
| **21. Emergency form replacement**| MISSING | No logic found for hot-swapping forms during an active exam. |
| **22. Session/token handling** | REAL | High-entropy candidate tokens (48 bytes), hashed before DB storage. |
| **23. Rate limiting** | MISSING | No rate-limiting middleware or endpoint restrictions found. |
| **24. Secrets/configuration** | SIMULATED | Master keys derived from environment variables instead of a secure Vault/HSM. |
| **25. Centre isolation** | SIMULATED | Centre model exists, but API does not actively restrict IPs yet. |
| **26. Form isolation** | SIMULATED | Forms randomize display, but do not use unique cryptographic keys per form. |
| **27. API authorization** | INCOMPLETE | Several critical endpoints (e.g., `/audit/logs`, `/security/events`) are accessible to any authenticated user. |
| **28. Production architecture** | SIMULATED | Uses SQLite and `MockKMS`. |

## 4. Important Security Weaknesses Found
1. **Broken Access Control (IDOR / Over-privilege):** The `@router.get("/logs")` endpoint in `audit.py` and the endpoints in `security.py` lack the `require_role` dependency. Any authenticated user (including a candidate if routes are mixed, or a question setter) can view all audit logs and security events.
2. **Missing Rate Limiting:** There is no rate limiting on APIs. An authenticated administrator or compromised service account could script the extraction of the entire encrypted question bank (`GET /questions/`).
3. **Authentication Bypass (Candidate Login):** In `candidates.py`, the `/auth/login` endpoint completely ignores the provided password, authenticating the candidate solely based on the existence of the `registration_number`.
4. **Audit Hash Chain Race Conditions:** The hash chain logic in `AuditService.log` retrieves the maximum sequence and last hash but does not use database locks (e.g., `SELECT ... FOR UPDATE`), meaning concurrent events could fork the hash chain.

## 5. Important Architectural Inconsistencies
- **Form Cryptography:** The architecture claims "Form isolation", but forms currently only shuffle question order via JSON mapping. True form isolation would require re-encrypting the question payload with a form-specific key.
- **KMS Statefulness:** The `MockKMS` singleton state works in a single-process `uvicorn` setup but will fail horizontally if scaled, as session keys derived and cached in memory wouldn't be shared. Production requires Redis-backed session key caching or stateless derivation.

## 6. Recommended Attack Tests
Based on the inspection, the following automated tests (already partially drafted in `tests/security/test_attacks.py`) must be executed and passed:
1. `test_candidate_cannot_access_admin_api`: Verify role separation.
2. `test_setter_cannot_access_audit_logs`: Verify missing RBAC decorators are fixed.
3. `test_bulk_extraction_rate_limit`: Implement and verify rate limiting.
4. `test_candidate_login_requires_password`: Verify the authentication bypass is patched.
5. `test_audit_chain_verification`: Ensure sequential hashing works under load.

## 7. Production Gaps
- **Hardware Security Module (HSM):** `MockKMS` must be replaced with Cloud KMS / HSM integrations.
- **Database:** SQLite must be swapped for PostgreSQL (requires replacing `JSON` with `JSONB` native operators).
- **Concurrency:** Implement Redis for distributed rate-limiting and session key caching.
