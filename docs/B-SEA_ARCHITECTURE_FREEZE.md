# B-SEA Architecture Freeze v1.0
## Bharat Secure Examination Architecture — Global Secure Examination Platform
**Date:** 2026-09-12 | **Status:** FROZEN — Implementation May Begin

---

## 1. FINAL SYSTEM ARCHITECTURE

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        INTERNET / CANDIDATE                              │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │ HTTPS / TLS 1.3
┌──────────────────────────────▼──────────────────────────────────────────┐
│                         CDN / WAF Layer                                  │
│              (Cloudflare / Nginx proxy in prototype)                     │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────────────┐
│                    React Frontend (Vite + TypeScript)                    │
│  ┌─────────────┐ ┌──────────────┐ ┌──────────────┐ ┌────────────────┐  │
│  │ Landing     │ │ Admin Portal │ │ Authoring    │ │ Candidate CBT  │  │
│  │ Public      │ │ Dashboards   │ │ Portal       │ │ Secure Exam    │  │
│  └─────────────┘ └──────────────┘ └──────────────┘ └────────────────┘  │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │ REST API (JSON)
┌──────────────────────────────▼──────────────────────────────────────────┐
│                   FastAPI Backend (Python 3.12)                          │
│                                                                          │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌─────────────┐  │
│  │  auth    │ │ question │ │  exam    │ │candidate │ │  security   │  │
│  │ service  │ │ service  │ │ service  │ │ service  │ │  service    │  │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └─────────────┘  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌─────────────┐  │
│  │ release  │ │  audit   │ │blueprint │ │evaluation│ │  incident   │  │
│  │ service  │ │ service  │ │ service  │ │ service  │ │  service    │  │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └─────────────┘  │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────────────────┐
│                            DATA LAYER                                    │
│   ┌────────────────┐  ┌──────────────┐  ┌──────────────────────────┐   │
│   │  PostgreSQL 16 │  │  Redis 7     │  │  MinIO (S3-compatible)   │   │
│   │  (Primary DB)  │  │  (Sessions)  │  │  (Encrypted Q Objects)   │   │
│   └────────────────┘  └──────────────┘  └──────────────────────────┘   │
│   ┌────────────────────────────────────────────────────────────────┐    │
│   │  MockKMS (prototype) → Cloud KMS / HSM (production)           │    │
│   └────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 2. MODULE ARCHITECTURE

### Backend Modules (Modular Monolith — Not Premature Microservices)

```
backend/
├── app/
│   ├── core/
│   │   ├── config.py          # Environment configuration
│   │   ├── security.py        # JWT, password hashing, token management
│   │   ├── database.py        # PostgreSQL connection + session
│   │   ├── redis_client.py    # Redis connection
│   │   ├── events.py          # Internal event bus (Kafka-replaceable)
│   │   └── dependencies.py    # FastAPI dependency injection
│   │
│   ├── crypto/
│   │   ├── kms_interface.py   # KMS abstraction (INTERFACE — never bypass)
│   │   ├── mock_kms.py        # Prototype: software KMS
│   │   ├── aes_gcm.py         # AES-256-GCM encrypt/decrypt
│   │   ├── signatures.py      # Ed25519 sign/verify
│   │   ├── hashing.py         # SHA-3-256, integrity hashing
│   │   └── threshold.py       # Threshold authorization simulator
│   │
│   ├── modules/
│   │   ├── auth/              # Authentication & session management
│   │   ├── users/             # User management & RBAC
│   │   ├── organizations/     # Multi-org support
│   │   ├── questions/         # Question lifecycle & encryption
│   │   ├── exams/             # Exam management
│   │   ├── blueprints/        # Exam blueprint engine
│   │   ├── forms/             # Multi-form generation
│   │   ├── release/           # Time-locked release engine
│   │   ├── candidates/        # Candidate management
│   │   ├── sessions/          # Exam session management
│   │   ├── delivery/          # Secure question delivery
│   │   ├── responses/         # Answer collection
│   │   ├── evaluation/        # Score calculation (answer-key isolated)
│   │   ├── audit/             # Hash-chained audit logging
│   │   ├── security/          # Anomaly detection & risk scoring
│   │   └── incidents/         # Incident response
│   │
│   └── api/
│       └── v1/
│           └── router.py      # Route aggregation
```

### Frontend Modules

```
frontend/
├── src/
│   ├── components/
│   │   ├── ui/                # Design system components
│   │   ├── security/          # Security status, watermark, alerts
│   │   ├── exam/              # Exam-specific components
│   │   └── charts/            # Dashboard charts
│   │
│   ├── pages/
│   │   ├── public/            # Landing, about, architecture
│   │   ├── auth/              # Login, MFA
│   │   ├── admin/             # All admin portals
│   │   ├── authoring/         # Question authoring portal
│   │   ├── candidate/         # CBT exam environment
│   │   └── security/          # Security console
│   │
│   ├── services/              # API client services
│   ├── stores/                # Zustand state management
│   ├── hooks/                 # Custom React hooks
│   └── types/                 # TypeScript types
```

---

## 3. DATABASE DESIGN

### Core Schema (PostgreSQL)

```sql
-- Organizations (global, multi-org support)
organizations: id, name, type, country, timezone, config_json, created_at

-- Users
users: id, org_id, email, password_hash, full_name, is_active, 
       mfa_enabled, mfa_secret_encrypted, last_login, created_at

-- Roles & RBAC
roles: id, name, description
permissions: id, resource, action, description
user_roles: user_id, role_id, org_id, exam_id (nullable — exam-scoped roles)
role_permissions: role_id, permission_id

-- Exams
exams: id, org_id, title, description, exam_type, security_mode,
       scheduled_start_utc, scheduled_end_utc, duration_minutes,
       status, created_by, created_at

-- Exam Blueprints
exam_blueprints: id, exam_id, config_json_encrypted, integrity_hash,
                 digital_signature, status, approved_by, approved_at, created_at

-- Questions (metadata only — content in object store)
questions: id, exam_id, author_id, subject, topic, difficulty,
           bloom_level, format, status, version, object_store_key,
           content_hash, digital_signature, key_reference,
           created_at, approved_at, approved_by

-- Question Versions (immutable history)
question_versions: id, question_id, version, author_id, object_store_key,
                   content_hash, change_summary, created_at

-- Question Reviews
question_reviews: id, question_id, reviewer_id, verdict, comments,
                  reviewed_at, signature

-- Exam Forms (per-candidate form assignments)
exam_forms: id, exam_id, form_label, seed_encrypted, question_ids_encrypted,
            integrity_hash, status, generated_at

-- Form-Question Mapping
form_questions: id, form_id, question_id, display_order, option_order_json

-- Candidates
candidates: id, org_id, external_id, full_name, email, phone_hash,
            identity_verified, registration_data_encrypted, created_at

-- Candidate Sessions
candidate_sessions: id, candidate_id, exam_id, form_id, centre_id,
                    session_token_hash, session_key_encrypted,
                    started_at, expires_at, submitted_at, status,
                    ip_address_hash, device_fingerprint, violations_json

-- Responses (answers)
responses: id, session_id, question_id, selected_option, is_marked_review,
           saved_at, response_sequence, response_signature

-- Release Approvals (threshold simulation)
release_approvals: id, exam_id, authority_id, approved_at,
                   approval_signature, nonce

-- Centres
centres: id, org_id, name, location, centre_code, status,
         device_count, checked_in_at

-- Devices
devices: id, centre_id, device_fingerprint, device_type,
         registered_at, last_seen, status

-- Audit Logs (hash-chained)
audit_logs: id, seq, event_type, actor_id, role, resource_type,
            resource_id, action, result, ip_hash, device_id,
            metadata_json, risk_score, prev_hash, event_hash,
            timestamp

-- Security Events
security_events: id, event_type, severity, actor_id, session_id,
                 details_json, risk_score, resolved, created_at

-- Incidents
incidents: id, title, severity, status, created_by, assigned_to,
           exam_id, description, resolution, created_at, resolved_at

-- Evaluation (answer keys — separate access control)
answer_keys: id, question_id, correct_option, partial_marks_json,
             marks_positive, marks_negative, key_hash, created_by

-- Results
results: id, session_id, candidate_id, exam_id, total_score,
         max_score, percentile, rank, generated_at, result_signature
```

---

## 4. API DESIGN

### Auth API
```
POST /api/v1/auth/login              — Username + password
POST /api/v1/auth/mfa/verify         — MFA TOTP verification
POST /api/v1/auth/refresh            — Token refresh
POST /api/v1/auth/logout             — Session revocation
GET  /api/v1/auth/me                 — Current user profile
```

### Question API
```
POST /api/v1/questions/              — Create question (QUESTION_SETTER)
GET  /api/v1/questions/              — List (scoped to role)
GET  /api/v1/questions/{id}          — Get question metadata
PUT  /api/v1/questions/{id}          — Update (own, DRAFT only)
POST /api/v1/questions/{id}/submit   — Submit for review
POST /api/v1/questions/{id}/approve  — Approve (MODERATOR)
POST /api/v1/questions/{id}/reject   — Reject (MODERATOR)
POST /api/v1/questions/{id}/encrypt  — Encrypt approved question
GET  /api/v1/questions/{id}/audit    — Question audit trail
```

### Blueprint API
```
POST /api/v1/exams/{id}/blueprint    — Create blueprint
GET  /api/v1/exams/{id}/blueprint    — Get blueprint
POST /api/v1/exams/{id}/forms/generate — Generate exam forms
GET  /api/v1/exams/{id}/forms        — List forms
```

### Release API
```
GET  /api/v1/exams/{id}/release/status    — Release status
POST /api/v1/exams/{id}/release/approve   — Submit threshold approval
GET  /api/v1/exams/{id}/release/approvals — List approvals
POST /api/v1/exams/{id}/release/freeze    — Emergency freeze
```

### Candidate / CBT API
```
POST /api/v1/candidate/auth/login         — Candidate login
GET  /api/v1/candidate/session/init       — Initialize exam session
GET  /api/v1/candidate/session/question/{n} — Fetch question N (secure)
POST /api/v1/candidate/session/response   — Save answer
POST /api/v1/candidate/session/heartbeat  — Session heartbeat
POST /api/v1/candidate/session/submit     — Final submission
POST /api/v1/candidate/session/event      — Security event report
```

### Security / Audit API
```
GET  /api/v1/audit/logs              — Audit log (AUDITOR/SECURITY_OFFICER)
GET  /api/v1/audit/verify            — Verify chain integrity
GET  /api/v1/security/events         — Security events
GET  /api/v1/security/risk/{actor}   — Risk score
POST /api/v1/incidents/              — Create incident
POST /api/v1/incidents/{id}/action   — Execute incident action
```

---

## 5. CRYPTOGRAPHIC MODEL

### Key Hierarchy (Prototype — MockKMS)
```
ROOT_KEY (env var — never in code)
    └─► Exam Cycle Key (derived per exam via HKDF)
            └─► Question Encryption Key (derived per question)
            └─► Session Key (ephemeral — per candidate session)
                    └─► Used for Redis-cached question delivery
```

### Per-Question Encryption
```python
plaintext = canonical_json(question_content)
nonce = secrets.token_bytes(12)           # 96-bit GCM nonce
ciphertext, tag = AES256GCM.encrypt(plaintext, question_key, nonce)
stored = base64(nonce + ciphertext + tag)  # Combined blob
integrity_hash = SHA3_256(stored + question_id + version)
signature = Ed25519.sign(integrity_hash, signing_key)
```

### Session Key Architecture (KMS call reduction)
```
Session Start:
  session_key = KMS.generate_data_key(exam_id)
  Store: Redis[session_id] = encrypt(session_key, root_key)

Per Question Request:
  session_key = decrypt(Redis[session_id], root_key)
  question_plaintext = AES256GCM.decrypt(question_blob, session_key)
  delivery = question_plaintext + watermark(session_id, candidate_id)
  return delivery
```

### Audit Log Hash Chain
```
event_n.prev_hash = SHA256(event_{n-1}.event_hash)
event_n.event_hash = SHA256(event_n.data + event_n.prev_hash)
```

---

## 6. THREAT MODEL (STRIDE)

| Threat | Scenario | Control | Detection |
|--------|----------|---------|-----------|
| Spoofing | Stolen credentials | MFA + short JWT TTL | Failed MFA alert |
| Spoofing | JWT forgery | RS256 signed, server-side validation | Invalid signature event |
| Tampering | Question modification | Ed25519 + integrity hash | Hash mismatch on delivery |
| Tampering | Audit log deletion | Hash chain + append-only | Chain verification API |
| Tampering | Blueprint modification | Blueprint signed + encrypted | Signature verification |
| Repudiation | Admin denies action | Ed25519-signed audit events | Audit trail |
| Info Disclosure | DB dump | AES-256-GCM at rest | N/A (ciphertext only) |
| Info Disclosure | Bulk question access | Rate limit + RBAC | Anomaly detection |
| Info Disclosure | Answer key via candidate API | Evaluation isolated | Authorization check |
| DoS | Login spike | Rate limiting + Redis | Traffic monitoring |
| DoS | Heartbeat flood | Per-session rate limit | Anomaly detection |
| EoP | Role bypass | Server-side RBAC on every endpoint | Unauthorized access event |
| EoP | Early release | Time check + threshold both required | Release attempt event |
| EoP | Reviewer → full bank | Per-question authorization | Anomaly detection |

---

## 7. TRUST MODEL

```
TRUST LEVEL 0 (Untrusted): Internet, anonymous requests
TRUST LEVEL 1 (Low):       Authenticated candidates
TRUST LEVEL 2 (Medium):    Authenticated admin users (single role)
TRUST LEVEL 3 (High):      Multi-role verified + MFA
TRUST LEVEL 4 (Critical):  Release Authority + threshold ceremony
TRUST LEVEL 5 (Maximum):   KMS/HSM system (no human access)
```

**Trust Boundaries:**
- TB-1: Internet → API (TLS + rate limiting)
- TB-2: Auth token → Service (JWT verification on every request)
- TB-3: Role → Resource (RBAC on every service method)
- TB-4: Session → Question (per-session authorization + exam window check)
- TB-5: Service → KMS (isolated interface — no direct key exposure)
- TB-6: Service → Audit (append-only — services cannot read/modify)

---

## 8. THRESHOLD AUTHORIZATION MODEL

### Prototype Implementation
```
ThresholdApprovalRecord {
  exam_id: UUID
  required_count: int (e.g., 3)
  approvals: [
    { authority_id, approved_at, signature, nonce }
  ]
  status: PENDING | APPROVED | EXPIRED
}

Release proceeds only when len(approvals) >= required_count
AND all signatures are valid
AND exam scheduled time has passed
AND system health check passes
AND centre readiness >= threshold%
```

### Production Upgrade Path
- Replace `ThresholdApprovalRecord` with Shamir Secret Sharing reconstruction
- HSM policy enforces minimum custodians
- No code change required in release-service except KMS call

---

## 9. TIME-LOCKED RELEASE STATE MACHINE

```
DRAFT → BLUEPRINT_CREATED → THRESHOLD_PENDING → THRESHOLD_APPROVED
      → RELEASE_CONDITIONS_MET → RELEASED → COMPLETED

Release conditions (ALL must be true):
  □ server_time >= exam.scheduled_start_utc
  □ threshold_approvals >= exam.required_approvals
  □ blueprint.status == APPROVED
  □ blueprint.signature VALID
  □ centre_readiness >= exam.min_centre_readiness_pct
  □ system_health == HEALTHY
  □ no FREEZE_RELEASE incident active
```

---

## 10. SECURE CBT MODEL

### Client-Side Controls (Browser — documented limitations)
```
✅ Fullscreen API enforcement
✅ visibilitychange detection (tab switch)
✅ blur event detection (window switch)
✅ contextmenu preventDefault
✅ copy/cut/paste prevention (event listeners)
✅ beforeprint prevention
✅ keyboard shortcut interception (Ctrl+C, Ctrl+P, Ctrl+U, F12, etc.)
✅ Dynamic watermark (session/candidate overlay)
✅ 30-second heartbeat with violation counter
✅ Auto-save every 60 seconds

⚠️ LIMITATIONS (clearly stated in UI):
❌ Cannot prevent OS-level screenshots
❌ Cannot prevent external camera photography
❌ Cannot prevent screen recording at OS level
❌ Cannot prevent memory inspection
```

### Server-Side Enforcement
```
- Exam window validation on every question request
- Session token expiry enforcement
- Violation threshold → session flag (configurable policy)
- Heartbeat miss → alert (not automatic termination)
- All violation events logged with timestamp
```

---

## 11. MONITORING MODEL

### Real-Time Dashboard Metrics
- Active exam sessions count
- Questions delivered per second
- Autosave queue depth
- Security violations per minute
- Failed auth attempts per minute
- System health (DB, Redis, MockKMS)
- Release status per active exam

### Anomaly Detection Rules (Rule-Based)
```python
RULES = [
    Rule("BRUTE_FORCE", failed_logins > 5 in 10min, MEDIUM),
    Rule("MFA_SWEEP", mfa_failures > 3 in 5min, HIGH),
    Rule("BULK_QUESTION_ACCESS", question_views > 20 in 1min, HIGH),
    Rule("OFF_HOURS_ADMIN", privileged_access outside 08:00-20:00, MEDIUM),
    Rule("NEW_DEVICE_ACCESS", privileged_login from unknown device, MEDIUM),
    Rule("EARLY_RELEASE_ATTEMPT", release API before scheduled_time, CRITICAL),
    Rule("CONCURRENT_SESSION", same candidate_id active session exists, HIGH),
    Rule("ANSWER_KEY_PROBE", candidate API requests evaluation endpoint, CRITICAL),
    Rule("RAPID_QUESTION_SCAN", question_requests > 50 without answers, HIGH),
    Rule("TAB_SWITCH_THRESHOLD", tab_switches > 5 in session, MEDIUM),
]
```

---

## 12. AUDIT MODEL

### Hash Chain Structure
```
Genesis block: prev_hash = "0" * 64
Each event: event_hash = SHA256(timestamp + actor + action + resource + prev_hash)
Chain verified by: /api/v1/audit/verify
```

### Tamper Detection
- Any historical record modification breaks the chain
- Chain verification API computes expected hashes and compares
- Chain head exported and stored separately for independent verification

---

## 13. INCIDENT RESPONSE MODEL

### Incident Actions
```
LOCK_USER → Sets user.is_active = false, revokes all sessions
REVOKE_SESSION → Invalidates specific candidate session token
REVOKE_DEVICE → Blacklists device fingerprint
ISOLATE_CENTRE → Sets centre.status = ISOLATED
REVOKE_FORM → Sets form.status = REVOKED, triggers backup form
FREEZE_RELEASE → Creates release freeze record (blocks automated release)
ROTATE_KEY → Triggers KMS key rotation for affected exam
SWITCH_FORM → Activates backup form for affected sessions
```

### Emergency Form Replacement
```
Active Form A → REVOKED (via incident action)
Backup Form B → ACTIVATED (requires SECURITY_OFFICER + RELEASE_AUTHORITY approval)
Affected sessions → Notified and reassigned
Event → Audit logged + security event
```

---

## 14. SCALABILITY MODEL

### Prototype Targets
- 1,000 concurrent users: Single Docker Compose stack
- 10,000 concurrent users: Redis + PgBouncer + 4 FastAPI workers

### Production Scaling Path (documented, not implemented in prototype)
```
10K  → FastAPI horizontal + PgBouncer + Redis
100K → K8s HPA + PostgreSQL replicas + Redis Cluster
500K → Multi-AZ + Kafka + CDN + session key caching
1M+  → Multi-region + HSM + full Kafka pipeline
```

---

## 15. PROTOTYPE vs PRODUCTION SEPARATION

| Feature | Prototype (3-Day) | Production |
|---------|-------------------|------------|
| KMS | MockKMS (env keys) | Cloud KMS / HSM |
| Threshold | N approval records | SSS + HSM policy |
| MFA | TOTP (pyotp) | FIDO2 + TOTP |
| Identity | Username+password+MFA | Gov ID / UIDAI / FIDO2 |
| Object Store | MinIO (local Docker) | S3 / cloud-native |
| Audit | Hash chain in PostgreSQL | WORM + SIEM |
| Events | In-process event bus | Kafka |
| TLS | Nginx termination | CloudFlare + mTLS |
| Device Trust | Device fingerprint | MDM + attestation |
| Screenshot prevention | JS detection | Managed device |
| Multi-region | Single region | Multi-region active-active |

---

## 3-DAY IMPLEMENTATION PLAN

### DAY 1 — SECURITY CORE

**Phase 1:** Monorepo scaffold, Docker Compose, PostgreSQL, Redis, MinIO  
**Phase 2:** Auth service — login, JWT, TOTP MFA, RBAC middleware  
**Phase 3:** Crypto layer — MockKMS, AES-256-GCM, Ed25519, SHA-3, hash chain  
**Phase 4:** Question service — lifecycle, encryption, object store  
**Phase 5:** Review/approval workflow  

### DAY 2 — EXAM SECURITY ENGINE

**Phase 6:** Blueprint engine — config, validation, encryption  
**Phase 7:** Multi-form generator — randomization, form assignment  
**Phase 8:** Threshold authorization simulator  
**Phase 9:** Time-locked release engine  
**Phase 10:** Candidate session + secure question delivery  

### DAY 3 — PLATFORM + POLISH

**Phase 11:** Secure CBT UI — fullscreen, watermark, timer, navigation  
**Phase 12:** Audit pipeline + hash chain verification  
**Phase 13:** Anomaly detection + risk scoring  
**Phase 14:** Incident response module  
**Phase 15:** Evaluation + result generation  
**Phase 16:** Professional UI — landing, dashboards, security console  
**Phase 17:** Attack demonstrations  
**Phase 18:** Documentation  

---

*Architecture Freeze v1.0 — All implementation must follow this document.*
*Deviations require explicit architectural review.*
