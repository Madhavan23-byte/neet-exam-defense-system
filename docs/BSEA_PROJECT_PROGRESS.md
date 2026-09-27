# B-SEA  Project Scratch Pad & Continuous Progress Tracker

Last Updated: 2026-09-27T12:32:00+05:30
Current Branch: main
Latest Commit: e57bfe

---

## 1. Project Health & Deployment Status Summary

| Component | Status | Verified Target | Notes |
|---|---|---|---|
| **Frontend** | [x] COMPLETED | https://neet-exam-defense-system.vercel.app | React 19 + TypeScript + Vite |
| **Backend Core** | [x] COMPLETED | http://0.0.0.0:8000 | FastAPI (Python 3.14) |
| **Public HTTPS URL** | [x] COMPLETED | https://aid-handmade-thee-opinions.trycloudflare.com | Cloudflare TLS 1.3 Edge |
| **PostgreSQL 16** | [x] COMPLETED | localhost:5432/bsea | Alembic Head 2c3d4e5f6a7 (35 tables, 133 indexes) |
| **Redis 8.10** | [x] COMPLETED | localhost:6379/0 | Authenticated standalone with AOF persistence |
| **KMS Provider** | [x] COMPLETED | MockKMS | AES-256-GCM Envelope Encryption verified |
| **CORS Policy** | [x] COMPLETED | https://neet-exam-defense-system.vercel.app | Strict origin with credentials (preflight verified) |
| **Test Suites** | [x] COMPLETED | 306 passed, 5 skipped (0 failed) | 5D: 31/31, 5E: 35/35 |
| **API Connectivity** | [x] COMPLETED | Vercel Edge /api/v1/:path* Proxy & Direct TLS | Solved 405 (Staff) and 5xx (Candidate) root causes |

---

## 2. Root Cause & Solution Log

### Issue 1: Staff Portal \"Request failed with status code 405\"
- **Root Cause:** In Vercel, requests to POST /api/v1/auth/login were captured by the catch-all SPA rewrite {"source": "/(.*)", "destination": "/index.html"}. Vercel's static file engine rejected HTTP POST requests against static HTML with HTTP 405 Method Not Allowed.
- **Solution:** Added edge reverse proxy rewrite {"source": "/api/v1/:path*", "destination": "https://aid-handmade-thee-opinions.trycloudflare.com/api/v1/:path*"} to both ercel.json and rontend/vercel.json, and configured DEFAULT_BACKEND_URL in rontend/src/services/api.ts.
- **Verification:** Verified live on Vercel (https://neet-exam-defense-system.vercel.app/login). POST /api/v1/auth/login no longer returns 405; requests are transparently routed to the backend.

### Issue 3: Architectural Separation of Candidate Discovery and Staff Exam Administration
- **Root Cause:** Making `GET /api/v1/exams/` unauthenticated violated security test `test_api_requires_auth_for_protected_routes` which tests that administrative exam routes require authentication and return 401.
- **Solution:** Restored strict `Depends(get_current_user)` authentication on `GET /api/v1/exams/`. Created dedicated public candidate endpoint `GET /api/v1/candidate/exams` returning only `RELEASED` and `ONGOING` exams. Added `getExams()` to `candidateApi` and updated `CandidateLoginPage.tsx`. Also cleaned package metadata from `temp-init` to `bsea-frontend@1.0.0`.
- **Verification:** Security test suite passed 100% (16 passed, 5 skipped, 0 failed in `test_attacks.py`; 31/31 in 5D; 35/35 in 5E). Public candidate discovery and staff administrative isolation both verified live.

### Issue 2: Candidate Portal \"Examination Server Error (HTTP 5xx)\"
- **Root Cause:** Candidate registry call GET /api/v1/exams/ was rewritten by Vercel to index.html. The frontend pi.ts interceptor detected HTML text instead of JSON and generated a synthetic HTTP 503 error, causing CandidateLoginPage to render a 5xx gateway error. Additionally, list_exams required staff JWT authentication.
- **Solution:** Vercel reverse proxy routes /api/v1/exams/ directly to FastAPI. In exams.py, list_exams now supports get_optional_current_user, serving public active/released exams to candidates without requiring staff JWT tokens.
- **Verification:** Verified live on Vercel (https://neet-exam-defense-system.vercel.app/candidate/login). Green banner System Readiness: Online is displayed and active examinations (Test Containment Exam (CBT)) are dynamically populated in the dropdown.

---

## 3. Granular Task Tracking

### Pre-Deployment & Frontend Hardening
- [x] Repository takeover audit & structural scan
- [x] Candidate login defensive shape validation & white-screen defense
- [x] Staff Portal authentication form layout fix (zero icon overlap, 48px padding, visibility toggle)
- [x] Production build passes clean on Vite (	sc -b && vite build)

### Infrastructure & Backend Environment
- [x] Native PostgreSQL 16 database verified & migrated to head 2c3d4e5f6a7
- [x] Native Redis 8.10 installed via WinGet & verified with check_redis_health()
- [x] Backend daemon launched and responding to /health/live and /health/ready
- [x] Demonstration data seeded (8 encrypted questions, 4 forms, demo candidate, admin)
- [x] Persistent Cloudflare edge tunnel established with zero interstitial warnings

### API Connectivity & Vercel Integration
- [x] Diagnose root cause of Staff 405 and Candidate 5xx errors
- [x] Configure Vercel reverse proxy rewrites (/api/v1/:path* -> Backend URL)
- [x] Configure production default backend URL in rontend/src/services/api.ts
- [x] Support unauthenticated listing of released exams for candidate registry
- [x] Pass 5D (31/31) and 5E (35/35) security test suites
- [x] Commit and push changes to GitHub origin/main (e57bfe)
- [x] End-to-end verification of Staff login on live Vercel
- [x] End-to-end verification of Candidate CBT flow on live Vercel
- [x] Live Vercel verification completed: zero 405 errors, zero 5xx errors
