# B-SEA Technology Demonstration Runbook
**Bharat Secure Examination Architecture — Reference Platform & Prototype**

This runbook provides the exact, end-to-end instructions for launching, verifying, and presenting the B-SEA technology demonstration to evaluators, professors, and technical review committees.

---

## 1. System Architecture Overview

The B-SEA demonstration platform runs with high fidelity across a distributed edge and local topology:

```
[Evaluator Browser]
       │
       ▼
[Vercel Global Edge (HTTPS)]
https://neet-exam-defense-system.vercel.app
       │
       │ Reverse Proxy / Direct HTTPS
       ▼
[Cloudflare Edge Tunnel (TLS 1.3)]
https://rehabilitation-wins-convergence-addresses.trycloudflare.com
       │
       ▼
[Local Host Services]
├── FastAPI Application Server (Port 8000)
├── PostgreSQL 16 Enterprise Database (Port 5432 - 35 tables, 13 triggers)
├── Redis 8.10 In-Memory State Cache (Port 6379 - Standalone AOF)
└── MockKMS Cryptographic Engine (AES-256-GCM + Ed25519)
```

---

## 2. One-Click Demonstration Startup

From the project root (`E:\Cloud-Mini-Project`), open PowerShell and run:

```powershell
.\start_demo.ps1
```

The script automatically:
1. Verifies PostgreSQL 16 on port 5432.
2. Launches Redis 8.10 with AOF persistence.
3. Launches the FastAPI backend on port 8000.
4. Verifies `/health/ready` returns HTTP 200 with DB, Redis, and Crypto status `ok`.
5. Establishes the Cloudflare Edge Tunnel and outputs the public HTTPS tunnel URL.

---

## 3. Manual Startup Steps (Alternative)

If you prefer starting services manually in separate terminals:

### Terminal 1: PostgreSQL 16
Ensure the PostgreSQL Windows service is running:
```powershell
Get-Service -Name "postgresql-x64-16" | Select-Object Status
```

### Terminal 2: Redis
```powershell
& "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\taizod1024.redis-windows-fork_Microsoft.Winget.Source_8wekyb3d8bbwe\Redis-8.10.1-Windows-x64-msys2\redis-server.exe" --appendonly yes
```

### Terminal 3: FastAPI Backend
```powershell
cd E:\Cloud-Mini-Project\backend
.\venv\Scripts\python.exe -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### Terminal 4: Cloudflare Edge Tunnel
```powershell
cd E:\Cloud-Mini-Project
.\cloudflared.exe tunnel --url http://127.0.0.1:8000
```
*Note the `https://<generated-subdomain>.trycloudflare.com` URL printed in the output.*

---

## 4. Pre-Presentation Verification Checklist (Smoke Test)

Run these checks 2 minutes before opening the browser for your teacher:

```powershell
# 1. Local Health Check
curl.exe -s http://127.0.0.1:8000/health/ready
# Expected: {"status":"ready","environment":"development","mode":"LOCAL","checks":{"database":"ok","redis":"ok","crypto":"ok (MockKMS)"}}

# 2. Public Edge Tunnel Check
curl.exe -s https://rehabilitation-wins-convergence-addresses.trycloudflare.com/health/ready
# Expected: HTTP 200 with checks ok

# 3. Candidate Discovery Route
curl.exe -s https://rehabilitation-wins-convergence-addresses.trycloudflare.com/api/v1/candidate/exams
# Expected: JSON array containing "B-SEA Global Security Certification 2026"
```

---

## 5. Teacher Demonstration Walkthrough Script

### Step 1: Architecture Introduction (`/`)
- Open [https://neet-exam-defense-system.vercel.app](https://neet-exam-defense-system.vercel.app).
- Highlight the **Technology Demonstrator** badge and real-time IST clock.
- Point out the **Four Pillars of Cryptographic Defense**:
  1. Question Sharding & Blind Redundancy
  2. Multi-Party Threshold Decryption
  3. Dynamic Dynamic-Watermarked CBT Terminal
  4. Cryptographic Proof of Session Completion

### Step 2: Candidate CBT Examination Journey (`/candidate/login`)
- Navigate to **Candidate CBT Portal** (`/candidate/login`).
- Point out the **System Readiness: Online** green status badge.
- Click **"Fill Demo Credentials"**:
  - Roll Number: `BSEA-2026-DEMO-001`
  - Password: `BSeaDemo@2026`
  - Examination: `B-SEA Global Security Certification 2026 (CBT)`
- Click **Sign In & Begin Exam**:
  - Show the dynamic anti-leak watermark (`034E6FB6 • Demo Candidate`).
  - Answer Question 1: Select `250 J` (Work-Energy Theorem). Click **Next Question**.
  - Answer Question 2: Select option and click **Mark for Review**.
  - Show the **Question Palette**: Green = Answered, Purple = Marked for Review.
  - Click **Submit Examination**. The two-step confirmation modal appears.
  - Confirm submission: The **Cryptographic Examination Receipt** (`/candidate/result`) is displayed, complete with cryptographic session hash, tamper-evident timestamp, and question audit breakdown.

### Step 3: Staff Security & Command Console (`/login`)
- Navigate to **Staff Portal** (`/login`).
- Enter Staff Credentials:
  - Username: `admin`
  - Password: `BSeaDemo@2026`
- Walk through the administrative consoles:
  - **Executive Dashboard (`/admin`):** Live exam status, candidate telemetry, active center readiness.
  - **Security Telemetry (5C) (`/admin/security`):** Real-time anomaly detection, sliding window violation graphs.
  - **Incident Management (5D) (`/admin/incidents`):** 5-state lifecycle (`TRIAGE` → `INVESTIGATING` → `CONTAINED` → `RESOLVED` → `CLOSED`).
  - **Containment Pipeline (5E) (`/admin/containment`):** Blast-radius isolation, 6-gate mitigation workflow.
  - **Audit Explorer (`/admin/audit`):** Canonical audit log explorer with SHA-256 hash chaining verification (`Verify Immutable Chain`).
  - **Break-Glass Emergency Room (`/admin/break-glass`):** Quorum-enforced emergency key assembly.
  - **User & Role Administration (`/admin/users`):** 11-role granular RBAC enforcement.

---

## 6. Troubleshooting Common Demonstration Scenarios

### Scenario A: UI Displays "Network Error"
- **Cause:** Cloudflare tunnel or local FastAPI daemon was stopped.
- **Resolution:**
  1. Open PowerShell and run `.\start_demo.ps1`.
  2. If the tunnel URL changed, either:
     - Update `bsea_backend_url` in browser `localStorage` directly in DevTools Console:
       ```javascript
       localStorage.setItem('bsea_backend_url', 'https://your-new-tunnel.trycloudflare.com')
       ```
     - Or point directly to localhost if testing locally:
       ```javascript
       localStorage.setItem('bsea_backend_url', 'http://localhost:8000')
       ```

### Scenario B: Candidate Login Shows "Active Session Conflict (HTTP 409)"
- **Cause:** Candidate `BSEA-2026-DEMO-001` already submitted or has an active session in the database/Redis.
- **Resolution:** The candidate portal automatically resumes stored browser tokens, or you can clear local candidate session from DevTools (`localStorage.removeItem('bsea_session')`).

---

## 7. Prototype Classification Notice

The current deployment is a **Technology Demonstrator & Functional Prototype**.
Future production enterprise phases (ECS Fargate clusters, AWS CloudHSM hardware modules, multi-region database failover) are scheduled as a dedicated future upgrade phase.
