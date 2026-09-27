# B-SEA — Backend Deployment & Cloud Integration Guide

## 1. Overview
The **Bharat Secure Examination Architecture (B-SEA)** backend is built on **FastAPI (Python 3.14)**, **PostgreSQL 16**, **Redis 8.10**, and a cryptographic provider layer (**MockKMS** in local prototype/development, **AWS KMS / Cloud HSM** in production).

This guide documents the persistent, production-parity backend environment, container requirements, networking topologies, environment configuration, and Vercel frontend integration.

---

## 2. Target Architecture
`
Vercel Edge Network (React 19 + TypeScript + Vite)
  ¦
  +-- HTTPS / TLS 1.3
  ?
FastAPI Application Server (Uvicorn / Gunicorn persistent daemon)
  ¦
  +-- PostgreSQL 16 (Relational state, immutability triggers, audit chain)
  +-- Redis 8.10 (Distributed session cache, layered IP/identity rate limiting)
  +-- Cryptographic Provider (AES-256-GCM envelope encryption, HMAC integrity, KMS)
`

### Invariant Constraint
> *\"No single person, account, server, examination centre, administrator, or compromised component should possess sufficient authority or cryptographic keys to obtain the complete examination paper prior to authorized release.\"*

---

## 3. Persistent Infrastructure Requirements
The B-SEA backend cannot be executed inside transient, stateless serverless runtimes (such as Vercel serverless functions) due to:
1. **Asynchronous Audit Sealer Worker:** Continuous queue consumer sealing audit logs with SHA-256 Merkelized hashing.
2. **Distributed Redis State:** Stateful rate limiting, token expiration, and concurrent candidate session prevention.
3. **Connection Pooling:** SQLAlchemy asyncpg connection pool with keepalives to PostgreSQL 16.

**Approved Deployment Targets:**
- Dedicated Cloud VM (Ubuntu / Windows Server)
- AWS ECS Fargate Container Service
- AWS App Runner with persistent Redis ElastiCache
- Docker Compose / Kubernetes Cluster

---

## 4. Environment Variables Checklist
All secrets and sensitive parameters must be supplied via secure environment variables or vault secret managers. Never commit credentials to version control.

| Variable Name | Description | Example / Allowed Values |
|---|---|---|
| ENVIRONMENT | Deployment environment profile | production / staging / development |
| LOG_LEVEL | Application logging verbosity | INFO / WARNING |
| DEBUG | FastAPI debug flag (must be false in production) | alse |
| DATABASE_URL | Async PostgreSQL 16 connection string | postgresql+asyncpg://<user>:<pwd>@<host>:5432/<db> |
| SYNC_DATABASE_URL | Sync PostgreSQL connection string for Alembic | postgresql+psycopg2://<user>:<pwd>@<host>:5432/<db> |
| REDIS_URL | Authenticated Redis connection URL | edis://:<password>@<host>:6379/0 |
| REDIS_SESSION_TTL | Examination candidate session timeout (seconds) | 7200 (2 hours) |
| REDIS_RATE_LIMIT_TTL | Rate limiting window size (seconds) | 60 |
| SECRET_KEY | High-entropy JWT signing key | 64+ char cryptographically random hex |
| CORS_ORIGINS | Explicitly allowed origins (NO wildcard in prod) | https://neet-exam-defense-system.vercel.app |
| KMS_PROVIDER | Cryptographic key manager | AWS-KMS (Cloud) / MockKMS (Demonstration) |
| AWS_KMS_KEY_ARN | Primary KMS key ARN (when KMS_PROVIDER=AWS-KMS) | rn:aws:kms:... |

---

## 5. Database Provisioning & Migration
1. Provision PostgreSQL 16 database.
2. Run database migrations:
   `ash
   alembic upgrade head
   `
3. Target Schema Head: 2c3d4e5f6a7
4. Verified schema includes 35 tables, 13 immutability triggers (for audit, answer keys, blueprints, questions), and 133 indexes.

---

## 6. Redis Provisioning & Configuration
1. Provision Redis 7.x or 8.x with password authentication (equirepass).
2. Verify connectivity:
   `python
   import redis
   r = redis.Redis(host='localhost', port=6379, password='...', socket_connect_timeout=2)
   assert r.ping() is True
   `
3. Ensure persistence: Enable AOF (Append-Only File) or RDB snapshots.

---

## 7. Seed Demonstration Data
Only run when initializing demonstration environments:
`ash
python app/scripts/seed_demo.py
`
This populates standard demonstration examination blueprints, encrypted questions, demonstration candidate BSEA-2026-DEMO-001, and administrative roles.

---

## 8. Health & Readiness Endpoints
- **Liveness:** GET /health/live (HTTP 200 { "status": "alive" })
- **Readiness:** GET /health/ready (HTTP 200 { "status": "ready", "checks": { "database": "ok", "redis": "ok", "crypto": "ok" } })

---

## 9. Vercel Frontend Connection
1. Set the Vercel production environment variable:
   `env
   VITE_API_URL=https://<VERIFIED_BACKEND_URL>
   `
2. In ercel.json, verify SPA rewrite rule:
   `json
   {
     "rewrites": [
       { "source": "/(.*)", "destination": "/index.html" }
     ]
   }
   `
3. Trigger a redeploy on Vercel.

---

## 10. Rollback Procedure
If a deployment defect is detected:
1. Revert Git commit: git revert <commit-hash>
2. Push to main: triggers automatic Vercel build.
3. Database Rollback: lembic downgrade -1 (only if non-breaking; immutability tables prevent truncation).
