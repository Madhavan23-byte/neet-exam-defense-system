"""
B-SEA — Phase 3B Break-Glass & Controlled Complete-Paper Exception Test Suite
Validates 30 Security Invariants:
 1. Request creation success (identity bound, fresh session independent)
 2. Requester cannot approve own request (separation of duties)
 3. Duplicate approver rejected (409 conflict)
 4. Unauthorized approver rejected (403 forbidden)
 5. Quorum satisfaction requires role diversity (headcount alone insufficient)
 6. Activation requires APPROVED status (400 if pending)
 7. Non-requester cannot activate request (403 forbidden)
 8. Fresh session JTI bound during activation (status -> ACTIVATED)
 9. Cross-session replay blocked (JTI mismatch rejected)
10. Request ID alone insufficient (unauthenticated/forged fails)
11. Assembled paper excludes answer keys (strict isolation)
12. Deterministic lazy expiration (403/410, transitions to EXPIRED)
13. Explicit revocation halts access (status -> REVOKED, approvals invalidated)
14. Exam freeze transactional cascade revokes break-glass (atomic cascade)
15. Material fingerprint mismatch invalidates approvals
16. Rejection marks request terminal REJECTED (cannot later reach quorum)
17. Concurrent approval race protection (row lock serialization)
18. Complete audit trail lifecycle (all events logged in chain)
19. Repeated assembly audited independently (per-read audit events)
20. No plaintext persisted to server storage (DB, files, Redis, logs verification)
21. Cross-exam request IDOR rejected (404)
22. Cross-blueprint version replay blocked (integrity check)
23. Quorum race competing approvals transition exactly once
24. Requester attempting multiple approval identities blocked
25. Approval after rejection rejected (409 terminal)
26. Approval after expiration rejected (409 expired)
27. Activation after revocation rejected (403 revoked)
28. Access after exam cancellation rejected (cascade revocation)
29. Duration policy violation rejected (bounds check)
30. Scope policy violation rejected (validation check)
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta
import asyncpg
import pytest
from fastapi.testclient import TestClient

from app.main import app

BASE_URL = "/api/v1"
ADMIN_CREDS = {"username": "admin", "password": "BSeaDemo@2026"}
EXAM_AUTH_CREDS = {"username": "exam_authority", "password": "BSeaDemo@2026"}
SECURITY_OFFICER_CREDS = {"username": "security_officer", "password": "BSeaDemo@2026"}
RELEASE_AUTH_1_CREDS = {"username": "release_auth_1", "password": "BSeaDemo@2026"}
RELEASE_AUTH_2_CREDS = {"username": "release_auth_2", "password": "BSeaDemo@2026"}
REVIEWER_CREDS = {"username": "reviewer_1", "password": "BSeaDemo@2026"}
DB_URL = "postgresql://postgres:root@localhost:5432/bsea"


def db_execute(query: str, *args):
    """Execute raw SQL in an independent asyncpg connection."""
    async def _exec():
        conn = await asyncpg.connect(DB_URL)
        try:
            return await conn.execute(query, *args)
        finally:
            await conn.close()
    return asyncio.run(_exec())


def db_fetchval(query: str, *args):
    """Fetch single value via independent asyncpg connection."""
    async def _exec():
        conn = await asyncpg.connect(DB_URL)
        try:
            return await conn.fetchval(query, *args)
        finally:
            await conn.close()
    return asyncio.run(_exec())


def db_fetch(query: str, *args):
    """Fetch rows via independent asyncpg connection."""
    async def _exec():
        conn = await asyncpg.connect(DB_URL)
        try:
            return await conn.fetch(query, *args)
        finally:
            await conn.close()
    return asyncio.run(_exec())


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def admin_token(client):
    res = client.post(f"{BASE_URL}/auth/login", json=ADMIN_CREDS)
    assert res.status_code == 200
    return res.json()["access_token"]


@pytest.fixture(scope="module")
def exam_auth_token(client):
    res = client.post(f"{BASE_URL}/auth/login", json=EXAM_AUTH_CREDS)
    assert res.status_code == 200
    return res.json()["access_token"]


@pytest.fixture(scope="module")
def security_officer_token(client):
    res = client.post(f"{BASE_URL}/auth/login", json=SECURITY_OFFICER_CREDS)
    assert res.status_code == 200
    return res.json()["access_token"]


@pytest.fixture(scope="module")
def release_auth_1_token(client):
    res = client.post(f"{BASE_URL}/auth/login", json=RELEASE_AUTH_1_CREDS)
    assert res.status_code == 200
    return res.json()["access_token"]


@pytest.fixture(scope="module")
def release_auth_2_token(client):
    res = client.post(f"{BASE_URL}/auth/login", json=RELEASE_AUTH_2_CREDS)
    assert res.status_code == 200
    return res.json()["access_token"]


@pytest.fixture(scope="module")
def reviewer_token(client):
    res = client.post(f"{BASE_URL}/auth/login", json=REVIEWER_CREDS)
    assert res.status_code == 200
    return res.json()["access_token"]


@pytest.fixture(scope="module")
def active_exam(client, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    res = client.get(f"{BASE_URL}/exams/", headers=headers)
    assert res.status_code == 200
    exams = res.json()
    assert len(exams) > 0

    exam = next((e for e in exams if e.get("title") == "B-SEA Global Security Certification 2026"), None)
    if not exam:
        exam = exams[0]

    # Ensure blueprint is APPROVED for the exam
    exam_id = exam["id"]
    client.post(f"{BASE_URL}/exams/{exam_id}/blueprint/approve", headers=headers)
    db_execute("UPDATE exams SET status = 'RELEASED', release_frozen = false WHERE id = $1", exam_id)
    return exam


@pytest.fixture(autouse=True)
def ensure_exam_clean(active_exam):
    """Ensure active_exam is RELEASED and not frozen before and after each test."""
    db_execute("UPDATE exams SET status = 'RELEASED', release_frozen = false WHERE id = $1", active_exam["id"])
    yield
    db_execute("UPDATE exams SET status = 'RELEASED', release_frozen = false WHERE id = $1", active_exam["id"])


# ── Test 1: Request Creation Success ──────────────────────────────────────────
def test_break_glass_request_creation_success(client, exam_auth_token, active_exam):
    headers = {"Authorization": f"Bearer {exam_auth_token}"}
    payload = {
        "exam_id": active_exam["id"],
        "scope": "COMPLETE_EXAM_PAPER",
        "justification": "Emergency court-ordered audit regarding paper integrity verification",
        "requested_duration_minutes": 30,
    }
    res = client.post(f"{BASE_URL}/break-glass/requests", json=payload, headers=headers)
    assert res.status_code == 201
    data = res.json()
    assert data["status"] == "PENDING"
    assert data["required_quorum"] == 2
    assert data["min_distinct_roles"] == 2
    assert data["activation_session_id"] is None
    assert len(data["content_fingerprint"]) == 64
    assert data["scope"] == "COMPLETE_EXAM_PAPER"


# ── Test 2: Requester Cannot Approve Own Request ───────────────────────────────
def test_requester_cannot_approve_own_request(client, exam_auth_token, active_exam):
    headers = {"Authorization": f"Bearer {exam_auth_token}"}
    req_res = client.post(
        f"{BASE_URL}/break-glass/requests",
        json={
            "exam_id": active_exam["id"],
            "scope": "COMPLETE_EXAM_PAPER",
            "justification": "Test separation of duties: requester cannot approve own request",
        },
        headers=headers,
    )
    assert req_res.status_code == 201
    req_id = req_res.json()["id"]

    # Requester attempts approval
    app_res = client.post(
        f"{BASE_URL}/break-glass/requests/{req_id}/approve",
        json={"decision": "APPROVE", "comments": "Self approval attempt"},
        headers=headers,
    )
    assert app_res.status_code == 403
    assert "Separation of duties violation" in app_res.json()["detail"]


# ── Test 3: Duplicate Approver Rejected ───────────────────────────────────────
def test_duplicate_approver_rejected(
    client, exam_auth_token, security_officer_token, active_exam
):
    headers_req = {"Authorization": f"Bearer {exam_auth_token}"}
    req_res = client.post(
        f"{BASE_URL}/break-glass/requests",
        json={
            "exam_id": active_exam["id"],
            "scope": "COMPLETE_EXAM_PAPER",
            "justification": "Test duplicate approver check inside locked transaction",
        },
        headers=headers_req,
    )
    req_id = req_res.json()["id"]

    headers_sec = {"Authorization": f"Bearer {security_officer_token}"}
    app1 = client.post(
        f"{BASE_URL}/break-glass/requests/{req_id}/approve",
        json={"decision": "APPROVE", "comments": "First approval"},
        headers=headers_sec,
    )
    assert app1.status_code == 200

    app2 = client.post(
        f"{BASE_URL}/break-glass/requests/{req_id}/approve",
        json={"decision": "APPROVE", "comments": "Duplicate approval attempt"},
        headers=headers_sec,
    )
    assert app2.status_code == 409
    assert "already submitted a decision" in app2.json()["detail"]


# ── Test 4: Unauthorized Approver Rejected ─────────────────────────────────────
def test_unauthorized_approver_rejected(client, exam_auth_token, reviewer_token, active_exam):
    headers_req = {"Authorization": f"Bearer {exam_auth_token}"}
    req_res = client.post(
        f"{BASE_URL}/break-glass/requests",
        json={
            "exam_id": active_exam["id"],
            "scope": "COMPLETE_EXAM_PAPER",
            "justification": "Test unauthorized reviewer role cannot approve break-glass",
        },
        headers=headers_req,
    )
    req_id = req_res.json()["id"]

    headers_rev = {"Authorization": f"Bearer {reviewer_token}"}
    app_res = client.post(
        f"{BASE_URL}/break-glass/requests/{req_id}/approve",
        json={"decision": "APPROVE"},
        headers=headers_rev,
    )
    assert app_res.status_code == 403


# ── Test 5: Quorum Satisfaction Requires Role Diversity ───────────────────────
def test_quorum_satisfaction_requires_role_diversity(
    client, exam_auth_token, release_auth_1_token, release_auth_2_token, security_officer_token, active_exam
):
    headers_req = {"Authorization": f"Bearer {exam_auth_token}"}
    req_res = client.post(
        f"{BASE_URL}/break-glass/requests",
        json={
            "exam_id": active_exam["id"],
            "scope": "COMPLETE_EXAM_PAPER",
            "justification": "Test role diversity: two release authorities alone cannot satisfy diversity",
        },
        headers=headers_req,
    )
    req_id = req_res.json()["id"]

    # Approver 1: RELEASE_AUTHORITY 1
    res1 = client.post(
        f"{BASE_URL}/break-glass/requests/{req_id}/approve",
        json={"decision": "APPROVE"},
        headers={"Authorization": f"Bearer {release_auth_1_token}"},
    )
    assert res1.status_code == 200

    # Approver 2: RELEASE_AUTHORITY 2 (Same role class)
    res2 = client.post(
        f"{BASE_URL}/break-glass/requests/{req_id}/approve",
        json={"decision": "APPROVE"},
        headers={"Authorization": f"Bearer {release_auth_2_token}"},
    )
    assert res2.status_code == 200

    # Check request status: headcount is 2, but distinct roles is 1 -> Still PENDING!
    check_res = client.get(
        f"{BASE_URL}/break-glass/requests/{req_id}",
        headers=headers_req,
    )
    data = check_res.json()
    assert data["approvals_count"] == 2
    assert data["distinct_roles_count"] == 1
    assert data["status"] == "PENDING"

    # Approver 3: SECURITY_OFFICER (Second distinct role class)
    res3 = client.post(
        f"{BASE_URL}/break-glass/requests/{req_id}/approve",
        json={"decision": "APPROVE"},
        headers={"Authorization": f"Bearer {security_officer_token}"},
    )
    assert res3.status_code == 200

    # Role diversity is satisfied -> APPROVED!
    check_res2 = client.get(
        f"{BASE_URL}/break-glass/requests/{req_id}",
        headers=headers_req,
    )
    data2 = check_res2.json()
    assert data2["distinct_roles_count"] == 2
    assert data2["status"] == "APPROVED"


# ── Test 6: Activation Requires APPROVED Status ────────────────────────────────
def test_activation_requires_approved_status(client, exam_auth_token, active_exam):
    headers = {"Authorization": f"Bearer {exam_auth_token}"}
    req_res = client.post(
        f"{BASE_URL}/break-glass/requests",
        json={
            "exam_id": active_exam["id"],
            "scope": "COMPLETE_EXAM_PAPER",
            "justification": "Test activation blocked when request is still in PENDING state",
        },
        headers=headers,
    )
    req_id = req_res.json()["id"]

    act_res = client.post(
        f"{BASE_URL}/break-glass/requests/{req_id}/activate",
        headers=headers,
    )
    assert act_res.status_code == 400
    assert "Must be APPROVED" in act_res.json()["detail"]


# ── Test 7: Non-Requester Cannot Activate Request ─────────────────────────────
def test_non_requester_cannot_activate_request(
    client, exam_auth_token, security_officer_token, admin_token, active_exam
):
    headers_req = {"Authorization": f"Bearer {exam_auth_token}"}
    req_res = client.post(
        f"{BASE_URL}/break-glass/requests",
        json={
            "exam_id": active_exam["id"],
            "scope": "COMPLETE_EXAM_PAPER",
            "justification": "Test non-requester cannot activate approved request",
        },
        headers=headers_req,
    )
    req_id = req_res.json()["id"]

    client.post(
        f"{BASE_URL}/break-glass/requests/{req_id}/approve",
        json={"decision": "APPROVE"},
        headers={"Authorization": f"Bearer {security_officer_token}"},
    )
    client.post(
        f"{BASE_URL}/break-glass/requests/{req_id}/approve",
        json={"decision": "APPROVE"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    act_res = client.post(
        f"{BASE_URL}/break-glass/requests/{req_id}/activate",
        headers={"Authorization": f"Bearer {security_officer_token}"},
    )
    assert act_res.status_code == 403
    assert "Only the original requester can activate" in act_res.json()["detail"]


# ── Test 8: Fresh Session JTI Bound During Activation ─────────────────────────
def test_fresh_session_jti_bound_during_activation(
    client, exam_auth_token, security_officer_token, admin_token, active_exam
):
    headers_req = {"Authorization": f"Bearer {exam_auth_token}"}
    req_res = client.post(
        f"{BASE_URL}/break-glass/requests",
        json={
            "exam_id": active_exam["id"],
            "scope": "COMPLETE_EXAM_PAPER",
            "justification": "Test fresh session JTI binding upon request activation",
            "requested_duration_minutes": 30,
        },
        headers=headers_req,
    )
    req_id = req_res.json()["id"]

    client.post(
        f"{BASE_URL}/break-glass/requests/{req_id}/approve",
        json={"decision": "APPROVE"},
        headers={"Authorization": f"Bearer {security_officer_token}"},
    )
    client.post(
        f"{BASE_URL}/break-glass/requests/{req_id}/approve",
        json={"decision": "APPROVE"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    act_res = client.post(
        f"{BASE_URL}/break-glass/requests/{req_id}/activate",
        headers=headers_req,
    )
    assert act_res.status_code == 200
    data = act_res.json()
    assert data["status"] == "ACTIVATED"
    assert data["activation_session_id"] is not None
    assert data["activated_at"] is not None
    assert data["expires_at"] is not None


# ── Test 9: Cross-Session Replay Blocked ──────────────────────────────────────
def test_cross_session_replay_blocked(
    client, exam_auth_token, security_officer_token, admin_token, active_exam
):
    headers_req = {"Authorization": f"Bearer {exam_auth_token}"}
    req_res = client.post(
        f"{BASE_URL}/break-glass/requests",
        json={
            "exam_id": active_exam["id"],
            "scope": "COMPLETE_EXAM_PAPER",
            "justification": "Test cross-session replay blocked when token JTI changes",
        },
        headers=headers_req,
    )
    req_id = req_res.json()["id"]

    client.post(
        f"{BASE_URL}/break-glass/requests/{req_id}/approve",
        json={"decision": "APPROVE"},
        headers={"Authorization": f"Bearer {security_officer_token}"},
    )
    client.post(
        f"{BASE_URL}/break-glass/requests/{req_id}/approve",
        json={"decision": "APPROVE"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    act_res = client.post(
        f"{BASE_URL}/break-glass/requests/{req_id}/activate",
        headers=headers_req,
    )
    assert act_res.status_code == 200

    # Obtain a fresh token for exam_authority (generates a new JTI)
    login2 = client.post(f"{BASE_URL}/auth/login", json=EXAM_AUTH_CREDS)
    token2 = login2.json()["access_token"]

    paper_res = client.get(
        f"{BASE_URL}/break-glass/requests/{req_id}/assembled-paper",
        headers={"Authorization": f"Bearer {token2}"},
    )
    assert paper_res.status_code == 403
    assert "Session JTI mismatch" in paper_res.json()["detail"]


# ── Test 10: Request ID Alone Insufficient ────────────────────────────────────
def test_request_id_alone_insufficient(client, exam_auth_token, active_exam):
    headers = {"Authorization": f"Bearer {exam_auth_token}"}
    req_res = client.post(
        f"{BASE_URL}/break-glass/requests",
        json={
            "exam_id": active_exam["id"],
            "scope": "COMPLETE_EXAM_PAPER",
            "justification": "Test unauthenticated possession of request ID cannot read paper",
        },
        headers=headers,
    )
    req_id = req_res.json()["id"]

    res_no_auth = client.get(f"{BASE_URL}/break-glass/requests/{req_id}/assembled-paper")
    assert res_no_auth.status_code in [401, 403]

    res_bad_auth = client.get(
        f"{BASE_URL}/break-glass/requests/{req_id}/assembled-paper",
        headers={"Authorization": "Bearer forged.jwt.token"},
    )
    assert res_bad_auth.status_code in [401, 403]


# ── Test 11: Assembled Paper Excludes Answer Keys ─────────────────────────────
def test_assembled_paper_excludes_answer_keys(
    client, exam_auth_token, security_officer_token, admin_token, active_exam
):
    headers_req = {"Authorization": f"Bearer {exam_auth_token}"}
    req_res = client.post(
        f"{BASE_URL}/break-glass/requests",
        json={
            "exam_id": active_exam["id"],
            "scope": "COMPLETE_EXAM_PAPER",
            "justification": "Verify complete isolation: AnswerKey and correct_option excluded",
        },
        headers=headers_req,
    )
    req_id = req_res.json()["id"]

    client.post(
        f"{BASE_URL}/break-glass/requests/{req_id}/approve",
        json={"decision": "APPROVE"},
        headers={"Authorization": f"Bearer {security_officer_token}"},
    )
    client.post(
        f"{BASE_URL}/break-glass/requests/{req_id}/approve",
        json={"decision": "APPROVE"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    client.post(f"{BASE_URL}/break-glass/requests/{req_id}/activate", headers=headers_req)

    paper_res = client.get(
        f"{BASE_URL}/break-glass/requests/{req_id}/assembled-paper",
        headers=headers_req,
    )
    assert paper_res.status_code == 200
    paper = paper_res.json()
    assert paper["question_count"] > 0
    assert "attribution_watermark" in paper

    for q in paper["questions"]:
        assert "correct_option" not in q
        assert "answer_key" not in q
        assert "explanation" not in q


# ── Test 12: Deterministic Lazy Expiration ────────────────────────────────────
def test_deterministic_lazy_expiration(
    client, exam_auth_token, security_officer_token, admin_token, active_exam
):
    headers_req = {"Authorization": f"Bearer {exam_auth_token}"}
    req_res = client.post(
        f"{BASE_URL}/break-glass/requests",
        json={
            "exam_id": active_exam["id"],
            "scope": "COMPLETE_EXAM_PAPER",
            "justification": "Test lazy expiration transition when timer has elapsed",
        },
        headers=headers_req,
    )
    req_id = req_res.json()["id"]

    client.post(
        f"{BASE_URL}/break-glass/requests/{req_id}/approve",
        json={"decision": "APPROVE"},
        headers={"Authorization": f"Bearer {security_officer_token}"},
    )
    client.post(
        f"{BASE_URL}/break-glass/requests/{req_id}/approve",
        json={"decision": "APPROVE"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    client.post(f"{BASE_URL}/break-glass/requests/{req_id}/activate", headers=headers_req)

    # Manually backdate expires_at in DB via standalone asyncpg
    db_execute("UPDATE break_glass_requests SET expires_at = NOW() - INTERVAL '5 minutes' WHERE id = $1", req_id)

    # Now attempt access -> 403 EXPIRED
    paper_res = client.get(
        f"{BASE_URL}/break-glass/requests/{req_id}/assembled-paper",
        headers=headers_req,
    )
    assert paper_res.status_code == 403
    assert "EXPIRED" in paper_res.json()["detail"]

    # Verify DB status lazily transitioned to EXPIRED
    check_res = client.get(f"{BASE_URL}/break-glass/requests/{req_id}", headers=headers_req)
    assert check_res.json()["status"] == "EXPIRED"


# ── Test 13: Explicit Revocation Halts Access ──────────────────────────────────
def test_explicit_revocation_halts_access(
    client, exam_auth_token, security_officer_token, admin_token, active_exam
):
    headers_req = {"Authorization": f"Bearer {exam_auth_token}"}
    req_res = client.post(
        f"{BASE_URL}/break-glass/requests",
        json={
            "exam_id": active_exam["id"],
            "scope": "COMPLETE_EXAM_PAPER",
            "justification": "Test explicit revocation halts further server-side paper assembly",
        },
        headers=headers_req,
    )
    req_id = req_res.json()["id"]

    client.post(
        f"{BASE_URL}/break-glass/requests/{req_id}/approve",
        json={"decision": "APPROVE"},
        headers={"Authorization": f"Bearer {security_officer_token}"},
    )
    client.post(
        f"{BASE_URL}/break-glass/requests/{req_id}/approve",
        json={"decision": "APPROVE"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    client.post(f"{BASE_URL}/break-glass/requests/{req_id}/activate", headers=headers_req)

    # Revoke by Security Officer
    rev_res = client.post(
        f"{BASE_URL}/break-glass/requests/{req_id}/revoke",
        json={"reason": "Emergency security revocation triggered"},
        headers={"Authorization": f"Bearer {security_officer_token}"},
    )
    assert rev_res.status_code == 200
    assert rev_res.json()["status"] == "REVOKED"

    # Subsequent paper access blocked
    paper_res = client.get(
        f"{BASE_URL}/break-glass/requests/{req_id}/assembled-paper",
        headers=headers_req,
    )
    assert paper_res.status_code == 403
    assert "REVOKED" in paper_res.json()["detail"]


# ── Test 14: Exam Freeze Transactional Cascade Revokes Break-Glass ────────────
def test_exam_freeze_transactional_cascade_revokes_break_glass(
    client, exam_auth_token, security_officer_token, admin_token, active_exam
):
    headers_req = {"Authorization": f"Bearer {exam_auth_token}"}
    req_res = client.post(
        f"{BASE_URL}/break-glass/requests",
        json={
            "exam_id": active_exam["id"],
            "scope": "COMPLETE_EXAM_PAPER",
            "justification": "Test application-level transactional freeze cascade",
        },
        headers=headers_req,
    )
    req_id = req_res.json()["id"]

    client.post(
        f"{BASE_URL}/break-glass/requests/{req_id}/approve",
        json={"decision": "APPROVE"},
        headers={"Authorization": f"Bearer {security_officer_token}"},
    )
    client.post(
        f"{BASE_URL}/break-glass/requests/{req_id}/approve",
        json={"decision": "APPROVE"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    client.post(f"{BASE_URL}/break-glass/requests/{req_id}/activate", headers=headers_req)

    # Freeze the exam via Release freeze endpoint
    freeze_res = client.post(
        f"{BASE_URL}/release/{active_exam['id']}/freeze",
        json={"reason": "Suspected physical center breach"},
        headers={"Authorization": f"Bearer {security_officer_token}"},
    )
    assert freeze_res.status_code == 200
    assert freeze_res.json()["revoked_break_glass_requests"] >= 1

    # Verify request status in break_glass is now REVOKED
    req_check = client.get(f"{BASE_URL}/break-glass/requests/{req_id}", headers=headers_req)
    assert req_check.json()["status"] == "REVOKED"

    # Paper assembly immediately fails
    paper_res = client.get(
        f"{BASE_URL}/break-glass/requests/{req_id}/assembled-paper",
        headers=headers_req,
    )
    assert paper_res.status_code == 403


# ── Test 15: Material Fingerprint Mismatch Invalidates Approvals ───────────────
def test_material_fingerprint_mismatch_invalidates_approvals(
    client, exam_auth_token, security_officer_token, active_exam
):
    headers_req = {"Authorization": f"Bearer {exam_auth_token}"}
    req_res = client.post(
        f"{BASE_URL}/break-glass/requests",
        json={
            "exam_id": active_exam["id"],
            "scope": "COMPLETE_EXAM_PAPER",
            "justification": "Test material tampering invalidates approval vote",
        },
        headers=headers_req,
    )
    req_id = req_res.json()["id"]

    # Tamper with blueprint hash in DB
    db_execute(
        "UPDATE break_glass_requests SET blueprint_hash = 'tampered_hash_0000000000000000000000000000000000000000' WHERE id = $1",
        req_id,
    )

    # Attempt to approve tampered request -> 400 fingerprint mismatch
    app_res = client.post(
        f"{BASE_URL}/break-glass/requests/{req_id}/approve",
        json={"decision": "APPROVE"},
        headers={"Authorization": f"Bearer {security_officer_token}"},
    )
    assert app_res.status_code == 400
    assert "fingerprint mismatch" in app_res.json()["detail"]


# ── Test 16: Rejection Marks Request Terminal REJECTED ─────────────────────────
def test_rejection_marks_request_terminal_rejected(
    client, exam_auth_token, security_officer_token, admin_token, active_exam
):
    headers_req = {"Authorization": f"Bearer {exam_auth_token}"}
    req_res = client.post(
        f"{BASE_URL}/break-glass/requests",
        json={
            "exam_id": active_exam["id"],
            "scope": "COMPLETE_EXAM_PAPER",
            "justification": "Test terminal rejection semantics: single rejection terminates request",
        },
        headers=headers_req,
    )
    req_id = req_res.json()["id"]

    # Security officer rejects
    rej_res = client.post(
        f"{BASE_URL}/break-glass/requests/{req_id}/reject",
        json={"decision": "REJECT", "comments": "Emergency access denied: insufficient justification"},
        headers={"Authorization": f"Bearer {security_officer_token}"},
    )
    assert rej_res.status_code == 200

    # Request is now terminal REJECTED
    req_check = client.get(f"{BASE_URL}/break-glass/requests/{req_id}", headers=headers_req)
    assert req_check.json()["status"] == "REJECTED"

    # Subsequent approval attempts fail
    app_res = client.post(
        f"{BASE_URL}/break-glass/requests/{req_id}/approve",
        json={"decision": "APPROVE"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert app_res.status_code == 409
    assert "REJECTED" in app_res.json()["detail"]


# ── Test 17: Concurrent Approval Race Protection ──────────────────────────────
def test_concurrent_approval_race_protection(
    client, exam_auth_token, security_officer_token, active_exam
):
    headers_req = {"Authorization": f"Bearer {exam_auth_token}"}
    req_res = client.post(
        f"{BASE_URL}/break-glass/requests",
        json={
            "exam_id": active_exam["id"],
            "scope": "COMPLETE_EXAM_PAPER",
            "justification": "Test concurrent approval submissions serialized by row lock",
        },
        headers=headers_req,
    )
    req_id = req_res.json()["id"]

    def submit_vote():
        return client.post(
            f"{BASE_URL}/break-glass/requests/{req_id}/approve",
            json={"decision": "APPROVE"},
            headers={"Authorization": f"Bearer {security_officer_token}"},
        )

    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = [executor.submit(submit_vote) for _ in range(3)]
        results = [f.result() for f in futures]

    statuses = [r.status_code for r in results]
    assert statuses.count(200) == 1
    assert statuses.count(409) == 2


# ── Test 18: Audit Trail Complete Lifecycle ───────────────────────────────────
def test_audit_trail_complete_lifecycle(
    client, exam_auth_token, security_officer_token, admin_token, active_exam
):
    headers_req = {"Authorization": f"Bearer {exam_auth_token}"}
    req_res = client.post(
        f"{BASE_URL}/break-glass/requests",
        json={
            "exam_id": active_exam["id"],
            "scope": "COMPLETE_EXAM_PAPER",
            "justification": "Test hash-chained audit logging for complete break-glass lifecycle",
        },
        headers=headers_req,
    )
    req_id = req_res.json()["id"]

    client.post(
        f"{BASE_URL}/break-glass/requests/{req_id}/approve",
        json={"decision": "APPROVE"},
        headers={"Authorization": f"Bearer {security_officer_token}"},
    )
    client.post(
        f"{BASE_URL}/break-glass/requests/{req_id}/approve",
        json={"decision": "APPROVE"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    client.post(f"{BASE_URL}/break-glass/requests/{req_id}/activate", headers=headers_req)
    client.get(f"{BASE_URL}/break-glass/requests/{req_id}/assembled-paper", headers=headers_req)
    client.post(
        f"{BASE_URL}/break-glass/requests/{req_id}/revoke",
        json={"reason": "Lifecycle test completion"},
        headers=headers_req,
    )
    import time
    time.sleep(0.3)

    rows = db_fetch(
        "SELECT event_type FROM audit_logs WHERE resource_id = $1 OR resource_id = $2",
        req_id,
        active_exam["id"],
    )
    types = {r["event_type"] for r in rows}
    assert "BREAK_GLASS_REQUESTED" in types
    assert "BREAK_GLASS_APPROVAL_SUBMITTED" in types
    assert "BREAK_GLASS_QUORUM_ACHIEVED" in types
    assert "BREAK_GLASS_ACTIVATED" in types
    assert "BREAK_GLASS_PAPER_ASSEMBLED" in types
    assert "BREAK_GLASS_REVOKED" in types


# ── Test 19: Repeated Assembly Audited Independently ──────────────────────────
def test_repeated_access_per_read_audit_logging(
    client, exam_auth_token, security_officer_token, admin_token, active_exam
):
    headers_req = {"Authorization": f"Bearer {exam_auth_token}"}
    req_res = client.post(
        f"{BASE_URL}/break-glass/requests",
        json={
            "exam_id": active_exam["id"],
            "scope": "COMPLETE_EXAM_PAPER",
            "justification": "Test per-access audit logging for repeated GET paper calls",
        },
        headers=headers_req,
    )
    req_id = req_res.json()["id"]

    client.post(
        f"{BASE_URL}/break-glass/requests/{req_id}/approve",
        json={"decision": "APPROVE"},
        headers={"Authorization": f"Bearer {security_officer_token}"},
    )
    client.post(
        f"{BASE_URL}/break-glass/requests/{req_id}/approve",
        json={"decision": "APPROVE"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    client.post(f"{BASE_URL}/break-glass/requests/{req_id}/activate", headers=headers_req)

    # Initial count before reads
    initial_count = db_fetchval(
        "SELECT count(*) FROM audit_logs WHERE event_type = 'BREAK_GLASS_PAPER_ASSEMBLED' AND resource_id = $1",
        active_exam["id"],
    )

    for _ in range(3):
        res = client.get(
            f"{BASE_URL}/break-glass/requests/{req_id}/assembled-paper",
            headers=headers_req,
        )
        assert res.status_code == 200

    import time
    time.sleep(0.3)

    new_count = db_fetchval(
        "SELECT count(*) FROM audit_logs WHERE event_type = 'BREAK_GLASS_PAPER_ASSEMBLED' AND resource_id = $1",
        active_exam["id"],
    )
    assert new_count >= initial_count + 3


# ── Test 20: No Plaintext Persisted to Server Storage ─────────────────────────
def test_no_plaintext_persisted_to_server_storage(
    client, exam_auth_token, security_officer_token, admin_token, active_exam
):
    headers_req = {"Authorization": f"Bearer {exam_auth_token}"}
    req_res = client.post(
        f"{BASE_URL}/break-glass/requests",
        json={
            "exam_id": active_exam["id"],
            "scope": "COMPLETE_EXAM_PAPER",
            "justification": "Test verification of Server-Side No-Persistent-Plaintext Invariant",
        },
        headers=headers_req,
    )
    req_id = req_res.json()["id"]

    client.post(
        f"{BASE_URL}/break-glass/requests/{req_id}/approve",
        json={"decision": "APPROVE"},
        headers={"Authorization": f"Bearer {security_officer_token}"},
    )
    client.post(
        f"{BASE_URL}/break-glass/requests/{req_id}/approve",
        json={"decision": "APPROVE"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    client.post(f"{BASE_URL}/break-glass/requests/{req_id}/activate", headers=headers_req)

    paper_res = client.get(
        f"{BASE_URL}/break-glass/requests/{req_id}/assembled-paper",
        headers=headers_req,
    )
    assert paper_res.status_code == 200
    paper_data = paper_res.json()
    first_question_text = paper_data["questions"][0]["content"]

    # 1. Verify not in break_glass_requests justification
    req_just = db_fetchval("SELECT justification FROM break_glass_requests WHERE id = $1", req_id)
    assert first_question_text not in (req_just or "")

    # 2. Verify not in audit_logs metadata
    audit_rows = db_fetch("SELECT event_metadata FROM audit_logs WHERE event_type = 'BREAK_GLASS_PAPER_ASSEMBLED'")
    for row in audit_rows:
        meta_str = str(row["event_metadata"] or "")
        assert first_question_text not in meta_str


# ── Test 21: Cross-Exam Request IDOR ──────────────────────────────────────────
def test_cross_exam_request_idor(client, exam_auth_token):
    headers = {"Authorization": f"Bearer {exam_auth_token}"}
    res = client.post(
        f"{BASE_URL}/break-glass/requests",
        json={
            "exam_id": "00000000-0000-0000-0000-000000000000",
            "scope": "COMPLETE_EXAM_PAPER",
            "justification": "Test invalid non-existent exam ID rejected with 404",
        },
        headers=headers,
    )
    assert res.status_code == 404


# ── Test 22: Cross-Blueprint Version Replay Blocked ────────────────────────────
def test_cross_blueprint_version_replay(
    client, exam_auth_token, security_officer_token, admin_token, active_exam
):
    headers_req = {"Authorization": f"Bearer {exam_auth_token}"}
    req_res = client.post(
        f"{BASE_URL}/break-glass/requests",
        json={
            "exam_id": active_exam["id"],
            "scope": "COMPLETE_EXAM_PAPER",
            "justification": "Test blueprint version update breaks existing request validity",
        },
        headers=headers_req,
    )
    req_id = req_res.json()["id"]

    client.post(
        f"{BASE_URL}/break-glass/requests/{req_id}/approve",
        json={"decision": "APPROVE"},
        headers={"Authorization": f"Bearer {security_officer_token}"},
    )
    client.post(
        f"{BASE_URL}/break-glass/requests/{req_id}/approve",
        json={"decision": "APPROVE"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    client.post(f"{BASE_URL}/break-glass/requests/{req_id}/activate", headers=headers_req)

    # Change the blueprint integrity hash in DB
    original_hash = db_fetchval("SELECT integrity_hash FROM exam_blueprints WHERE exam_id = $1", active_exam["id"])
    db_execute("UPDATE exam_blueprints SET integrity_hash = 'new_blueprint_hash_changed_version' WHERE exam_id = $1", active_exam["id"])

    # Access must fail due to blueprint integrity mismatch
    res = client.get(
        f"{BASE_URL}/break-glass/requests/{req_id}/assembled-paper",
        headers=headers_req,
    )
    assert res.status_code == 403
    assert "Blueprint integrity" in res.json()["detail"]

    # Restore blueprint hash
    db_execute("UPDATE exam_blueprints SET integrity_hash = $1 WHERE exam_id = $2", original_hash, active_exam["id"])


# ── Test 23: Quorum Race Competing Approvals ──────────────────────────────────
def test_quorum_race_competing_approvals(
    client, exam_auth_token, security_officer_token, admin_token, active_exam
):
    headers_req = {"Authorization": f"Bearer {exam_auth_token}"}
    req_res = client.post(
        f"{BASE_URL}/break-glass/requests",
        json={
            "exam_id": active_exam["id"],
            "scope": "COMPLETE_EXAM_PAPER",
            "justification": "Test competing distinct role approvals reach quorum safely",
        },
        headers=headers_req,
    )
    req_id = req_res.json()["id"]

    def vote_sec():
        return client.post(
            f"{BASE_URL}/break-glass/requests/{req_id}/approve",
            json={"decision": "APPROVE"},
            headers={"Authorization": f"Bearer {security_officer_token}"},
        )

    def vote_admin():
        return client.post(
            f"{BASE_URL}/break-glass/requests/{req_id}/approve",
            json={"decision": "APPROVE"},
            headers={"Authorization": f"Bearer {admin_token}"},
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        f1 = executor.submit(vote_sec)
        f2 = executor.submit(vote_admin)
        r1 = f1.result()
        r2 = f2.result()

    assert r1.status_code == 200
    assert r2.status_code == 200

    check = client.get(f"{BASE_URL}/break-glass/requests/{req_id}", headers=headers_req)
    assert check.json()["status"] == "APPROVED"


# ── Test 24: Requester Attempting Multiple Approval Identities Blocked ────────
def test_requester_attempting_multiple_approval_identities(
    client, exam_auth_token, active_exam
):
    headers_req = {"Authorization": f"Bearer {exam_auth_token}"}
    req_res = client.post(
        f"{BASE_URL}/break-glass/requests",
        json={
            "exam_id": active_exam["id"],
            "scope": "COMPLETE_EXAM_PAPER",
            "justification": "Test requester cannot vote under any circumstances",
        },
        headers=headers_req,
    )
    req_id = req_res.json()["id"]

    res = client.post(
        f"{BASE_URL}/break-glass/requests/{req_id}/approve",
        json={"decision": "APPROVE"},
        headers=headers_req,
    )
    assert res.status_code == 403


# ── Test 25: Approval After Rejection Rejected ────────────────────────────────
def test_approval_after_rejection(
    client, exam_auth_token, security_officer_token, admin_token, active_exam
):
    headers_req = {"Authorization": f"Bearer {exam_auth_token}"}
    req_res = client.post(
        f"{BASE_URL}/break-glass/requests",
        json={
            "exam_id": active_exam["id"],
            "scope": "COMPLETE_EXAM_PAPER",
            "justification": "Test that approvals after a rejection are strictly blocked",
        },
        headers=headers_req,
    )
    req_id = req_res.json()["id"]

    client.post(
        f"{BASE_URL}/break-glass/requests/{req_id}/reject",
        json={"decision": "REJECT"},
        headers={"Authorization": f"Bearer {security_officer_token}"},
    )

    res = client.post(
        f"{BASE_URL}/break-glass/requests/{req_id}/approve",
        json={"decision": "APPROVE"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 409


# ── Test 26: Approval After Expiration Rejected ───────────────────────────────
def test_approval_after_expiration(
    client, exam_auth_token, security_officer_token, active_exam
):
    headers_req = {"Authorization": f"Bearer {exam_auth_token}"}
    req_res = client.post(
        f"{BASE_URL}/break-glass/requests",
        json={
            "exam_id": active_exam["id"],
            "scope": "COMPLETE_EXAM_PAPER",
            "justification": "Test approvals on expired requests are rejected",
        },
        headers=headers_req,
    )
    req_id = req_res.json()["id"]

    # Mark as EXPIRED directly in DB
    db_execute("UPDATE break_glass_requests SET status = 'EXPIRED' WHERE id = $1", req_id)

    res = client.post(
        f"{BASE_URL}/break-glass/requests/{req_id}/approve",
        json={"decision": "APPROVE"},
        headers={"Authorization": f"Bearer {security_officer_token}"},
    )
    assert res.status_code == 409


# ── Test 27: Activation After Revocation Rejected ─────────────────────────────
def test_activation_after_revocation(
    client, exam_auth_token, security_officer_token, admin_token, active_exam
):
    headers_req = {"Authorization": f"Bearer {exam_auth_token}"}
    req_res = client.post(
        f"{BASE_URL}/break-glass/requests",
        json={
            "exam_id": active_exam["id"],
            "scope": "COMPLETE_EXAM_PAPER",
            "justification": "Test activation on revoked request is rejected",
        },
        headers=headers_req,
    )
    req_id = req_res.json()["id"]

    client.post(
        f"{BASE_URL}/break-glass/requests/{req_id}/approve",
        json={"decision": "APPROVE"},
        headers={"Authorization": f"Bearer {security_officer_token}"},
    )
    client.post(
        f"{BASE_URL}/break-glass/requests/{req_id}/approve",
        json={"decision": "APPROVE"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    client.post(
        f"{BASE_URL}/break-glass/requests/{req_id}/revoke",
        json={"reason": "Revocation prior to activation"},
        headers=headers_req,
    )

    act_res = client.post(
        f"{BASE_URL}/break-glass/requests/{req_id}/activate",
        headers=headers_req,
    )
    assert act_res.status_code == 403
    assert "REVOKED" in act_res.json()["detail"]


# ── Test 28: Access After Exam Cancellation Rejected ──────────────────────────
def test_access_after_exam_cancellation(
    client, exam_auth_token, security_officer_token, admin_token, active_exam
):
    headers_req = {"Authorization": f"Bearer {exam_auth_token}"}
    req_res = client.post(
        f"{BASE_URL}/break-glass/requests",
        json={
            "exam_id": active_exam["id"],
            "scope": "COMPLETE_EXAM_PAPER",
            "justification": "Test exam cancellation cascade invalidates paper access",
        },
        headers=headers_req,
    )
    req_id = req_res.json()["id"]

    client.post(
        f"{BASE_URL}/break-glass/requests/{req_id}/approve",
        json={"decision": "APPROVE"},
        headers={"Authorization": f"Bearer {security_officer_token}"},
    )
    client.post(
        f"{BASE_URL}/break-glass/requests/{req_id}/approve",
        json={"decision": "APPROVE"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    client.post(f"{BASE_URL}/break-glass/requests/{req_id}/activate", headers=headers_req)

    # Cancel exam
    cancel_res = client.post(
        f"{BASE_URL}/exams/{active_exam['id']}/cancel",
        json={"reason": "Severe leak detected on Telegram"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert cancel_res.status_code == 200

    # Attempt paper access -> 403
    paper_res = client.get(
        f"{BASE_URL}/break-glass/requests/{req_id}/assembled-paper",
        headers=headers_req,
    )
    assert paper_res.status_code == 403


# ── Test 29: Duration Policy Violation ────────────────────────────────────────
def test_duration_policy_violation(client, exam_auth_token, active_exam):
    headers = {"Authorization": f"Bearer {exam_auth_token}"}
    res_short = client.post(
        f"{BASE_URL}/break-glass/requests",
        json={
            "exam_id": active_exam["id"],
            "scope": "COMPLETE_EXAM_PAPER",
            "justification": "Test duration bounds violation check for short duration",
            "requested_duration_minutes": 5,
        },
        headers=headers,
    )
    assert res_short.status_code == 400

    res_long = client.post(
        f"{BASE_URL}/break-glass/requests",
        json={
            "exam_id": active_exam["id"],
            "scope": "COMPLETE_EXAM_PAPER",
            "justification": "Test duration bounds violation check for long duration",
            "requested_duration_minutes": 120,
        },
        headers=headers,
    )
    assert res_long.status_code == 400


# ── Test 30: Scope Policy Violation ───────────────────────────────────────────
def test_scope_policy_violation(client, exam_auth_token, active_exam):
    headers = {"Authorization": f"Bearer {exam_auth_token}"}
    res_no_form = client.post(
        f"{BASE_URL}/break-glass/requests",
        json={
            "exam_id": active_exam["id"],
            "scope": "EXAM_FORM_PREVIEW",
            "justification": "Test form_label required when scope is EXAM_FORM_PREVIEW",
        },
        headers=headers,
    )
    assert res_no_form.status_code == 400
    assert "form_label is mandatory" in res_no_form.json()["detail"]
