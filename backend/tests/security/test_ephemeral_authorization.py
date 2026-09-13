"""
B-SEA — Phase 3A Dynamic & Ephemeral Question Access Control Test Suite
Validates:
1. Grant creation with valid assignment (GRANTED -> ACTIVE)
2. Grant denied without assignment (403)
3. Grant ID alone is insufficient (unauthenticated / forged actor fails)
4. Cross-actor grant replay blocked (Reviewer B cannot use Reviewer A's grant)
5. Cross-question grant replay blocked (Grant for Q1 cannot access Q2)
6. Operation escalation blocked (VIEW grant cannot start/submit review)
7. Purpose mismatch blocked (Grant purpose must match assignment purpose)
8. Role escalation blocked (Reviewer cannot approve even with grant)
9. Policy intersection matrix enforcement (Role ∩ Purpose ∩ Permission)
10. Revoked assignment invalidates grants immediately
11. Atomic reassignment cascades grant revocation
12. Deterministic lazy expiration (expired grant rejected and marked EXPIRED)
13. Completed assignment invalidates remaining grants
14. Session binding validation (JTI mismatch rejected)
15. IDOR random/forged grant ID rejected
16. Answer key isolation preserved (grant never reveals answer key)
17. Audit trail logs all grant lifecycle events
18. Concurrent grant creation protection (partial unique index / lock)
19. Explicit grant revocation endpoint
20. Duplicate active grant returns existing active grant
"""
import secrets
from datetime import datetime, timezone, timedelta
from concurrent.futures import ThreadPoolExecutor
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.models import (
    AccessGrantStatus,
    QuestionAssignmentStatus,
    QuestionOperation,
    ReviewPurpose,
    UserRoleEnum,
)

BASE_URL = "/api/v1"
ADMIN_CREDS = {"username": "admin", "password": "BSeaDemo@2026"}
SETTER_CREDS = {"username": "q_setter_1", "password": "BSeaDemo@2026"}
REVIEWER_1_CREDS = {"username": "reviewer_1", "password": "BSeaDemo@2026"}
REVIEWER_2_CREDS = {"username": "reviewer_2", "password": "BSeaDemo@2026"}
MODERATOR_CREDS = {"username": "moderator_1", "password": "BSeaDemo@2026"}


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
def setter_token(client):
    res = client.post(f"{BASE_URL}/auth/login", json=SETTER_CREDS)
    assert res.status_code == 200
    return res.json()["access_token"]


@pytest.fixture(scope="module")
def reviewer_1_token(client):
    res = client.post(f"{BASE_URL}/auth/login", json=REVIEWER_1_CREDS)
    assert res.status_code == 200
    return res.json()["access_token"]


@pytest.fixture(scope="module")
def reviewer_2_user(client, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    users = client.get(f"{BASE_URL}/users/", headers=headers).json()
    r2 = next((u for u in users if u["username"] == "reviewer_2"), None)
    if not r2:
        res = client.post(
            f"{BASE_URL}/users/",
            json={
                "username": "reviewer_2",
                "email": "reviewer_2@bsea.gov.in",
                "password": "BSeaDemo@2026",
                "full_name": "Second Reviewer",
                "role": "REVIEWER",
            },
            headers=headers,
        )
        assert res.status_code == 200
        r2 = res.json()
    return r2


@pytest.fixture(scope="module")
def reviewer_2_token(client, reviewer_2_user):
    res = client.post(f"{BASE_URL}/auth/login", json=REVIEWER_2_CREDS)
    assert res.status_code == 200
    return res.json()["access_token"]


@pytest.fixture(scope="module")
def moderator_token(client):
    res = client.post(f"{BASE_URL}/auth/login", json=MODERATOR_CREDS)
    assert res.status_code == 200
    return res.json()["access_token"]


@pytest.fixture(scope="module")
def user_ids(client, admin_token, reviewer_2_user):
    headers = {"Authorization": f"Bearer {admin_token}"}
    res = client.get(f"{BASE_URL}/users/", headers=headers)
    assert res.status_code == 200
    users = res.json()
    id_map = {u["username"]: u["id"] for u in users}
    id_map["reviewer_2"] = reviewer_2_user["id"]
    return id_map


@pytest.fixture(scope="module")
def exam_id(client, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    res = client.get(f"{BASE_URL}/exams/", headers=headers)
    assert res.status_code == 200
    exams = res.json()
    assert len(exams) > 0
    return exams[0]["id"]


def create_and_assign_question(
    client, admin_token, setter_token, reviewer_id, exam_id, purpose="TECHNICAL_REVIEW"
):
    """Helper: create question, submit it, and assign to reviewer."""
    headers_setter = {"Authorization": f"Bearer {setter_token}"}
    payload = {
        "exam_id": exam_id,
        "subject": "PHYSICS",
        "topic": "Thermodynamics",
        "difficulty": "medium",
        "bloom_level": "Analyze",
        "content": {
            "text": f"Question {secrets.token_hex(4)}: First law of thermodynamics",
            "options": ["dU = dQ - dW", "dU = dQ + dW", "dQ = 0", "dW = 0"],
        },
        "correct_option": 0,
        "marks_positive": 4.0,
        "marks_negative": 1.0,
    }
    create_res = client.post(f"{BASE_URL}/questions/", json=payload, headers=headers_setter)
    assert create_res.status_code == 200
    q_id = create_res.json()["id"]

    sub_res = client.post(f"{BASE_URL}/questions/{q_id}/submit", headers=headers_setter)
    assert sub_res.status_code == 200

    headers_admin = {"Authorization": f"Bearer {admin_token}"}
    assign_res = client.post(
        f"{BASE_URL}/questions/{q_id}/assign",
        json={"reviewer_id": reviewer_id, "purpose": purpose},
        headers=headers_admin,
    )
    assert assign_res.status_code == 200
    assignment_id = assign_res.json()["assignment_id"]
    return q_id, assignment_id


# ── TEST 1: GRANT CREATION WITH VALID ASSIGNMENT ──────────────────────────────

def test_grant_creation_with_valid_assignment(
    client, admin_token, setter_token, reviewer_1_token, user_ids, exam_id
):
    """Reviewer with active assignment can request an ephemeral access grant."""
    q_id, _ = create_and_assign_question(
        client, admin_token, setter_token, user_ids["reviewer_1"], exam_id
    )

    headers = {"Authorization": f"Bearer {reviewer_1_token}"}
    grant_res = client.post(
        f"{BASE_URL}/questions/{q_id}/access-grant",
        json={"operation": "VIEW", "purpose": "TECHNICAL_REVIEW", "expires_in_minutes": 15},
        headers=headers,
    )
    assert grant_res.status_code == 200
    data = grant_res.json()
    assert data["success"] is True
    assert "grant_id" in data
    assert data["status"] == "GRANTED"
    assert data["operation"] == "VIEW"
    assert data["purpose"] == "TECHNICAL_REVIEW"
    assert data["expires_at"] is not None


# ── TEST 2: GRANT DENIED WITHOUT ASSIGNMENT ───────────────────────────────────

def test_grant_denied_without_assignment(
    client, admin_token, setter_token, reviewer_2_token, user_ids, exam_id
):
    """Reviewer without assignment cannot request an access grant."""
    # Question assigned to reviewer_1
    q_id, _ = create_and_assign_question(
        client, admin_token, setter_token, user_ids["reviewer_1"], exam_id
    )

    # Reviewer 2 attempts to request grant
    headers = {"Authorization": f"Bearer {reviewer_2_token}"}
    grant_res = client.post(
        f"{BASE_URL}/questions/{q_id}/access-grant",
        json={"operation": "VIEW", "purpose": "TECHNICAL_REVIEW"},
        headers=headers,
    )
    assert grant_res.status_code == 403
    assert "no assignment found" in grant_res.json()["detail"].lower() or "not assigned" in grant_res.json()["detail"].lower()


# ── TEST 3: GRANT ID ALONE IS INSUFFICIENT ────────────────────────────────────

def test_grant_id_alone_is_insufficient(
    client, admin_token, setter_token, reviewer_1_token, user_ids, exam_id
):
    """Submitting valid grant_id without authentication token fails authorization."""
    q_id, _ = create_and_assign_question(
        client, admin_token, setter_token, user_ids["reviewer_1"], exam_id
    )
    headers = {"Authorization": f"Bearer {reviewer_1_token}"}
    grant_res = client.post(
        f"{BASE_URL}/questions/{q_id}/access-grant",
        json={"operation": "VIEW"},
        headers=headers,
    )
    grant_id = grant_res.json()["grant_id"]

    # Request without Authorization header (only grant_id)
    unauth_res = client.get(f"{BASE_URL}/questions/{q_id}?grant_id={grant_id}")
    assert unauth_res.status_code in [401, 403]


# ── TEST 4: CROSS-ACTOR GRANT REPLAY BLOCKED ─────────────────────────────────

def test_cross_actor_grant_replay_blocked(
    client, admin_token, setter_token, reviewer_1_token, reviewer_2_token, user_ids, exam_id
):
    """Reviewer 2 cannot use Reviewer 1's valid grant_id."""
    q_id, _ = create_and_assign_question(
        client, admin_token, setter_token, user_ids["reviewer_1"], exam_id
    )
    headers_1 = {"Authorization": f"Bearer {reviewer_1_token}"}
    grant_res = client.post(
        f"{BASE_URL}/questions/{q_id}/access-grant",
        json={"operation": "VIEW"},
        headers=headers_1,
    )
    grant_id = grant_res.json()["grant_id"]

    # Reviewer 2 tries to use reviewer_1's grant_id
    headers_2 = {"Authorization": f"Bearer {reviewer_2_token}"}
    replay_res = client.get(
        f"{BASE_URL}/questions/{q_id}?grant_id={grant_id}",
        headers=headers_2,
    )
    assert replay_res.status_code == 403
    assert "different user" in replay_res.json()["detail"].lower() or "mismatch" in replay_res.json()["detail"].lower()


# ── TEST 5: CROSS-QUESTION GRANT REPLAY BLOCKED ──────────────────────────────

def test_cross_question_grant_replay_blocked(
    client, admin_token, setter_token, reviewer_1_token, user_ids, exam_id
):
    """Grant issued for Question A cannot be used to access Question B."""
    q_a, _ = create_and_assign_question(
        client, admin_token, setter_token, user_ids["reviewer_1"], exam_id
    )
    q_b, _ = create_and_assign_question(
        client, admin_token, setter_token, user_ids["reviewer_1"], exam_id
    )

    headers = {"Authorization": f"Bearer {reviewer_1_token}"}
    grant_res = client.post(
        f"{BASE_URL}/questions/{q_a}/access-grant",
        json={"operation": "VIEW"},
        headers=headers,
    )
    grant_id = grant_res.json()["grant_id"]

    # Attempt to access q_b using q_a's grant
    replay_res = client.get(
        f"{BASE_URL}/questions/{q_b}?grant_id={grant_id}",
        headers=headers,
    )
    assert replay_res.status_code == 403
    assert "grant does not apply to this question" in replay_res.json()["detail"].lower() or "mismatch" in replay_res.json()["detail"].lower()


# ── TEST 6: OPERATION ESCALATION BLOCKED ─────────────────────────────────────

def test_operation_escalation_blocked(
    client, admin_token, setter_token, reviewer_1_token, user_ids, exam_id
):
    """A grant issued for VIEW cannot authorize REVIEW or APPROVE operations."""
    q_id, assignment_id = create_and_assign_question(
        client, admin_token, setter_token, user_ids["reviewer_1"], exam_id
    )

    headers = {"Authorization": f"Bearer {reviewer_1_token}"}
    # Issue VIEW grant
    grant_res = client.post(
        f"{BASE_URL}/questions/{q_id}/access-grant",
        json={"operation": "VIEW"},
        headers=headers,
    )
    view_grant_id = grant_res.json()["grant_id"]

    # Attempt to start review using VIEW grant
    escalate_res = client.post(
        f"{BASE_URL}/questions/assignments/{assignment_id}/start",
        json={"grant_id": view_grant_id},
        headers=headers,
    )
    assert escalate_res.status_code == 403
    assert "operation is view" in escalate_res.json()["detail"].lower() or "operation" in escalate_res.json()["detail"].lower()


# ── TEST 7: PURPOSE MISMATCH BLOCKED ─────────────────────────────────────────

def test_purpose_mismatch_blocked(
    client, admin_token, setter_token, reviewer_1_token, user_ids, exam_id
):
    """Requesting grant with purpose differing from assigned purpose is rejected."""
    # Assigned for TECHNICAL_REVIEW
    q_id, _ = create_and_assign_question(
        client, admin_token, setter_token, user_ids["reviewer_1"], exam_id, purpose="TECHNICAL_REVIEW"
    )

    headers = {"Authorization": f"Bearer {reviewer_1_token}"}
    # Request grant for LANGUAGE_REVIEW
    mismatch_res = client.post(
        f"{BASE_URL}/questions/{q_id}/access-grant",
        json={"operation": "VIEW", "purpose": "LANGUAGE_REVIEW"},
        headers=headers,
    )
    assert mismatch_res.status_code == 403
    assert "purpose mismatch" in mismatch_res.json()["detail"].lower()


# ── TEST 8: ROLE ESCALATION BLOCKED ──────────────────────────────────────────

def test_role_escalation_blocked(
    client, admin_token, setter_token, reviewer_1_token, user_ids, exam_id
):
    """Reviewer cannot obtain an APPROVE grant or approve a question."""
    q_id, _ = create_and_assign_question(
        client, admin_token, setter_token, user_ids["reviewer_1"], exam_id
    )

    headers = {"Authorization": f"Bearer {reviewer_1_token}"}
    # Attempt to request APPROVE grant
    grant_res = client.post(
        f"{BASE_URL}/questions/{q_id}/access-grant",
        json={"operation": "APPROVE"},
        headers=headers,
    )
    assert grant_res.status_code == 403
    assert "not permitted" in grant_res.json()["detail"].lower() or "denied" in grant_res.json()["detail"].lower()


# ── TEST 9: POLICY INTERSECTION MATRIX ENFORCEMENT ───────────────────────────

def test_policy_intersection_matrix(
    client, admin_token, setter_token, reviewer_1_token, user_ids, exam_id
):
    """Validates that Reviewer role can only perform permitted operations."""
    q_id, _ = create_and_assign_question(
        client, admin_token, setter_token, user_ids["reviewer_1"], exam_id
    )
    headers = {"Authorization": f"Bearer {reviewer_1_token}"}

    # REVIEWER can request VIEW and REVIEW
    res_view = client.post(
        f"{BASE_URL}/questions/{q_id}/access-grant",
        json={"operation": "VIEW"},
        headers=headers,
    )
    assert res_view.status_code == 200

    # Explicitly revoke VIEW grant so we can request REVIEW grant
    client.post(
        f"{BASE_URL}/questions/grants/{res_view.json()['grant_id']}/revoke",
        json={"reason": "Testing next op"},
        headers=headers,
    )

    res_review = client.post(
        f"{BASE_URL}/questions/{q_id}/access-grant",
        json={"operation": "REVIEW"},
        headers=headers,
    )
    assert res_review.status_code == 200

    # REVIEWER cannot request APPROVE or REJECT
    res_approve = client.post(
        f"{BASE_URL}/questions/{q_id}/access-grant",
        json={"operation": "APPROVE"},
        headers=headers,
    )
    assert res_approve.status_code == 403


# ── TEST 10: REVOKED ASSIGNMENT INVALIDATES GRANTS ───────────────────────────

def test_revoked_assignment_invalidates_grants(
    client, admin_token, setter_token, reviewer_1_token, reviewer_2_token, user_ids, exam_id
):
    """When an assignment is revoked via reassignment, existing grants are rejected."""
    q_id, assignment_id = create_and_assign_question(
        client, admin_token, setter_token, user_ids["reviewer_1"], exam_id
    )

    headers_rev1 = {"Authorization": f"Bearer {reviewer_1_token}"}
    grant_res = client.post(
        f"{BASE_URL}/questions/{q_id}/access-grant",
        json={"operation": "VIEW"},
        headers=headers_rev1,
    )
    grant_id = grant_res.json()["grant_id"]

    # Reassign question to reviewer 2 (atomically revoking assignment 1)
    headers_admin = {"Authorization": f"Bearer {admin_token}"}
    reassign_res = client.post(
        f"{BASE_URL}/questions/assignments/{assignment_id}/reassign",
        json={"new_reviewer_id": user_ids["reviewer_2"], "reason": "Workload balancing"},
        headers=headers_admin,
    )
    assert reassign_res.status_code == 200

    # Attempt to access question with old grant_id
    access_res = client.get(
        f"{BASE_URL}/questions/{q_id}?grant_id={grant_id}",
        headers=headers_rev1,
    )
    assert access_res.status_code == 403
    assert "revoked" in access_res.json()["detail"].lower()


# ── TEST 11: ATOMIC REASSIGNMENT CASCADES GRANT REVOCATION ────────────────────

def test_atomic_reassignment_cascades_grant_revocation(
    client, admin_token, setter_token, reviewer_1_token, user_ids, exam_id
):
    """Reassignment cascades grant revocation and marks grant status as REVOKED."""
    q_id, assignment_id = create_and_assign_question(
        client, admin_token, setter_token, user_ids["reviewer_1"], exam_id
    )

    headers_rev1 = {"Authorization": f"Bearer {reviewer_1_token}"}
    grant_res = client.post(
        f"{BASE_URL}/questions/{q_id}/access-grant",
        json={"operation": "VIEW"},
        headers=headers_rev1,
    )
    grant_id = grant_res.json()["grant_id"]

    headers_admin = {"Authorization": f"Bearer {admin_token}"}
    reassign_res = client.post(
        f"{BASE_URL}/questions/assignments/{assignment_id}/reassign",
        json={"new_reviewer_id": user_ids["reviewer_2"], "reason": "Cascading revocation test"},
        headers=headers_admin,
    )
    assert reassign_res.status_code == 200

    # Old reviewer cannot start review with that grant
    start_res = client.post(
        f"{BASE_URL}/questions/assignments/{assignment_id}/start",
        json={"grant_id": grant_id},
        headers=headers_rev1,
    )
    assert start_res.status_code in [400, 403]


# ── TEST 12: DETERMINISTIC LAZY EXPIRATION ────────────────────────────────────

def test_deterministic_lazy_expiration(
    client, admin_token, setter_token, reviewer_1_token, user_ids, exam_id
):
    """Grant with 0 or negative TTL is immediately expired upon authorization attempt."""
    q_id, _ = create_and_assign_question(
        client, admin_token, setter_token, user_ids["reviewer_1"], exam_id
    )

    headers = {"Authorization": f"Bearer {reviewer_1_token}"}
    # Request grant with 0 minutes TTL (or expired immediately)
    grant_res = client.post(
        f"{BASE_URL}/questions/{q_id}/access-grant",
        json={"operation": "VIEW", "expires_in_minutes": 0},
        headers=headers,
    )
    assert grant_res.status_code == 200
    grant_id = grant_res.json()["grant_id"]

    # Authorize attempt must trigger lazy expiration
    detail_res = client.get(
        f"{BASE_URL}/questions/{q_id}?grant_id={grant_id}",
        headers=headers,
    )
    assert detail_res.status_code == 403
    assert "expired" in detail_res.json()["detail"].lower()


# ── TEST 13: COMPLETED ASSIGNMENT INVALIDATES REMAINING GRANTS ────────────────

def test_completed_assignment_invalidates_remaining_grants(
    client, admin_token, setter_token, reviewer_1_token, user_ids, exam_id
):
    """When a review is submitted and assignment reaches COMPLETED, active grants expire."""
    q_id, assignment_id = create_and_assign_question(
        client, admin_token, setter_token, user_ids["reviewer_1"], exam_id
    )

    headers = {"Authorization": f"Bearer {reviewer_1_token}"}
    grant_res = client.post(
        f"{BASE_URL}/questions/{q_id}/access-grant",
        json={"operation": "REVIEW"},
        headers=headers,
    )
    grant_id = grant_res.json()["grant_id"]

    # Start review
    start_res = client.post(
        f"{BASE_URL}/questions/assignments/{assignment_id}/start",
        json={"grant_id": grant_id},
        headers=headers,
    )
    assert start_res.status_code == 200

    # Submit review
    submit_res = client.post(
        f"{BASE_URL}/questions/{q_id}/review",
        json={
            "assignment_id": assignment_id,
            "verdict": "APPROVED",
            "comments": "Syllabus aligned and rigorous",
            "grant_id": grant_id,
        },
        headers=headers,
    )
    assert submit_res.status_code == 200

    # Now attempt to use that grant again
    post_res = client.get(
        f"{BASE_URL}/questions/{q_id}?grant_id={grant_id}",
        headers=headers,
    )
    assert post_res.status_code == 403


# ── TEST 14: SESSION BINDING VALIDATION ───────────────────────────────────────

def test_session_binding_validation(
    client, admin_token, setter_token, user_ids, exam_id
):
    """Grant acquired under Session A (jti 1) cannot be used with Session B token (jti 2)."""
    q_id, _ = create_and_assign_question(
        client, admin_token, setter_token, user_ids["reviewer_1"], exam_id
    )

    # Session 1 login
    login_1 = client.post(f"{BASE_URL}/auth/login", json=REVIEWER_1_CREDS)
    token_1 = login_1.json()["access_token"]

    # Acquire grant under Session 1
    grant_res = client.post(
        f"{BASE_URL}/questions/{q_id}/access-grant",
        json={"operation": "VIEW"},
        headers={"Authorization": f"Bearer {token_1}"},
    )
    grant_id = grant_res.json()["grant_id"]

    # Session 2 login (creates new JWT with fresh JTI)
    login_2 = client.post(f"{BASE_URL}/auth/login", json=REVIEWER_1_CREDS)
    token_2 = login_2.json()["access_token"]
    assert token_1 != token_2

    # Attempt to use grant_id with Session 2 token
    res = client.get(
        f"{BASE_URL}/questions/{q_id}?grant_id={grant_id}",
        headers={"Authorization": f"Bearer {token_2}"},
    )
    assert res.status_code == 403
    assert "session" in res.json()["detail"].lower()


# ── TEST 15: IDOR RANDOM/FORGED GRANT ID REJECTED ─────────────────────────────

def test_idor_random_grant_id_rejected(
    client, admin_token, setter_token, reviewer_1_token, user_ids, exam_id
):
    """Submitting a random UUID as grant_id is rejected with 403."""
    q_id, _ = create_and_assign_question(
        client, admin_token, setter_token, user_ids["reviewer_1"], exam_id
    )
    fake_grant_id = "00000000-0000-0000-0000-000000000000"

    headers = {"Authorization": f"Bearer {reviewer_1_token}"}
    res = client.get(
        f"{BASE_URL}/questions/{q_id}?grant_id={fake_grant_id}",
        headers=headers,
    )
    assert res.status_code == 403
    assert "invalid access grant" in res.json()["detail"].lower()


# ── TEST 16: ANSWER KEY ISOLATION PRESERVED ───────────────────────────────────

def test_answer_key_isolation_preserved(
    client, admin_token, setter_token, reviewer_1_token, user_ids, exam_id
):
    """Question detail returned to reviewer with active grant never exposes answer key."""
    q_id, _ = create_and_assign_question(
        client, admin_token, setter_token, user_ids["reviewer_1"], exam_id
    )

    headers = {"Authorization": f"Bearer {reviewer_1_token}"}
    grant_res = client.post(
        f"{BASE_URL}/questions/{q_id}/access-grant",
        json={"operation": "VIEW"},
        headers=headers,
    )
    grant_id = grant_res.json()["grant_id"]

    res = client.get(
        f"{BASE_URL}/questions/{q_id}?grant_id={grant_id}",
        headers=headers,
    )
    assert res.status_code == 200
    data = res.json()
    assert "correct_option" not in data
    assert "answer_key" not in data
    assert "content" in data


# ── TEST 17: AUDIT TRAIL EVENTS LOGGED ────────────────────────────────────────

def test_audit_trail_events_logged(
    client, admin_token, setter_token, reviewer_1_token, user_ids, exam_id
):
    """Ephemeral access grant requests, approvals, and revocations generate audit logs."""
    q_id, _ = create_and_assign_question(
        client, admin_token, setter_token, user_ids["reviewer_1"], exam_id
    )

    headers = {"Authorization": f"Bearer {reviewer_1_token}"}
    grant_res = client.post(
        f"{BASE_URL}/questions/{q_id}/access-grant",
        json={"operation": "VIEW"},
        headers=headers,
    )
    grant_id = grant_res.json()["grant_id"]

    # Verify audit logs
    headers_admin = {"Authorization": f"Bearer {admin_token}"}
    audit_res = client.get(f"{BASE_URL}/audit/logs?limit=50", headers=headers_admin)
    assert audit_res.status_code == 200
    logs = audit_res.json()
    grant_events = [l for l in logs if l.get("metadata", {}).get("grant_id") == grant_id or l.get("event_type") == "ACCESS_GRANTED"]
    assert len(grant_events) > 0


# ── TEST 18: CONCURRENT GRANT CREATION RACE PROTECTION ────────────────────────

def test_concurrent_grant_creation_race_protection(
    client, admin_token, setter_token, reviewer_1_token, user_ids, exam_id
):
    """Concurrent requests for active grant for same assignment/operation succeed safely."""
    q_id, _ = create_and_assign_question(
        client, admin_token, setter_token, user_ids["reviewer_1"], exam_id
    )
    headers = {"Authorization": f"Bearer {reviewer_1_token}"}

    def req_grant():
        return client.post(
            f"{BASE_URL}/questions/{q_id}/access-grant",
            json={"operation": "VIEW"},
            headers=headers,
        )

    with ThreadPoolExecutor(max_workers=5) as pool:
        responses = list(pool.map(lambda _: req_grant(), range(5)))

    # All should return 200 and return the same grant or a valid grant
    for r in responses:
        assert r.status_code == 200
    grant_ids = {r.json()["grant_id"] for r in responses}
    # Should resolve to 1 single active grant
    assert len(grant_ids) == 1


# ── TEST 19: EXPLICIT GRANT REVOCATION ENDPOINT ───────────────────────────────

def test_explicit_grant_revocation_endpoint(
    client, admin_token, setter_token, reviewer_1_token, user_ids, exam_id
):
    """User can explicitly revoke an active access grant via revocation endpoint."""
    q_id, _ = create_and_assign_question(
        client, admin_token, setter_token, user_ids["reviewer_1"], exam_id
    )
    headers = {"Authorization": f"Bearer {reviewer_1_token}"}
    grant_res = client.post(
        f"{BASE_URL}/questions/{q_id}/access-grant",
        json={"operation": "VIEW"},
        headers=headers,
    )
    grant_id = grant_res.json()["grant_id"]

    revoke_res = client.post(
        f"{BASE_URL}/questions/grants/{grant_id}/revoke",
        json={"reason": "Completed early"},
        headers=headers,
    )
    assert revoke_res.status_code == 200
    data = revoke_res.json()
    assert data["status"] == "REVOKED"

    # Subsequent access attempt fails
    access_res = client.get(
        f"{BASE_URL}/questions/{q_id}?grant_id={grant_id}",
        headers=headers,
    )
    assert access_res.status_code == 403


# ── TEST 20: DUPLICATE ACTIVE GRANT RETURNS EXISTING GRANT ───────────────────

def test_duplicate_active_grant_returns_existing_grant(
    client, admin_token, setter_token, reviewer_1_token, user_ids, exam_id
):
    """Requesting an active grant when one already exists returns the existing grant."""
    q_id, _ = create_and_assign_question(
        client, admin_token, setter_token, user_ids["reviewer_1"], exam_id
    )
    headers = {"Authorization": f"Bearer {reviewer_1_token}"}

    res_1 = client.post(
        f"{BASE_URL}/questions/{q_id}/access-grant",
        json={"operation": "VIEW"},
        headers=headers,
    )
    grant_id_1 = res_1.json()["grant_id"]

    res_2 = client.post(
        f"{BASE_URL}/questions/{q_id}/access-grant",
        json={"operation": "VIEW"},
        headers=headers,
    )
    grant_id_2 = res_2.json()["grant_id"]

    assert grant_id_1 == grant_id_2
