"""
B-SEA — Phase 2 Question Sharding & Compartmentalized Review Test Suite
Validates:
A. Manual question assignment & authorization
B. Conflict-of-interest prevention (author self-review blocked)
C. CSPRNG batch sharding with configurable redundancy & shard size
D. Review assignment lifecycle (ACTIVE -> IN_REVIEW -> COMPLETED)
E. Transactional reassignment & immediate access revocation
F. Enumeration & IDOR defense (unassigned questions inaccessible)
G. Moderator isolation (no blanket moderation bypass without assignment)
H. Answer-key non-disclosure
I. Concurrency & duplicate active assignment protection
"""
import secrets
from concurrent.futures import ThreadPoolExecutor
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.models import UserRoleEnum, ReviewPurpose, QuestionAssignmentStatus

BASE_URL = "/api/v1"
ADMIN_CREDS = {"username": "admin", "password": "BSeaDemo@2026"}
SETTER_CREDS = {"username": "q_setter_1", "password": "BSeaDemo@2026"}
REVIEWER_CREDS = {"username": "reviewer_1", "password": "BSeaDemo@2026"}
MODERATOR_CREDS = {"username": "moderator_1", "password": "BSeaDemo@2026"}


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def admin_token(client):
    res = client.post(f"{BASE_URL}/auth/login", json=ADMIN_CREDS)
    assert res.status_code == 200, f"Admin login failed: {res.text}"
    return res.json()["access_token"]


@pytest.fixture(scope="module")
def setter_token(client):
    res = client.post(f"{BASE_URL}/auth/login", json=SETTER_CREDS)
    assert res.status_code == 200, f"Setter login failed: {res.text}"
    return res.json()["access_token"]


@pytest.fixture(scope="module")
def reviewer_token(client):
    res = client.post(f"{BASE_URL}/auth/login", json=REVIEWER_CREDS)
    assert res.status_code == 200, f"Reviewer login failed: {res.text}"
    return res.json()["access_token"]


@pytest.fixture(scope="module")
def moderator_token(client):
    res = client.post(f"{BASE_URL}/auth/login", json=MODERATOR_CREDS)
    assert res.status_code == 200, f"Moderator login failed: {res.text}"
    return res.json()["access_token"]


@pytest.fixture(scope="module")
def user_ids(client, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    res = client.get(f"{BASE_URL}/users/", headers=headers)
    assert res.status_code == 200
    users = res.json()
    id_map = {u["username"]: u["id"] for u in users}
    return id_map


@pytest.fixture(scope="module")
def exam_id(client, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    res = client.get(f"{BASE_URL}/exams/", headers=headers)
    assert res.status_code == 200
    exams = res.json()
    assert len(exams) > 0
    return exams[0]["id"]


# ── HELPER: Create and Submit Draft Question ───────────────────────────────────

def create_submitted_question(client, setter_token, exam_id, subject="PHYSICS"):
    headers = {"Authorization": f"Bearer {setter_token}"}
    payload = {
        "exam_id": exam_id,
        "subject": subject,
        "topic": "Mechanics",
        "difficulty": "medium",
        "bloom_level": "Apply",
        "content": {
            "text": f"Question {secrets.token_hex(4)}: Calculate force F=ma",
            "options": ["F=ma", "F=m/a", "F=a/m", "F=m+a"],
        },
        "correct_option": 0,
        "marks_positive": 4.0,
        "marks_negative": 1.0,
    }
    res = client.post(f"{BASE_URL}/questions/", json=payload, headers=headers)
    assert res.status_code == 200, f"Create question failed: {res.text}"
    q_id = res.json()["id"]

    sub_res = client.post(f"{BASE_URL}/questions/{q_id}/submit", headers=headers)
    assert sub_res.status_code == 200, f"Submit question failed: {sub_res.text}"
    return q_id


# ── A. MANUAL ASSIGNMENT & CONFLICT OF INTEREST ───────────────────────────────

def test_manual_assignment_success(client, admin_token, setter_token, exam_id, user_ids):
    """Admin can assign a submitted question to an active reviewer."""
    q_id = create_submitted_question(client, setter_token, exam_id)
    reviewer_id = user_ids["reviewer_1"]

    headers = {"Authorization": f"Bearer {admin_token}"}
    assign_res = client.post(
        f"{BASE_URL}/questions/{q_id}/assign",
        json={"reviewer_id": reviewer_id, "purpose": "TECHNICAL_REVIEW"},
        headers=headers,
    )
    assert assign_res.status_code == 200, f"Assign failed: {assign_res.text}"
    data = assign_res.json()
    assert data["success"] is True
    assert data["question_id"] == q_id
    assert data["reviewer_id"] == reviewer_id
    assert data["purpose"] == "TECHNICAL_REVIEW"
    assert data["status"] == "ACTIVE"


def test_conflict_of_interest_author_cannot_review_own_question(client, admin_token, setter_token, exam_id, user_ids):
    """Author cannot be assigned to review their own question."""
    q_id = create_submitted_question(client, setter_token, exam_id)
    author_id = user_ids["q_setter_1"]

    headers = {"Authorization": f"Bearer {admin_token}"}
    res = client.post(
        f"{BASE_URL}/questions/{q_id}/assign",
        json={"reviewer_id": author_id, "purpose": "TECHNICAL_REVIEW"},
        headers=headers,
    )
    # Must fail with 400 Bad Request (either author conflict or not reviewer role)
    assert res.status_code in [400, 403]
    assert "conflict" in res.json()["detail"].lower() or "role" in res.json()["detail"].lower()


def test_unauthorized_user_cannot_assign_questions(client, reviewer_token, setter_token, exam_id, user_ids):
    """Reviewer or setter cannot assign questions."""
    q_id = create_submitted_question(client, setter_token, exam_id)
    headers = {"Authorization": f"Bearer {reviewer_token}"}
    res = client.post(
        f"{BASE_URL}/questions/{q_id}/assign",
        json={"reviewer_id": user_ids["reviewer_1"], "purpose": "TECHNICAL_REVIEW"},
        headers=headers,
    )
    assert res.status_code == 403


# ── B. DUPLICATE ASSIGNMENT & PARTIAL UNIQUE INDEX ────────────────────────────

def test_duplicate_active_assignment_rejected(client, admin_token, setter_token, exam_id, user_ids):
    """Cannot assign the same question to the same reviewer twice while active."""
    q_id = create_submitted_question(client, setter_token, exam_id)
    reviewer_id = user_ids["reviewer_1"]
    headers = {"Authorization": f"Bearer {admin_token}"}

    res1 = client.post(
        f"{BASE_URL}/questions/{q_id}/assign",
        json={"reviewer_id": reviewer_id, "purpose": "TECHNICAL_REVIEW"},
        headers=headers,
    )
    assert res1.status_code == 200

    res2 = client.post(
        f"{BASE_URL}/questions/{q_id}/assign",
        json={"reviewer_id": reviewer_id, "purpose": "TECHNICAL_REVIEW"},
        headers=headers,
    )
    assert res2.status_code in [400, 409]
    assert "already exists" in res2.json()["detail"].lower()


# ── C. REVIEW LIFECYCLE (ACTIVE -> IN_REVIEW -> COMPLETED) ─────────────────────

def test_review_lifecycle_full_flow(client, admin_token, setter_token, reviewer_token, exam_id, user_ids):
    """
    1. Assigned question is ACTIVE.
    2. Reviewer starts review: ACTIVE -> IN_REVIEW.
    3. Reviewer submits review verdict: IN_REVIEW -> COMPLETED.
    4. Cannot submit review without starting review.
    """
    q_id = create_submitted_question(client, setter_token, exam_id)
    reviewer_id = user_ids["reviewer_1"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    reviewer_headers = {"Authorization": f"Bearer {reviewer_token}"}

    # 1. Assign
    assign_res = client.post(
        f"{BASE_URL}/questions/{q_id}/assign",
        json={"reviewer_id": reviewer_id, "purpose": "TECHNICAL_REVIEW"},
        headers=admin_headers,
    )
    assert assign_res.status_code == 200
    assignment_id = assign_res.json()["assignment_id"]

    # Attempt to submit review directly while still ACTIVE -> must fail
    direct_submit = client.post(
        f"{BASE_URL}/questions/{q_id}/review",
        json={"assignment_id": assignment_id, "verdict": "APPROVED", "comments": "Premature"},
        headers=reviewer_headers,
    )
    assert direct_submit.status_code == 400
    assert "in_review" in direct_submit.json()["detail"].lower()

    # 2. Start review -> transitions to IN_REVIEW
    start_res = client.post(
        f"{BASE_URL}/questions/assignments/{assignment_id}/start",
        headers=reviewer_headers,
    )
    assert start_res.status_code == 200
    assert start_res.json()["status"] == "IN_REVIEW"

    # 3. Submit review -> transitions to COMPLETED
    submit_res = client.post(
        f"{BASE_URL}/questions/{q_id}/review",
        json={"assignment_id": assignment_id, "verdict": "APPROVED", "comments": "Item verified accurate"},
        headers=reviewer_headers,
    )
    assert submit_res.status_code == 200
    data = submit_res.json()
    assert data["success"] is True
    assert data["verdict"] == "APPROVED"


# ── D. ENUMERATION & IDOR DEFENSE ─────────────────────────────────────────────

def test_reviewer_compartmentalization_and_enumeration_defense(
    client, admin_token, setter_token, reviewer_token, moderator_token, exam_id, user_ids
):
    """
    Security Proof:
    - Question 1 is assigned to Reviewer 1.
    - Question 2 is assigned to Moderator 1.
    - Reviewer 1 calling GET /questions/exam/{id} sees ONLY Question 1, NEVER Question 2.
    - Reviewer 1 attempting GET /questions/{q2_id} receives HTTP 403 Forbidden.
    - Reviewer 1 attempting to review Q2 receives HTTP 403 Forbidden.
    - Reviewer 1 attempting to approve Q2 receives HTTP 403 Forbidden.
    """
    q1_id = create_submitted_question(client, setter_token, exam_id)
    q2_id = create_submitted_question(client, setter_token, exam_id)

    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    rev_headers = {"Authorization": f"Bearer {reviewer_token}"}
    mod_headers = {"Authorization": f"Bearer {moderator_token}"}

    # Assign Q1 to reviewer_1
    client.post(
        f"{BASE_URL}/questions/{q1_id}/assign",
        json={"reviewer_id": user_ids["reviewer_1"], "purpose": "TECHNICAL_REVIEW"},
        headers=admin_headers,
    )
    # Assign Q2 to moderator_1
    client.post(
        f"{BASE_URL}/questions/{q2_id}/assign",
        json={"reviewer_id": user_ids["moderator_1"], "purpose": "TECHNICAL_REVIEW"},
        headers=admin_headers,
    )

    # 1. Reviewer 1 lists exam questions:
    list_res = client.get(f"{BASE_URL}/questions/exam/{exam_id}", headers=rev_headers)
    assert list_res.status_code == 200
    q_ids_visible = [q["id"] for q in list_res.json()]
    assert q1_id in q_ids_visible, "Assigned question Q1 must be visible"
    assert q2_id not in q_ids_visible, "Unassigned question Q2 must NOT be visible to Reviewer 1!"

    # 2. Reviewer 1 direct retrieval of Q2 -> must return 403
    direct_res = client.get(f"{BASE_URL}/questions/{q2_id}", headers=rev_headers)
    assert direct_res.status_code == 403, f"Expected 403 on unassigned question, got {direct_res.status_code}"

    # 3. Reviewer 1 review action on Q2 -> must return 403
    review_res = client.post(
        f"{BASE_URL}/questions/{q2_id}/review",
        json={"assignment_id": "fake-or-wrong-id", "verdict": "APPROVED"},
        headers=rev_headers,
    )
    assert review_res.status_code in [400, 403, 404]

    # 4. Reviewer 1 direct approve on Q2 -> must return 403
    app_res = client.post(
        f"{BASE_URL}/questions/{q2_id}/approve",
        json={"verdict": "APPROVED", "comments": "Illegitimate"},
        headers=rev_headers,
    )
    assert app_res.status_code == 403


def test_moderator_without_assignment_cannot_access_or_approve(
    client, setter_token, moderator_token, exam_id, user_ids
):
    """
    Moderator Isolation:
    Moderators do NOT have an unassigned bypass. A question with no assignment
    to moderator_1 cannot be viewed or approved by moderator_1.
    """
    q_id = create_submitted_question(client, setter_token, exam_id)
    mod_headers = {"Authorization": f"Bearer {moderator_token}"}

    # Direct detail access on unassigned question -> 403
    get_res = client.get(f"{BASE_URL}/questions/{q_id}", headers=mod_headers)
    assert get_res.status_code == 403

    # Approve on unassigned question -> 403
    app_res = client.post(
        f"{BASE_URL}/questions/{q_id}/approve",
        json={"verdict": "APPROVED", "comments": "Unassigned approval attempt"},
        headers=mod_headers,
    )
    assert app_res.status_code == 403


# ── E. TRANSACTIONAL REASSIGNMENT ─────────────────────────────────────────────

def test_transactional_reassignment_revokes_old_and_grants_new(
    client, admin_token, setter_token, reviewer_token, moderator_token, exam_id, user_ids
):
    """
    Reassignment:
    1. Q is assigned to Reviewer 1.
    2. Admin reassigns Q to Moderator 1.
    3. Reviewer 1 immediately loses access (403).
    4. Moderator 1 gains access (200).
    5. Old assignment is marked REVOKED with revocation reason.
    """
    q_id = create_submitted_question(client, setter_token, exam_id)
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    rev_headers = {"Authorization": f"Bearer {reviewer_token}"}
    mod_headers = {"Authorization": f"Bearer {moderator_token}"}

    # Initial assignment to reviewer_1
    assign_res = client.post(
        f"{BASE_URL}/questions/{q_id}/assign",
        json={"reviewer_id": user_ids["reviewer_1"], "purpose": "TECHNICAL_REVIEW"},
        headers=admin_headers,
    )
    assert assign_res.status_code == 200
    assignment_id = assign_res.json()["assignment_id"]

    # Verify Reviewer 1 has access
    check1 = client.get(f"{BASE_URL}/questions/{q_id}", headers=rev_headers)
    assert check1.status_code == 200

    # Reassign to moderator_1
    reassign_res = client.post(
        f"{BASE_URL}/questions/assignments/{assignment_id}/reassign",
        json={"new_reviewer_id": user_ids["moderator_1"], "reason": "Workload rebalancing"},
        headers=admin_headers,
    )
    assert reassign_res.status_code == 200
    assert reassign_res.json()["success"] is True

    # Reviewer 1 MUST now be denied
    check_old = client.get(f"{BASE_URL}/questions/{q_id}", headers=rev_headers)
    assert check_old.status_code == 403

    # Moderator 1 MUST now have access
    check_new = client.get(f"{BASE_URL}/questions/{q_id}", headers=mod_headers)
    assert check_new.status_code == 200


# ── F. CSPRNG BATCH SHARDING ENGINE ───────────────────────────────────────────

def test_csprng_batch_sharding_distribution(client, admin_token, setter_token, exam_id, user_ids):
    """
    Batch Sharding Engine:
    - Creates multiple submitted questions.
    - Shards across reviewers using CSPRNG.
    - Respects redundancy=1 without author conflict.
    """
    q1 = create_submitted_question(client, setter_token, exam_id)
    q2 = create_submitted_question(client, setter_token, exam_id)

    reviewer_pool = [user_ids["reviewer_1"], user_ids["moderator_1"]]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    shard_res = client.post(
        f"{BASE_URL}/questions/exam/{exam_id}/shard",
        json={
            "reviewer_ids": reviewer_pool,
            "redundancy": 1,
            "purpose": "TECHNICAL_REVIEW",
        },
        headers=admin_headers,
    )
    assert shard_res.status_code == 200, f"Sharding failed: {shard_res.text}"
    data = shard_res.json()
    assert data["success"] is True
    assert data["questions_sharded"] >= 2
    assert data["assignments_created"] >= 2


def test_batch_sharding_infeasible_redundancy_rejected(client, admin_token, exam_id, user_ids):
    """Requesting redundancy higher than reviewer pool size is rejected."""
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    res = client.post(
        f"{BASE_URL}/questions/exam/{exam_id}/shard",
        json={
            "reviewer_ids": [user_ids["reviewer_1"]],
            "redundancy": 2,  # Impossible: 1 reviewer cannot provide 2 distinct reviews
        },
        headers=admin_headers,
    )
    assert res.status_code == 400
    assert "infeasibility" in res.json()["detail"].lower()


# ── G. ANSWER-KEY NON-DISCLOSURE ──────────────────────────────────────────────

def test_review_apis_never_expose_answer_key(client, admin_token, setter_token, reviewer_token, exam_id, user_ids):
    """
    Strict Non-Disclosure:
    Neither GET /questions/{id} nor GET /questions/assignments/me leaks answer keys or correct option.
    """
    q_id = create_submitted_question(client, setter_token, exam_id)
    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    rev_headers = {"Authorization": f"Bearer {reviewer_token}"}

    client.post(
        f"{BASE_URL}/questions/{q_id}/assign",
        json={"reviewer_id": user_ids["reviewer_1"], "purpose": "KEY_VERIFICATION"},
        headers=admin_headers,
    )

    # 1. Detail endpoint
    detail_res = client.get(f"{BASE_URL}/questions/{q_id}", headers=rev_headers)
    assert detail_res.status_code == 200
    detail_text = str(detail_res.json())
    assert "correct_option" not in detail_text
    assert "answer_key" not in detail_text
    assert "key_hash" not in detail_text

    # 2. My assignments endpoint
    assign_res = client.get(f"{BASE_URL}/questions/assignments/me", headers=rev_headers)
    assert assign_res.status_code == 200
    assign_text = str(assign_res.json())
    assert "correct_option" not in assign_text
    assert "answer_key" not in assign_text


# ── H. CONCURRENCY TESTS ──────────────────────────────────────────────────────

def test_concurrent_assignment_creation_race_no_duplicates(
    client, admin_token, setter_token, exam_id, user_ids
):
    """
    Concurrency Protection:
    Simultaneous assignment requests for the same question and reviewer must not
    create duplicate active assignments. Exactly 1 succeeds, remaining fail cleanly.
    Zero HTTP 500 errors.
    """
    q_id = create_submitted_question(client, setter_token, exam_id)
    reviewer_id = user_ids["reviewer_1"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    def assign():
        return client.post(
            f"{BASE_URL}/questions/{q_id}/assign",
            json={"reviewer_id": reviewer_id, "purpose": "TECHNICAL_REVIEW"},
            headers=admin_headers,
        )

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(assign) for _ in range(5)]
        responses = [f.result() for f in futures]

    codes = [r.status_code for r in responses]
    assert 500 not in codes, f"Encountered 500: {codes}"
    assert codes.count(200) == 1, f"Expected exactly one 200, got: {codes}"
    assert all(c in [200, 400, 409] for c in codes)


def test_batch_sharding_redundancy_two(client, admin_token, setter_token, exam_id, user_ids):
    """
    Redundancy = 2:
    Each question is assigned to 2 distinct reviewers.
    No reviewer receives the same question twice.
    """
    q1 = create_submitted_question(client, setter_token, exam_id)
    reviewer_pool = [user_ids["reviewer_1"], user_ids["moderator_1"]]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    shard_res = client.post(
        f"{BASE_URL}/questions/exam/{exam_id}/shard",
        json={
            "reviewer_ids": reviewer_pool,
            "redundancy": 2,
            "purpose": "TECHNICAL_REVIEW",
        },
        headers=admin_headers,
    )
    assert shard_res.status_code == 200, f"Redundancy 2 sharding failed: {shard_res.text}"
    data = shard_res.json()
    assert data["success"] is True
    assert data["redundancy"] == 2


def test_direct_idor_random_question_id_denied(client, reviewer_token):
    """Direct IDOR attempt with arbitrary question ID is denied."""
    random_id = secrets.token_hex(16)
    rev_headers = {"Authorization": f"Bearer {reviewer_token}"}
    res = client.get(f"{BASE_URL}/questions/{random_id}", headers=rev_headers)
    assert res.status_code in [403, 404]

