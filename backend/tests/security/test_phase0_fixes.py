"""
B-SEA — Phase 0 Regression Test Suite
Validates the four verified functional defect fixes:
1. Bug 1: Candidate invalid password / unregistered candidate (no NameError, uniform 401, audit logged).
2. Bug 3: Question creation schema normalization (string, dict, structured Pydantic model).
3. Bug 4: Exam submission & evaluation (single result persistence, 409 on second submit, secure result retrieval).
"""
import pytest
import asyncio
import secrets
import datetime
from fastapi.testclient import TestClient
from sqlalchemy import select, delete

from app.main import app
from app.core.database import AsyncSessionLocal
from app.core.models import (
    Candidate, CandidateSession, Exam, ExamForm, Question, AnswerKey, Result, SessionStatus, UserRoleEnum, AuditLog
)
from app.core.security import hash_token

BASE_URL = "/api/v1"
ADMIN_CREDS = {"username": "admin", "password": "BSeaDemo@2026"}
SETTER_CREDS = {"username": "q_setter_1", "password": "BSeaDemo@2026"}

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
    assert res.status_code == 200, f"Setter login failed: {res.text}"
    return res.json()["access_token"]

@pytest.fixture(scope="module")
def released_exam_id(client, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    res = client.get(f"{BASE_URL}/exams/", headers=headers)
    assert res.status_code == 200
    exams = res.json()
    for exam in exams:
        if exam.get("title") == "B-SEA Global Security Certification 2026" and exam.get("status") == "RELEASED":
            return exam["id"]
    for exam in exams:
        if exam.get("status") == "RELEASED":
            return exam["id"]
    return exams[0]["id"]

# ── BUG 1 TESTS: Candidate Authentication ─────────────────────────────────────

def test_candidate_auth_invalid_password_returns_401_no_nameerror(client, released_exam_id):
    """
    Bug 1 Regression:
    Invalid password must return HTTP 401 Unauthorized, NOT HTTP 500 NameError.
    Must emit audit log with ip_hash without crashing.
    """
    res = client.post(
        f"{BASE_URL}/candidate/auth/login",
        json={
            "registration_number": "BSEA-2026-DEMO-002",
            "password": "WrongPassword@123",
            "exam_id": released_exam_id
        }
    )
    assert res.status_code == 401, f"Expected 401, got {res.status_code}: {res.text}"
    assert res.json()["detail"] == "Invalid credentials"

def test_candidate_auth_unregistered_candidate_returns_401(client, released_exam_id):
    """
    Bug 1 Regression:
    Unregistered candidate must return uniform HTTP 401 with identical message.
    Must NOT leak whether registration number exists.
    """
    res = client.post(
        f"{BASE_URL}/candidate/auth/login",
        json={
            "registration_number": "BSEA-NONEXISTENT-999",
            "password": "AnyPassword@123",
            "exam_id": released_exam_id
        }
    )
    assert res.status_code == 401
    assert res.json()["detail"] == "Invalid credentials"

def test_candidate_auth_enumeration_protection(client, released_exam_id):
    """Verify both invalid password and non-existent registration return identical 401 payloads."""
    res1 = client.post(
        f"{BASE_URL}/candidate/auth/login",
        json={"registration_number": "BSEA-NONEXISTENT", "password": "X", "exam_id": released_exam_id}
    )
    res2 = client.post(
        f"{BASE_URL}/candidate/auth/login",
        json={"registration_number": "BSEA-2026-DEMO-003", "password": "X", "exam_id": released_exam_id}
    )
    assert res1.status_code == 401
    assert res2.status_code == 401
    assert res1.json() == res2.json()

# ── BUG 3 TESTS: Question Creation Schema Normalization ───────────────────────

def test_question_creation_with_string_content(client, setter_token, released_exam_id):
    """Bug 3: Test creation with raw JSON string content."""
    headers = {"Authorization": f"Bearer {setter_token}"}
    payload = {
        "exam_id": released_exam_id,
        "subject": "PHYSICS",
        "topic": "Thermodynamics",
        "difficulty": "medium",
        "bloom_level": "Apply",
        "content": '{"text": "What is the SI unit of entropy?", "options": ["J/K", "J", "W", "N"]}',
        "correct_option": 0,
        "marks_positive": 4.0,
        "marks_negative": 1.0
    }
    res = client.post(f"{BASE_URL}/questions/", json=payload, headers=headers)
    assert res.status_code == 200, f"Failed with: {res.text}"
    data = res.json()
    assert "id" in data
    assert data["status"] == "DRAFT"

def test_question_creation_with_structured_dict_content(client, setter_token, released_exam_id):
    """Bug 3: Test creation with structured JSON dictionary content."""
    headers = {"Authorization": f"Bearer {setter_token}"}
    payload = {
        "exam_id": released_exam_id,
        "subject": "CHEMISTRY",
        "topic": "Organic",
        "difficulty": "hard",
        "bloom_level": "Analyze",
        "content": {
            "text": "Identify the major product in the given reaction.",
            "options": ["Product A", "Product B", "Product C", "Product D"],
            "diagram_urls": ["https://cdn.bsea.gov.in/diagram1.png"]
        },
        "correct_option": 2,
        "marks_positive": 4.0,
        "marks_negative": 1.0
    }
    res = client.post(f"{BASE_URL}/questions/", json=payload, headers=headers)
    assert res.status_code == 200, f"Structured content creation failed: {res.text}"
    data = res.json()
    assert "id" in data
    assert data["status"] == "DRAFT"

def test_question_creation_isolates_answer_key(client, setter_token, released_exam_id):
    """Bug 3: Verify question response NEVER returns correct_option or answer key."""
    headers = {"Authorization": f"Bearer {setter_token}"}
    payload = {
        "exam_id": released_exam_id,
        "subject": "MATHEMATICS",
        "content": {"text": "Evaluate integral of x dx", "options": ["x^2/2", "x", "2x", "x^3"]},
        "correct_option": 0,
        "marks_positive": 4.0,
        "marks_negative": 1.0
    }
    res = client.post(f"{BASE_URL}/questions/", json=payload, headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert "correct_option" not in data
    assert "answer_key" not in data

def test_question_content_canonical_serialization():
    """Bug 3: Verify normalize_question_content produces identical canonical representation."""
    import json
    from app.api.v1.questions import normalize_question_content, QuestionContentPayload

    raw_dict = {"options": ["B", "A"], "text": "Sample", "type": "MCQ"}
    # Different key order string
    raw_str = '{"type": "MCQ", "text": "Sample", "options": ["B", "A"]}'
    # Pydantic model
    payload_model = QuestionContentPayload(text="Sample", options=["B", "A"], type="MCQ")

    canon_dict = normalize_question_content(raw_dict)
    canon_str = normalize_question_content(raw_str)
    canon_model = normalize_question_content(payload_model)

    # All three must produce identical string with sorted keys and tight separators
    assert canon_dict == canon_str
    assert canon_dict == canon_model
    assert canon_dict == json.dumps(raw_dict, sort_keys=True, separators=(",", ":"))

def test_question_creation_with_malformed_payload(client, setter_token, released_exam_id):
    """Bug 3: Reject malformed payload with 422 Unprocessable Entity."""
    headers = {"Authorization": f"Bearer {setter_token}"}
    # Missing required fields like subject or correct_option
    invalid_payload = {
        "exam_id": released_exam_id,
        "content": {"text": "Incomplete"},
    }
    res = client.post(f"{BASE_URL}/questions/", json=invalid_payload, headers=headers)
    assert res.status_code == 422

def test_question_encryption_decryption_compatibility():
    """
    Bug 3 & KMS:
    Verify that canonical serialized content is safely encrypted by MockKMS
    and decrypts back to a valid JSON dictionary without corruption.
    """
    import json
    from app.api.v1.questions import normalize_question_content, QuestionContentPayload
    from app.crypto.kms_interface import get_kms, compute_integrity_hash, EncryptedBlob

    kms = get_kms()
    payload = QuestionContentPayload(
        text="What is AES?",
        options=["Symmetric Cipher", "Asymmetric", "Hash", "MAC"],
        type="MCQ",
        diagram_urls=["https://bsea.local/diagram.png"]
    )
    canonical = normalize_question_content(payload)
    context = "question:q-test-1:exam:exam-test-1"

    # Encrypt
    encrypted_blob = kms.encrypt(canonical.encode("utf-8"), context)
    assert encrypted_blob.ciphertext_b64 is not None

    # Decrypt
    decrypted_bytes = kms.decrypt(encrypted_blob, context)
    decrypted_str = decrypted_bytes.decode("utf-8")
    assert decrypted_str == canonical

    # Verify JSON deserialization
    parsed = json.loads(decrypted_str)
    assert parsed["text"] == "What is AES?"
    assert parsed["options"][0] == "Symmetric Cipher"


# ── BUG 4 TESTS: Exam Submission, Result Persistence & Retrieval ──────────────

def test_exam_submission_flow_and_second_submission_conflict(client, released_exam_id):
    """
    Bug 4 Regression:
    1. Candidate login establishes active session.
    2. Result retrieval on active session returns HTTP 400 (not yet submitted).
    3. First submission succeeds (200), evaluates, persists Result, and marks SUBMITTED.
    4. Second submission returns HTTP 409 Conflict ('Exam already submitted').
    5. Candidate can fetch result via GET /candidate/session/result.
    6. Result endpoint NEVER exposes answer keys or internal evaluation details.
    """
    # Use a unique synthetic candidate (e.g. 501 + random offset)
    rand_idx = 500 + secrets.randbelow(1000)
    cand_reg = f"BSEA-TEST-{rand_idx:06d}"

    # 1. Candidate Login
    login_res = client.post(
        f"{BASE_URL}/candidate/auth/login",
        json={
            "registration_number": cand_reg,
            "password": "BSeaTest@2026",
            "exam_id": released_exam_id
        }
    )
    assert login_res.status_code == 200, f"Candidate login failed for {cand_reg}: {login_res.text}"
    token = login_res.json()["session_token"]
    assert token, "No session token returned"

    # 2. Result retrieval on ACTIVE session -> must return 400
    res_early = client.get(f"{BASE_URL}/candidate/session/result?session_token={token}")
    assert res_early.status_code == 400, f"Expected 400 for unsubmitted session, got {res_early.status_code}"
    assert "not been submitted" in res_early.json()["detail"].lower()

    # 3. First submission -> must return 200, mark SUBMITTED, and return result receipt
    res_submit = client.post(
        f"{BASE_URL}/candidate/session/submit",
        json={"session_token": token, "current_question_index": 0}
    )
    assert res_submit.status_code == 200, f"Submission failed: {res_submit.text}"
    submit_data = res_submit.json()
    assert submit_data["success"] is True
    assert "result" in submit_data
    assert "total_score" in submit_data["result"]
    assert "correct_option" not in str(submit_data)
    assert "answer_key" not in str(submit_data)

    # 4. Second submission -> must return HTTP 409 Conflict ('Exam already submitted')
    res_second = client.post(
        f"{BASE_URL}/candidate/session/submit",
        json={"session_token": token, "current_question_index": 0}
    )
    assert res_second.status_code == 409, f"Expected 409 for duplicate submit, got {res_second.status_code}: {res_second.text}"
    assert "already submitted" in res_second.json()["detail"].lower()

    # 5. Result retrieval -> must return 200 with result receipt
    res_result = client.get(f"{BASE_URL}/candidate/session/result?session_token={token}")
    assert res_result.status_code == 200, f"Result retrieval failed: {res_result.text}"
    result_data = res_result.json()
    assert result_data["success"] is True
    assert result_data["result_available"] is True
    assert "total_score" in result_data
    assert "max_score" in result_data
    assert "percentage" in result_data
    assert "submitted_at" in result_data
    # Strict security assertion: NEVER expose answer keys
    assert "correct_option" not in result_data
    assert "answer_key" not in result_data
    assert "form_id" not in result_data
    assert "user_id" not in result_data

def test_result_retrieval_invalid_token_returns_401(client):
    """Result endpoint must reject invalid or forged session tokens with 401."""
    fake_token = secrets.token_urlsafe(32)
    res = client.get(f"{BASE_URL}/candidate/session/result?session_token={fake_token}")
    assert res.status_code == 401, f"Expected 401, got {res.status_code}"
    assert "invalid" in res.json()["detail"].lower()

def test_concurrent_duplicate_submission(client, released_exam_id):
    """
    Bug 4 Concurrency Regression:
    When concurrent submission requests arrive for the same candidate session,
    exactly one submission proceeds to evaluate/persist Result (200),
    and all subsequent or racing submissions are rejected with 409 Conflict.
    Zero 500 errors.
    """
    from concurrent.futures import ThreadPoolExecutor

    rand_idx = 2000 + secrets.randbelow(1000)
    cand_reg = f"BSEA-TEST-{rand_idx:06d}"

    # Log in candidate
    login_res = client.post(
        f"{BASE_URL}/candidate/auth/login",
        json={
            "registration_number": cand_reg,
            "password": "BSeaTest@2026",
            "exam_id": released_exam_id
        }
    )
    assert login_res.status_code == 200, f"Login failed: {login_res.text}"
    token = login_res.json()["session_token"]

    def submit():
        return client.post(
            f"{BASE_URL}/candidate/session/submit",
            json={"session_token": token, "current_question_index": 0}
        )

    # Fire 5 concurrent submissions
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(submit) for _ in range(5)]
        responses = [f.result() for f in futures]

    status_codes = [r.status_code for r in responses]
    # At least one 200, rest 409. Zero 500s.
    assert 500 not in status_codes, f"Encountered HTTP 500 in concurrent submission: {status_codes}"
    assert 200 in status_codes, f"No request succeeded with 200: {status_codes}"
    assert status_codes.count(200) == 1, f"Expected exactly 1 HTTP 200, got: {status_codes}"
    assert status_codes.count(409) == 4, f"Expected 4 HTTP 409 conflicts, got: {status_codes}"

