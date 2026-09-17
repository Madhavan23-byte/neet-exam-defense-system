import httpx
import json

BASE_URL = "http://127.0.0.1:8000/api/v1"

def test_security_behaviors():
    client = httpx.Client(base_url=BASE_URL, timeout=10.0)
    print("==================================================")
    print("B-SEA PART 8 — SECURITY BEHAVIOR TEST")
    print("==================================================")
    
    # 1. Candidate attempting admin route / protected API
    # Candidate login first to get candidate token
    cand_resp = client.post("/candidate/auth/login", json={
        "registration_number": "BSEA-2026-DEMO-001",
        "password": "BSeaDemo@2026",
        "exam_id": "2db7915f-4a8b-465a-a107-7af83aa12c94"
    })
    print(f"Candidate Login status: {cand_resp.status_code}")
    # Note: might be 409 if active session already exists
    print(f"Candidate Login response: {cand_resp.text[:150]}")
    
    # Test 1A: Second active session for same candidate
    # Attempting second login while session is ACTIVE
    print("\n--- TEST 1: Second active session for same candidate ---")
    cand_resp2 = client.post("/candidate/auth/login", json={
        "registration_number": "BSEA-2026-DEMO-001",
        "password": "BSeaDemo@2026",
        "exam_id": "2db7915f-4a8b-465a-a107-7af83aa12c94"
    })
    print(f"Second login HTTP Status: {cand_resp2.status_code}")
    print(f"Second login Body: {cand_resp2.text}")
    
    # Test 2: Unauthenticated / Invalid token accessing protected admin route
    print("\n--- TEST 2: Protected Admin Route Access (No Auth / Invalid Token) ---")
    resp_noauth = client.get("/exams/")
    print(f"Unauthenticated /exams/ HTTP Status: {resp_noauth.status_code}")
    print(f"Response: {resp_noauth.text}")
    
    resp_badtoken = client.get("/exams/", headers={"Authorization": "Bearer invalid.jwt.token"})
    print(f"Invalid Bearer Token /exams/ HTTP Status: {resp_badtoken.status_code}")
    print(f"Response: {resp_badtoken.text}")

    # Test 3: Candidate session token attempting admin route
    print("\n--- TEST 3: Candidate session token attempting admin route ---")
    resp_cand_admin = client.get("/exams/", headers={"Authorization": "Bearer candidate-session-token"})
    print(f"Candidate token on /exams/ HTTP Status: {resp_cand_admin.status_code}")
    print(f"Response: {resp_cand_admin.text}")

    # Test 4: Candidate attempting answer-key access
    print("\n--- TEST 4: Candidate attempting answer-key access ---")
    # Let's test questions endpoint / questions/keys or similar
    resp_keys_noauth = client.get("/questions/keys")
    print(f"No auth /questions/keys HTTP Status: {resp_keys_noauth.status_code}")
    print(f"Response: {resp_keys_noauth.text[:120]}")
    
    # Check if there is an answer key endpoint or question setter endpoint
    resp_q = client.get("/questions/")
    print(f"No auth /questions/ HTTP Status: {resp_q.status_code}")
    print(f"Response: {resp_q.text[:120]}")

    # Test 5: Expired/invalid candidate session token
    print("\n--- TEST 5: Expired/invalid candidate session token ---")
    resp_bad_session = client.get("/candidate/session/question/0?session_token=completely-invalid-session-token-12345")
    print(f"Invalid session token question fetch HTTP Status: {resp_bad_session.status_code}")
    print(f"Response: {resp_bad_session.text}")
    
    resp_bad_save = client.post("/candidate/session/response", json={
        "session_token": "fake-token-xyz",
        "question_id": "00000000-0000-0000-0000-000000000000",
        "selected_option": 1,
        "is_marked_review": False
    })
    print(f"Invalid session token response save HTTP Status: {resp_bad_save.status_code}")
    print(f"Response: {resp_bad_save.text}")

    # Test 6: Role-Based Access Control (Admin credentials vs Question Setter / Reviewer / Release Authority)
    print("\n--- TEST 6: RBAC Role Separation ---")
    # Login as admin
    admin_login = client.post("/auth/login", json={"username": "admin", "password": "BSeaDemo@2026"})
    print(f"Admin login status: {admin_login.status_code}")
    if admin_login.status_code == 200:
        admin_token = admin_login.json()["access_token"]
        headers_admin = {"Authorization": f"Bearer {admin_token}"}
        
        # Admin attempting setter-only endpoint (create question or submit question)
        resp_admin_create_q = client.post("/questions/", json={
            "exam_id": "2db7915f-4a8b-465a-a107-7af83aa12c94",
            "subject": "PHYSICS",
            "content": {"text": "Test question"},
            "options": ["A", "B", "C", "D"],
            "correct_option": 0,
            "marks": 4
        }, headers=headers_admin)
        print(f"Admin attempting question creation HTTP Status: {resp_admin_create_q.status_code}")
        print(f"Response: {resp_admin_create_q.text[:150]}")
        
    # Login as setter
    setter_login = client.post("/auth/login", json={"username": "setter1", "password": "BSeaDemo@2026"})
    print("Setter login response:", setter_login.json())
    if setter_login.status_code == 200 and "access_token" in setter_login.json():
        setter_token = setter_login.json()["access_token"]
        headers_setter = {"Authorization": f"Bearer {setter_token}"}
        
        # Setter attempting exam release approval (authority-only endpoint)
        resp_setter_release = client.post("/release/approve", json={
            "exam_id": "2db7915f-4a8b-465a-a107-7af83aa12c94"
        }, headers=headers_setter)
        print(f"Setter attempting release approval HTTP Status: {resp_setter_release.status_code}")
        print(f"Response: {resp_setter_release.text[:150]}")

if __name__ == "__main__":
    test_security_behaviors()
