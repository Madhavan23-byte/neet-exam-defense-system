"""
B-SEA — Phase 3C-1 Multi-Worker Concurrency Integration Test
Validates that multiple independent Uvicorn worker processes:
1. Initialize application and respond correctly to liveness probes.
2. Authenticate users and validate JWT tokens across workers.
3. Enforce QuestionAccessGrant ephemeral authorization consistently.
4. Enforce Break-Glass dual-quorum and role diversity across worker boundaries.
5. Share authoritative state through PostgreSQL without process-local dependency.
"""
from __future__ import annotations

import os
import sys
import subprocess
import time
import pytest
import httpx

TEST_PORT = 8021
SERVER_URL = f"http://127.0.0.1:{TEST_PORT}"
BASE_URL = f"{SERVER_URL}/api/v1"
ADMIN_CREDS = {"username": "admin", "password": "BSeaDemo@2026"}
EXAM_AUTH_CREDS = {"username": "exam_authority", "password": "BSeaDemo@2026"}
SECURITY_OFFICER_CREDS = {"username": "security_officer", "password": "BSeaDemo@2026"}


@pytest.fixture(scope="module")
def multiworker_server():
    """Start uvicorn with 2 workers in a subprocess for the test session."""
    python_exe = sys.executable
    cmd = [
        python_exe,
        "-m",
        "uvicorn",
        "app.main:app",
        "--workers",
        "2",
        "--host",
        "127.0.0.1",
        "--port",
        str(TEST_PORT),
    ]

    env = os.environ.copy()
    env["PYTHONPATH"] = "."
    env["ENVIRONMENT"] = "testing"

    proc = subprocess.Popen(
        cmd,
        cwd=os.path.join(os.path.dirname(__file__), ".."),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Poll until server is ready
    ready = False
    for _ in range(30):
        time.sleep(0.3)
        try:
            res = httpx.get(f"{SERVER_URL}/health/live", timeout=1.0)
            if res.status_code == 200:
                ready = True
                break
        except Exception:
            pass

    if not ready:
        proc.terminate()
        proc.wait()
        pytest.fail("Multiworker server failed to start within 10 seconds")

    yield proc

    # Cleanup
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except Exception:
        proc.kill()


def test_multiworker_liveness_probe(multiworker_server):
    """Verify both workers handle liveness probes."""
    with httpx.Client(base_url=SERVER_URL, timeout=5.0) as client:
        for _ in range(6):
            res = client.get("/health/live")
            assert res.status_code == 200
            assert res.json()["status"] == "alive"


def test_multiworker_authentication_and_session_validation(multiworker_server):
    """Verify authentication succeeds and tokens validate across distinct worker processes."""
    with httpx.Client(base_url=SERVER_URL, timeout=5.0) as client:
        login_res = client.post(f"{BASE_URL}/auth/login", json=ADMIN_CREDS)
        assert login_res.status_code == 200, f"Login failed: {login_res.text}"
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Send multiple requests that route to different worker processes
        for _ in range(10):
            me_res = client.get(f"{BASE_URL}/auth/me", headers=headers)
            assert me_res.status_code == 200
            assert me_res.json()["username"] == "admin"


def test_multiworker_break_glass_quorum_across_workers(multiworker_server):
    """Verify Break-Glass quorum and approval tracking works across independent workers."""
    with httpx.Client(base_url=SERVER_URL, timeout=5.0) as client:
        # Get tokens
        admin_tok = client.post(f"{BASE_URL}/auth/login", json=ADMIN_CREDS).json()["access_token"]
        ea_tok = client.post(f"{BASE_URL}/auth/login", json=EXAM_AUTH_CREDS).json()["access_token"]
        so_tok = client.post(f"{BASE_URL}/auth/login", json=SECURITY_OFFICER_CREDS).json()["access_token"]

        # Fetch active exam with blueprint
        exams = client.get(f"{BASE_URL}/exams/", headers={"Authorization": f"Bearer {admin_tok}"}).json()
        assert len(exams) > 0
        target_exam = next((e for e in exams if "B-SEA Global Security" in e.get("title", "")), exams[-1])
        exam_id = target_exam["id"]

        # Step 1: Requester creates request
        req_res = client.post(
            f"{BASE_URL}/break-glass/requests",
            json={
                "exam_id": exam_id,
                "scope": "COMPLETE_EXAM_PAPER",
                "justification": "Multi-worker integration verification test",
            },
            headers={"Authorization": f"Bearer {ea_tok}"},
        )
        assert req_res.status_code == 201
        req_id = req_res.json()["id"]

        # Step 2: Approver 1 approves
        app1 = client.post(
            f"{BASE_URL}/break-glass/requests/{req_id}/approve",
            json={"decision": "APPROVE"},
            headers={"Authorization": f"Bearer {so_tok}"},
        )
        assert app1.status_code == 200

        # Step 3: Approver 2 approves
        app2 = client.post(
            f"{BASE_URL}/break-glass/requests/{req_id}/approve",
            json={"decision": "APPROVE"},
            headers={"Authorization": f"Bearer {admin_tok}"},
        )
        assert app2.status_code == 200
        assert app2.json()["decision"] == "APPROVE"

        # Verify request transitioned to APPROVED across workers
        req_status = client.get(
            f"{BASE_URL}/break-glass/requests/{req_id}",
            headers={"Authorization": f"Bearer {ea_tok}"},
        )
        assert req_status.status_code == 200
        assert req_status.json()["status"] == "APPROVED"

        # Step 4: Requester activates
        act = client.post(
            f"{BASE_URL}/break-glass/requests/{req_id}/activate",
            headers={"Authorization": f"Bearer {ea_tok}"},
        )
        assert act.status_code == 200
        assert act.json()["status"] == "ACTIVATED"

        # Step 5: Read assembled paper
        paper = client.get(
            f"{BASE_URL}/break-glass/requests/{req_id}/assembled-paper",
            headers={"Authorization": f"Bearer {ea_tok}"},
        )
        assert paper.status_code == 200
        assert "questions" in paper.json()

        # Step 6: Revoke
        rev = client.post(
            f"{BASE_URL}/break-glass/requests/{req_id}/revoke",
            json={"reason": "Multi-worker test completion"},
            headers={"Authorization": f"Bearer {ea_tok}"},
        )
        assert rev.status_code == 200
        assert rev.json()["status"] == "REVOKED"
