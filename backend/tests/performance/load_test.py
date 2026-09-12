import asyncio
import time
import argparse
import httpx
from statistics import median
from collections import defaultdict

# DB Setup for synthetic seeding
from app.core.database import AsyncSessionLocal
from app.core.models import User, Candidate, UserRoleEnum, Exam
from app.core.security import hash_password
import pyotp
from sqlalchemy import select

BASE_URL = "http://127.0.0.1:8000/api/v1"

async def seed_candidates(num_candidates: int):
    print(f"Seeding {num_candidates} synthetic candidates...")
    async with AsyncSessionLocal() as db:
        # Get org and exam
        org_result = await db.execute(select(User).where(User.username == "exam_authority"))
        org_id = org_result.scalar_one().org_id
        
        exam_result = await db.execute(select(Exam))
        exam = exam_result.scalars().first()
        if not exam:
            print("No exam found! Please run seed_demo.py first.")
            return None
            
        # Check existing
        existing = await db.execute(select(User).where(User.username.like("perf_cand_%")))
        if len(existing.scalars().all()) >= num_candidates:
            print(f"Already seeded at least {num_candidates} candidates.")
            return exam.id
            
        print("Hashing password once for speed...")
        pwd_hash = await hash_password("PERF_PASS_123!")
        
        batch_size = 500
        for i in range(0, num_candidates, batch_size):
            users = []
            candidates = []
            for j in range(i, min(i + batch_size, num_candidates)):
                idx = j + 1
                user = User(
                    username=f"perf_cand_{idx}",
                    email=f"perf{idx}@bsea.demo",
                    password_hash=pwd_hash,
                    full_name=f"Perf Candidate {idx}",
                    role=UserRoleEnum.CANDIDATE,
                    org_id=org_id,
                    is_active=True,
                    mfa_enabled=False
                )
                db.add(user)
                users.append(user)
            await db.flush()
            
            for j, user in enumerate(users):
                idx = i + j + 1
                candidate = Candidate(
                    org_id=org_id,
                    user_id=user.id,
                    registration_number=f"PERF-{idx:05d}",
                    full_name=f"Perf Candidate {idx}",
                    email_hash="fakehash",
                    identity_verified=True,
                )
                db.add(candidate)
            await db.commit()
            print(f"Seeded {min(i + batch_size, num_candidates)}/{num_candidates}")
    return exam.id

class LoadTester:
    def __init__(self, num_users: int, exam_id: str):
        self.num_users = num_users
        self.exam_id = exam_id
        self.metrics = defaultdict(list)
        self.status_codes = defaultdict(int)
        self.errors = 0
        self.timeouts = 0
        self.start_time = 0

    async def _request(self, client: httpx.AsyncClient, method: str, url: str, name: str, **kwargs):
        start = time.perf_counter()
        try:
            res = await client.request(method, url, **kwargs)
            duration = time.perf_counter() - start
            self.metrics[name].append(duration)
            self.status_codes[res.status_code] += 1
            if res.status_code >= 400 and res.status_code != 429:
                if res.status_code not in [409]: # 409 might be normal if login races, though shouldn't happen here
                    self.errors += 1
            return res
        except httpx.TimeoutException:
            self.timeouts += 1
            self.status_codes["TIMEOUT"] += 1
        except Exception as e:
            print(f"Request error: {e}")
            self.errors += 1
            self.status_codes["ERROR"] += 1
        return None

    async def simulate_user(self, idx: int):
        async with httpx.AsyncClient(timeout=10.0, limits=httpx.Limits(max_connections=5000, max_keepalive_connections=5000)) as client:
            # 1. Login
            res = await self._request(
                client, "POST", f"{BASE_URL}/candidate/auth/login", "login",
                json={
                    "registration_number": f"PERF-{idx:05d}",
                    "password": "PERF_PASS_123!",
                    "exam_id": self.exam_id,
                    "device_fingerprint": f"dev_{idx}"
                }
            )
            if not res or res.status_code != 200:
                return
            
            data = res.json()
            session_token = data.get("session_token")
            
            # 2. Get Question 0
            await self._request(
                client, "GET", f"{BASE_URL}/candidate/session/question/0", "get_question",
                params={"session_token": session_token}
            )
            
            # 3. Autosave response
            await self._request(
                client, "POST", f"{BASE_URL}/candidate/session/response", "autosave",
                json={
                    "session_token": session_token,
                    "question_id": "q1", # fake
                    "selected_option": 2,
                    "time_spent_seconds": 15
                }
            )
            
            # 4. Security Event
            await self._request(
                client, "POST", f"{BASE_URL}/candidate/session/event", "log_event",
                json={
                    "session_token": session_token,
                    "event_type": "TAB_SWITCH",
                    "details": {"reason": "load test"}
                }
            )

    async def run(self):
        self.start_time = time.perf_counter()
        tasks = [self.simulate_user(i + 1) for i in range(self.num_users)]
        await asyncio.gather(*tasks)
        total_time = time.perf_counter() - self.start_time
        
        self.report(total_time)

    def report(self, total_time: float):
        total_reqs = sum(len(latencies) for latencies in self.metrics.values())
        print("="*60)
        print(f"RESULTS FOR {self.num_users} CONCURRENT USERS")
        print("="*60)
        print(f"Total Time: {total_time:.2f}s")
        print(f"Total Requests: {total_reqs}")
        print(f"RPS: {total_reqs / total_time:.2f}")
        print(f"Timeouts: {self.timeouts}")
        print(f"Errors (non-429): {self.errors}")
        print(f"Status Codes: {dict(self.status_codes)}")
        
        print("\n--- Latencies (ms) ---")
        for name, latencies in self.metrics.items():
            if not latencies: continue
            latencies.sort()
            p50 = latencies[len(latencies)//2] * 1000
            p95 = latencies[int(len(latencies)*0.95)] * 1000
            p99 = latencies[int(len(latencies)*0.99)] * 1000
            avg = (sum(latencies) / len(latencies)) * 1000
            print(f"{name:15}: Avg: {avg:6.1f}ms | P50: {p50:6.1f}ms | P95: {p95:6.1f}ms | P99: {p99:6.1f}ms")


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--users", type=int, default=100)
    args = parser.parse_args()
    
    exam_id = await seed_candidates(args.users)
    if not exam_id:
        return
        
    print(f"\nStarting Load Test with {args.users} users...")
    tester = LoadTester(args.users, exam_id)
    await tester.run()

if __name__ == "__main__":
    asyncio.run(main())
