import asyncio
import time
import pytest
from app.core.security import verify_password, hash_password

@pytest.mark.asyncio
async def test_argon2_non_blocking():
    """
    Proves that verify_password no longer blocks the asyncio event loop.
    We run a CPU-heavy verify_password concurrently with a sleep task.
    If it blocks, the sleep task will be delayed significantly.
    """
    password = "SuperSecretPassword123!"
    hashed = await hash_password(password)

    async def sleep_task():
        start = time.perf_counter()
        await asyncio.sleep(0.1)
        end = time.perf_counter()
        return end - start

    async def verify_task():
        start = time.perf_counter()
        await verify_password(password, hashed)
        end = time.perf_counter()
        return end - start

    # Run them concurrently
    sleep_future = asyncio.create_task(sleep_task())
    verify_future = asyncio.create_task(verify_task())

    sleep_duration, verify_duration = await asyncio.gather(sleep_future, verify_future)

    print(f"Verify duration: {verify_duration:.3f}s")
    print(f"Sleep duration: {sleep_duration:.3f}s")

    # The sleep task should not be delayed by the full verification time
    # (Allowing a generous buffer for context switching overhead)
    assert sleep_duration < 0.20, f"Event loop was blocked! Sleep took {sleep_duration:.3f}s"
