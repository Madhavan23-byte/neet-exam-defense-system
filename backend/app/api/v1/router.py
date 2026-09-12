"""B-SEA — API v1 Router aggregation"""
from fastapi import APIRouter

from app.api.v1 import auth, users, exams, questions, release, candidates, security, audit, incidents, dashboard

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(users.router, prefix="/users", tags=["Users"])
api_router.include_router(exams.router, prefix="/exams", tags=["Exams"])
api_router.include_router(questions.router, prefix="/questions", tags=["Questions"])
api_router.include_router(release.router, prefix="/release", tags=["Release"])
api_router.include_router(candidates.router, prefix="/candidate", tags=["Candidate CBT"])
api_router.include_router(security.router, prefix="/security", tags=["Security"])
api_router.include_router(audit.router, prefix="/audit", tags=["Audit"])
api_router.include_router(incidents.router, prefix="/incidents", tags=["Incidents"])
api_router.include_router(dashboard.router, prefix="/dashboard", tags=["Dashboard"])
