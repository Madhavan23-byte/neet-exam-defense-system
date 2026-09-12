"""
B-SEA — Security Service
Rule-based anomaly detection and risk scoring.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.models import AuditLog, AuditResult, SecurityEvent, Incident, IncidentSeverity

settings = get_settings()


SEVERITY_SCORES = {
    "LOW": 0.2,
    "MEDIUM": 0.5,
    "HIGH": 0.75,
    "CRITICAL": 1.0,
}


class SecurityService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def evaluate_risk(self, actor_id: str, event_type: str, metadata: dict = None) -> float:
        """Compute risk score for an actor based on recent events."""
        window = datetime.now(timezone.utc) - timedelta(minutes=10)

        result = await self.db.execute(
            select(AuditLog).where(
                AuditLog.actor_id == actor_id,
                AuditLog.timestamp >= window,
            )
        )
        recent_events = result.scalars().all()

        score = 0.0

        # Rule: Brute force
        failed_logins = sum(1 for e in recent_events if e.event_type == "LOGIN_FAILURE")
        if failed_logins >= settings.anomaly_brute_force_threshold:
            score += 0.5
            await self.create_security_event(
                event_type="BRUTE_FORCE_DETECTED",
                severity="HIGH",
                actor_id=actor_id,
                details={"failed_logins": failed_logins, "window_minutes": 10},
                risk_score=0.75,
            )

        # Rule: MFA failures
        mfa_failures = sum(1 for e in recent_events if e.event_type == "MFA_FAILURE")
        if mfa_failures >= settings.anomaly_failed_mfa_threshold:
            score += 0.4
            await self.create_security_event(
                event_type="MFA_SWEEP_DETECTED",
                severity="HIGH",
                actor_id=actor_id,
                details={"mfa_failures": mfa_failures},
                risk_score=0.7,
            )

        # Rule: Bulk question access
        q_accesses = sum(1 for e in recent_events if e.event_type == "QUESTION_DECRYPTED")
        if q_accesses >= settings.anomaly_bulk_question_threshold:
            score += 0.8
            await self.create_security_event(
                event_type="BULK_QUESTION_ACCESS",
                severity="CRITICAL",
                actor_id=actor_id,
                details={"question_accesses": q_accesses, "window_minutes": 10},
                risk_score=0.9,
            )

        # Rule: Early release attempt (check metadata)
        release_attempts = sum(1 for e in recent_events if "RELEASE_ATTEMPT" in e.event_type)
        if release_attempts > 0:
            score += 0.6

        return min(score, 1.0)

    async def create_security_event(
        self,
        event_type: str,
        severity: str,
        actor_id: Optional[str] = None,
        session_id: Optional[str] = None,
        exam_id: Optional[str] = None,
        details: Optional[dict] = None,
        risk_score: float = 0.5,
    ) -> SecurityEvent:
        """Record a security event."""
        event = SecurityEvent(
            event_type=event_type,
            severity=severity,
            actor_id=actor_id,
            session_id=session_id,
            exam_id=exam_id,
            details=details or {},
            risk_score=risk_score,
            resolved=False,
        )
        self.db.add(event)
        await self.db.flush()
        return event

    async def get_dashboard_stats(self) -> dict:
        """Get security dashboard statistics."""
        now = datetime.now(timezone.utc)
        last_24h = now - timedelta(hours=24)

        # Event counts
        total_events = await self.db.execute(
            select(func.count(SecurityEvent.id))
        )
        high_critical = await self.db.execute(
            select(func.count(SecurityEvent.id)).where(
                SecurityEvent.severity.in_(["HIGH", "CRITICAL"]),
                SecurityEvent.resolved == False,
            )
        )
        recent_events = await self.db.execute(
            select(func.count(SecurityEvent.id)).where(
                SecurityEvent.created_at >= last_24h,
            )
        )
        open_incidents = await self.db.execute(
            select(func.count(Incident.id)).where(
                Incident.status.in_(["OPEN", "INVESTIGATING"])
            )
        )

        # Recent security events
        events_result = await self.db.execute(
            select(SecurityEvent)
            .order_by(SecurityEvent.created_at.desc())
            .limit(20)
        )
        recent = events_result.scalars().all()

        return {
            "total_security_events": total_events.scalar() or 0,
            "unresolved_high_critical": high_critical.scalar() or 0,
            "events_last_24h": recent_events.scalar() or 0,
            "open_incidents": open_incidents.scalar() or 0,
            "recent_events": [
                {
                    "id": e.id,
                    "event_type": e.event_type,
                    "severity": e.severity,
                    "actor_id": e.actor_id,
                    "risk_score": e.risk_score,
                    "created_at": e.created_at.isoformat(),
                    "resolved": e.resolved,
                }
                for e in recent
            ],
        }
