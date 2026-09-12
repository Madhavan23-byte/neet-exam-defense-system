"""B-SEA — Evaluation Service
Protected evaluation — answer keys NEVER exposed to candidate API.
"""
from __future__ import annotations
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.models import AnswerKey, CandidateSession, Response, Result, SessionStatus


class EvaluationService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def evaluate_session(self, session_id: str) -> dict:
        """
        Evaluate a submitted exam session.
        This service has exclusive access to answer keys.
        No candidate-facing API routes access this service.
        """
        sess_result = await self.db.execute(
            select(CandidateSession).where(CandidateSession.id == session_id)
        )
        session = sess_result.scalar_one_or_none()
        if not session:
            return {"error": "Session not found"}

        # Get all responses
        resp_result = await self.db.execute(
            select(Response).where(Response.session_id == session_id)
        )
        responses = {r.question_id: r for r in resp_result.scalars().all()}

        # Get answer keys for all questions in form
        form_result = await self.db.execute(
            select(__import__('app.core.models', fromlist=['ExamForm']).ExamForm)
            .where(__import__('app.core.models', fromlist=['ExamForm']).ExamForm.id == session.form_id)
        )
        form = form_result.scalar_one_or_none()
        if not form:
            return {"error": "Form not found"}

        question_ids = form.question_ids
        keys_result = await self.db.execute(
            select(AnswerKey).where(AnswerKey.question_id.in_(question_ids))
        )
        answer_keys = {k.question_id: k for k in keys_result.scalars().all()}

        total_score = 0.0
        max_score = 0.0
        correct = 0
        incorrect = 0
        skipped = 0

        for qid in question_ids:
            key = answer_keys.get(qid)
            if not key:
                continue

            max_score += key.marks_positive
            response = responses.get(qid)

            if not response or response.selected_option is None:
                skipped += 1
            elif response.selected_option == key.correct_option:
                total_score += key.marks_positive
                correct += 1
            else:
                total_score -= key.marks_negative
                incorrect += 1

        # Create result record
        result = Result(
            session_id=session_id,
            candidate_id=session.candidate_id,
            exam_id=session.exam_id,
            total_score=max(0, total_score),
            max_score=max_score,
            attempted=correct + incorrect,
            correct=correct,
            incorrect=incorrect,
            skipped=skipped,
        )
        self.db.add(result)
        await self.db.flush()

        return {
            "total_score": max(0, total_score),
            "max_score": max_score,
            "correct": correct,
            "incorrect": incorrect,
            "skipped": skipped,
            "percentage": round((max(0, total_score) / max_score * 100) if max_score > 0 else 0, 2),
        }
