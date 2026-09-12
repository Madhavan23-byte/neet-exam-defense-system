"""
B-SEA — Demo Data Seeder
Creates demo users, organization, exam, questions, and candidates.
ALL DEMO PASSWORDS ARE PUBLICLY KNOWN — FOR DEMONSTRATION ONLY.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import AsyncSessionLocal
from app.core.models import (
    Candidate, Exam, ExamBlueprint, ExamStatus, Organization, Question,
    QuestionStatus, SecurityMode, User, UserRoleEnum, AnswerKey
)
from app.core.security import hash_password
from app.crypto.kms_interface import compute_integrity_hash, get_kms


DEMO_QUESTIONS = [
    {
        "subject": "Physics",
        "topic": "Mechanics",
        "difficulty": "medium",
        "content": json.dumps({
            "text": "A body of mass 5 kg is moving with a velocity of 10 m/s. What is its kinetic energy?",
            "options": ["200 J", "250 J", "300 J", "500 J"],
            "type": "MCQ"
        }),
        "correct_option": 1,  # 250 J
    },
    {
        "subject": "Physics",
        "topic": "Optics",
        "difficulty": "easy",
        "content": json.dumps({
            "text": "The speed of light in vacuum is approximately:",
            "options": ["3×10⁸ m/s", "3×10⁶ m/s", "3×10¹⁰ m/s", "3×10⁴ m/s"],
            "type": "MCQ"
        }),
        "correct_option": 0,
    },
    {
        "subject": "Chemistry",
        "topic": "Periodic Table",
        "difficulty": "easy",
        "content": json.dumps({
            "text": "The atomic number of Carbon is:",
            "options": ["4", "6", "8", "12"],
            "type": "MCQ"
        }),
        "correct_option": 1,
    },
    {
        "subject": "Chemistry",
        "topic": "Chemical Bonding",
        "difficulty": "medium",
        "content": json.dumps({
            "text": "Which type of bond is present in NaCl?",
            "options": ["Covalent bond", "Ionic bond", "Metallic bond", "Hydrogen bond"],
            "type": "MCQ"
        }),
        "correct_option": 1,
    },
    {
        "subject": "Mathematics",
        "topic": "Calculus",
        "difficulty": "hard",
        "content": json.dumps({
            "text": "What is the derivative of sin(x)?",
            "options": ["-cos(x)", "cos(x)", "-sin(x)", "tan(x)"],
            "type": "MCQ"
        }),
        "correct_option": 1,
    },
    {
        "subject": "Mathematics",
        "topic": "Algebra",
        "difficulty": "medium",
        "content": json.dumps({
            "text": "If x² - 5x + 6 = 0, what are the values of x?",
            "options": ["x=2, x=3", "x=1, x=6", "x=-2, x=-3", "x=2, x=-3"],
            "type": "MCQ"
        }),
        "correct_option": 0,
    },
    {
        "subject": "Biology",
        "topic": "Cell Biology",
        "difficulty": "easy",
        "content": json.dumps({
            "text": "The powerhouse of the cell is:",
            "options": ["Nucleus", "Ribosome", "Mitochondria", "Endoplasmic Reticulum"],
            "type": "MCQ"
        }),
        "correct_option": 2,
    },
    {
        "subject": "Biology",
        "topic": "Genetics",
        "difficulty": "medium",
        "content": json.dumps({
            "text": "DNA replication is:",
            "options": ["Conservative", "Semi-conservative", "Dispersive", "Non-conservative"],
            "type": "MCQ"
        }),
        "correct_option": 1,
    },
]


async def seed_demo_data():
    """Seed demonstration data."""
    # Ensure tables exist first
    from app.core.database import engine, Base
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with AsyncSessionLocal() as db:
        # Check if already seeded
        existing_org = await db.execute(
            select(Organization).where(Organization.short_name == "BSEA-DEMO")
        )
        if existing_org.scalar_one_or_none():
            return  # Already seeded

        # Create demo organization
        org = Organization(
            name="B-SEA Global Examination Authority",
            short_name="BSEA-DEMO",
            org_type="National Testing Authority",
            country="Global",
            timezone="UTC",
        )
        db.add(org)
        await db.flush()

        # Create demo users
        users_config = [
            ("admin", "admin@bsea.demo", "BSEA Administrator", "SUPER_ADMIN"),
            ("exam_authority", "examauth@bsea.demo", "Exam Authority Officer", "EXAM_AUTHORITY"),
            ("q_setter_1", "setter1@bsea.demo", "Dr. Priya Sharma", "QUESTION_SETTER"),
            ("q_setter_2", "setter2@bsea.demo", "Prof. Arjun Mehta", "QUESTION_SETTER"),
            ("reviewer_1", "reviewer1@bsea.demo", "Dr. Sarah Chen", "REVIEWER"),
            ("moderator_1", "moderator1@bsea.demo", "Prof. James Wright", "MODERATOR"),
            ("security_officer", "security@bsea.demo", "Security Officer Singh", "SECURITY_OFFICER"),
            ("release_auth_1", "release1@bsea.demo", "Release Authority Patel", "RELEASE_AUTHORITY"),
            ("release_auth_2", "release2@bsea.demo", "Release Authority Kumar", "RELEASE_AUTHORITY"),
            ("release_auth_3", "release3@bsea.demo", "Release Authority Nair", "RELEASE_AUTHORITY"),
            ("auditor_1", "auditor@bsea.demo", "Independent Auditor", "AUDITOR"),
            ("candidate_demo", "candidate@bsea.demo", "Demo Candidate", "CANDIDATE"),
        ]

        created_users = {}
        for username, email, full_name, role in users_config:
            user = User(
                org_id=org.id,
                email=email,
                username=username,
                full_name=full_name,
                role=UserRoleEnum(role),
                password_hash=await hash_password("BSeaDemo@2026"),  # Demo password
                is_active=True,
            )
            db.add(user)
            created_users[username] = user

        await db.flush()

        # Create demo exam
        exam = Exam(
            org_id=org.id,
            title="B-SEA Global Security Certification 2026",
            description=(
                "Demonstration examination showcasing B-SEA secure examination architecture. "
                "This exam demonstrates encrypted question bank, threshold authorization, "
                "time-locked release, and secure CBT delivery."
            ),
            exam_type="CBT",
            security_mode=SecurityMode.CRITICAL,
            scheduled_start_utc=datetime.now(timezone.utc) - timedelta(minutes=5),  # Already past for demo
            scheduled_end_utc=datetime.now(timezone.utc) + timedelta(hours=3),
            duration_minutes=180,
            required_approvals=3,
            created_by=created_users["exam_authority"].id,
            status=ExamStatus.RELEASED,  # Demo: pre-released for demonstration
            released_at=datetime.now(timezone.utc) - timedelta(minutes=5),
        )
        db.add(exam)
        await db.flush()

        # Create and encrypt questions
        kms = get_kms()
        setter = created_users["q_setter_1"]
        moderator = created_users["moderator_1"]

        for q_data in DEMO_QUESTIONS:
            question = Question(
                exam_id=exam.id,
                author_id=setter.id,
                subject=q_data["subject"],
                topic=q_data["topic"],
                difficulty=q_data["difficulty"],
                question_format="MCQ",
                marks_positive=4.0,
                marks_negative=1.0,
                status=QuestionStatus.DRAFT,
                version=1,
                plaintext_content=q_data["content"],
                approved_by=moderator.id,
                approved_at=datetime.now(timezone.utc),
            )
            db.add(question)
            await db.flush()

            # Encrypt the question
            context = f"question:{question.id}:exam:{exam.id}"
            content_bytes = q_data["content"].encode("utf-8")
            encrypted_blob = kms.encrypt(content_bytes, context)
            integrity_data = f"{question.id}:{question.version}:{encrypted_blob.ciphertext_b64}"
            integrity_hash = compute_integrity_hash(integrity_data.encode("utf-8"))
            signed = kms.sign(integrity_hash.encode("utf-8"))

            question.encrypted_content = encrypted_blob.ciphertext_b64
            question.key_reference = encrypted_blob.key_reference
            question.content_hash = integrity_hash
            question.digital_signature = signed.signature_b64
            question.status = QuestionStatus.ENCRYPTED
            question.plaintext_content = None  # CLEARED

            # Create answer key
            key_data = f"{question.id}:{q_data['correct_option']}:4.0:1.0"
            answer_key = AnswerKey(
                question_id=question.id,
                correct_option=q_data["correct_option"],
                marks_positive=4.0,
                marks_negative=1.0,
                key_hash=compute_integrity_hash(key_data.encode()),
                created_by=moderator.id,
            )
            db.add(answer_key)
            
            # Keep track of IDs for the form
            if not hasattr(exam, "_seeded_questions"):
                exam._seeded_questions = []
            exam._seeded_questions.append(question.id)

        # Create ExamForm
        from app.core.models import ExamForm, FormStatus
        form_data = b"FORM_A:" + b":".join([q_id.encode() for q_id in exam._seeded_questions])
        form = ExamForm(
            exam_id=exam.id,
            form_label="A",
            question_ids=exam._seeded_questions,
            option_orders={},
            integrity_hash=compute_integrity_hash(form_data),
            status=FormStatus.ACTIVE,
        )
        db.add(form)

        # Create exam blueprint
        blueprint_config = {
            "subjects": {"Physics": 2, "Chemistry": 2, "Mathematics": 2, "Biology": 2},
            "difficulty_distribution": {"easy": 3, "medium": 4, "hard": 1},
            "total_questions": 8,
            "marks_per_correct": 4.0,
            "marks_per_incorrect": 1.0,
            "negative_marking": True,
            "form_count": 4,
        }
        blueprint_json = json.dumps(blueprint_config, sort_keys=True)
        bp_hash = compute_integrity_hash(blueprint_json.encode())
        bp_signed = kms.sign(bp_hash.encode())

        blueprint = ExamBlueprint(
            exam_id=exam.id,
            config=blueprint_config,
            integrity_hash=bp_hash,
            digital_signature=bp_signed.signature_b64,
            status="APPROVED",
            approved_by=created_users["exam_authority"].id,
            approved_at=datetime.now(timezone.utc),
            created_by=created_users["exam_authority"].id,
        )
        db.add(blueprint)

        # Create demo candidate
        candidate = Candidate(
            org_id=org.id,
            user_id=created_users["candidate_demo"].id,
            registration_number="BSEA-2026-DEMO-001",
            full_name="Demo Candidate",
            email_hash=compute_integrity_hash(b"candidate@bsea.demo"),
            identity_verified=True,
        )
        db.add(candidate)

        # Add release approvals (threshold met for demo)
        from app.core.models import ReleaseApproval
        from app.core.security import generate_nonce

        for auth_key in ["release_auth_1", "release_auth_2", "release_auth_3"]:
            nonce = generate_nonce()
            approval_data = f"RELEASE_APPROVAL:{exam.id}:{created_users[auth_key].id}:{nonce}"
            signed = kms.sign(approval_data.encode())
            approval = ReleaseApproval(
                exam_id=exam.id,
                authority_id=created_users[auth_key].id,
                nonce=nonce,
                approval_signature=signed.signature_b64,
                is_valid=True,
            )
            db.add(approval)

        # Add some demo security events
        from app.core.models import SecurityEvent
        demo_events = [
            ("LOGIN_FAILURE", "MEDIUM", 0.4),
            ("MFA_FAILURE", "HIGH", 0.6),
            ("BULK_QUESTION_ACCESS", "CRITICAL", 0.9),
            ("TAB_SWITCH", "LOW", 0.1),
            ("SUSPICIOUS_ACCESS", "HIGH", 0.75),
        ]
        for etype, severity, score in demo_events:
            event = SecurityEvent(
                event_type=etype,
                severity=severity,
                actor_id=created_users["q_setter_1"].id,
                exam_id=exam.id,
                details={"demo": True, "description": f"Demo security event: {etype}"},
                risk_score=score,
                resolved=False,
            )
            db.add(event)

        await db.commit()

        print("✅ B-SEA Demo data seeded successfully")
        print(f"   Organization: {org.name} ({org.id})")
        print(f"   Exam: {exam.title} ({exam.id})")
        print(f"   Demo login: admin / BSeaDemo@2026")
        print(f"   Candidate registration: BSEA-2026-DEMO-001")
import asyncio; asyncio.run(seed_demo_data())



if __name__ == '__main__':
    import asyncio
    asyncio.run(seed_demo_data())
