"""add question access grants

Revision ID: b3a1c2d3e4f5
Revises: a2f3b4c5d6e7
Create Date: 2026-09-13 16:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'b3a1c2d3e4f5'
down_revision: Union[str, None] = 'a2f3b4c5d6e7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Use postgresql.ENUM with create_type=False for existing reviewpurpose type
    reviewpurpose_enum = postgresql.ENUM(
        'TECHNICAL_REVIEW', 'SYLLABUS_REVIEW', 'LANGUAGE_REVIEW', 'DISTRACTOR_REVIEW', 'KEY_VERIFICATION',
        name='reviewpurpose',
        create_type=False
    )
    questionoperation_enum = sa.Enum('VIEW', 'REVIEW', 'APPROVE', 'REJECT', name='questionoperation')
    accessgrantstatus_enum = sa.Enum('GRANTED', 'ACTIVE', 'EXPIRED', 'REVOKED', name='accessgrantstatus')

    op.create_table('question_access_grants',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('question_id', sa.String(length=36), nullable=False),
        sa.Column('exam_id', sa.String(length=36), nullable=False),
        sa.Column('reviewer_id', sa.String(length=36), nullable=False),
        sa.Column('assignment_id', sa.String(length=36), nullable=False),
        sa.Column('purpose', reviewpurpose_enum, nullable=False),
        sa.Column('operation', questionoperation_enum, nullable=False),
        sa.Column('status', accessgrantstatus_enum, nullable=False),
        sa.Column('issued_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('activated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revocation_reason', sa.String(length=255), nullable=True),
        sa.Column('session_id', sa.String(length=64), nullable=True),
        sa.Column('created_by', sa.String(length=36), nullable=False),
        sa.Column('correlation_id', sa.String(length=64), nullable=True),
        sa.ForeignKeyConstraint(['assignment_id'], ['question_assignments.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['created_by'], ['users.id'], ),
        sa.ForeignKeyConstraint(['exam_id'], ['exams.id'], ),
        sa.ForeignKeyConstraint(['question_id'], ['questions.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['reviewer_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_qgrant_assignment_status', 'question_access_grants', ['assignment_id', 'status'], unique=False)
    op.create_index('ix_qgrant_question_op', 'question_access_grants', ['question_id', 'operation'], unique=False)
    op.create_index('ix_qgrant_reviewer_status', 'question_access_grants', ['reviewer_id', 'status'], unique=False)
    op.create_index(
        'uix_active_grant_assignment_operation',
        'question_access_grants',
        ['assignment_id', 'operation'],
        unique=True,
        postgresql_where=sa.text("status IN ('GRANTED', 'ACTIVE')"),
        sqlite_where=sa.text("status IN ('GRANTED', 'ACTIVE')")
    )


def downgrade() -> None:
    op.drop_index(
        'uix_active_grant_assignment_operation',
        table_name='question_access_grants',
        postgresql_where=sa.text("status IN ('GRANTED', 'ACTIVE')"),
        sqlite_where=sa.text("status IN ('GRANTED', 'ACTIVE')")
    )
    op.drop_index('ix_qgrant_reviewer_status', table_name='question_access_grants')
    op.drop_index('ix_qgrant_question_op', table_name='question_access_grants')
    op.drop_index('ix_qgrant_assignment_status', table_name='question_access_grants')
    op.drop_table('question_access_grants')

    sa.Enum(name='questionoperation').drop(op.get_bind(), checkfirst=True)
    sa.Enum(name='accessgrantstatus').drop(op.get_bind(), checkfirst=True)
