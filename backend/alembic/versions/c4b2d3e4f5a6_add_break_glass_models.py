"""add break glass models

Revision ID: c4b2d3e4f5a6
Revises: b3a1c2d3e4f5
Create Date: 2026-09-13 18:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'c4b2d3e4f5a6'
down_revision: Union[str, None] = 'b3a1c2d3e4f5'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Existing userroleenum type
    userrole_enum = postgresql.ENUM(
        'SUPER_ADMIN', 'EXAM_AUTHORITY', 'QUESTION_SETTER', 'REVIEWER', 'MODERATOR',
        'SECURITY_OFFICER', 'RELEASE_AUTHORITY', 'CENTRE_ADMIN', 'INVIGILATOR',
        'CANDIDATE', 'AUDITOR',
        name='userroleenum',
        create_type=False
    )
    breakglassscope_enum = sa.Enum(
        'COMPLETE_EXAM_PAPER', 'EXAM_FORM_PREVIEW', 'AUDIT_VERIFICATION',
        name='breakglassscope'
    )
    breakglassrequeststatus_enum = sa.Enum(
        'PENDING', 'APPROVED', 'REJECTED', 'ACTIVATED', 'EXPIRED', 'REVOKED',
        name='breakglassrequeststatus'
    )
    breakglassapprovaldecision_enum = sa.Enum(
        'APPROVE', 'REJECT',
        name='breakglassapprovaldecision'
    )

    # 1. Create break_glass_requests table
    op.create_table(
        'break_glass_requests',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('exam_id', sa.String(length=36), nullable=False),
        sa.Column('blueprint_id', sa.String(length=36), nullable=True),
        sa.Column('exam_version', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('blueprint_hash', sa.String(length=128), nullable=False),
        sa.Column('requester_id', sa.String(length=36), nullable=False),
        sa.Column('scope', breakglassscope_enum, nullable=False),
        sa.Column('form_label', sa.String(length=10), nullable=True),
        sa.Column('justification', sa.Text(), nullable=False),
        sa.Column('incident_id', sa.String(length=36), nullable=True),
        sa.Column('required_quorum', sa.Integer(), nullable=False, server_default='2'),
        sa.Column('min_distinct_roles', sa.Integer(), nullable=False, server_default='2'),
        sa.Column('status', breakglassrequeststatus_enum, nullable=False, server_default='PENDING'),
        sa.Column('requested_duration_minutes', sa.Integer(), nullable=False, server_default='30'),
        sa.Column('activation_session_id', sa.String(length=64), nullable=True),
        sa.Column('content_fingerprint', sa.String(length=64), nullable=False),
        sa.Column('policy_version', sa.String(length=20), nullable=False, server_default='1.0'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('approved_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('activated_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revoked_by', sa.String(length=36), nullable=True),
        sa.Column('revocation_reason', sa.String(length=255), nullable=True),
        sa.Column('correlation_id', sa.String(length=64), nullable=True),
        sa.ForeignKeyConstraint(['blueprint_id'], ['exam_blueprints.id'], ),
        sa.ForeignKeyConstraint(['exam_id'], ['exams.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['incident_id'], ['incidents.id'], ),
        sa.ForeignKeyConstraint(['requester_id'], ['users.id'], ),
        sa.ForeignKeyConstraint(['revoked_by'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_bg_request_exam_status', 'break_glass_requests', ['exam_id', 'status'], unique=False)
    op.create_index('ix_bg_request_requester_status', 'break_glass_requests', ['requester_id', 'status'], unique=False)
    op.create_index('ix_bg_request_created_at', 'break_glass_requests', ['created_at'], unique=False)

    # 2. Create break_glass_approvals table
    op.create_table(
        'break_glass_approvals',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('request_id', sa.String(length=36), nullable=False),
        sa.Column('approver_id', sa.String(length=36), nullable=False),
        sa.Column('approver_role', userrole_enum, nullable=False),
        sa.Column('decision', breakglassapprovaldecision_enum, nullable=False),
        sa.Column('comments', sa.Text(), nullable=True),
        sa.Column('nonce', sa.String(length=64), nullable=False),
        sa.Column('request_fingerprint', sa.String(length=64), nullable=False),
        sa.Column('digital_signature', sa.Text(), nullable=False),
        sa.Column('is_valid', sa.Boolean(), nullable=False, server_default='true'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['approver_id'], ['users.id'], ),
        sa.ForeignKeyConstraint(['request_id'], ['break_glass_requests.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('request_id', 'approver_id', name='uq_bg_approval_request_approver')
    )
    op.create_index('ix_bg_approval_request_valid', 'break_glass_approvals', ['request_id', 'is_valid'], unique=False)
    op.create_index('ix_bg_approval_approver_id', 'break_glass_approvals', ['approver_id'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_bg_approval_approver_id', table_name='break_glass_approvals')
    op.drop_index('ix_bg_approval_request_valid', table_name='break_glass_approvals')
    op.drop_table('break_glass_approvals')

    op.drop_index('ix_bg_request_created_at', table_name='break_glass_requests')
    op.drop_index('ix_bg_request_requester_status', table_name='break_glass_requests')
    op.drop_index('ix_bg_request_exam_status', table_name='break_glass_requests')
    op.drop_table('break_glass_requests')

    sa.Enum(name='breakglassapprovaldecision').drop(op.get_bind(), checkfirst=True)
    sa.Enum(name='breakglassrequeststatus').drop(op.get_bind(), checkfirst=True)
    sa.Enum(name='breakglassscope').drop(op.get_bind(), checkfirst=True)
