"""Phase 3C-5A audit poison quarantine schema and immutability trigger

Revision ID: f1a2b3c4d5e6
Revises: e5f6a7b8c9d0
Create Date: 2026-09-14 14:15:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f1a2b3c4d5e6'
down_revision: Union[str, None] = 'e5f6a7b8c9d0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── 1. Create audit_poison_quarantine table ───────────────────────────────
    op.create_table(
        'audit_poison_quarantine',
        sa.Column('quarantine_id', sa.String(length=36), nullable=False),
        sa.Column('audit_log_id', sa.String(length=36), nullable=False),
        sa.Column('detected_event_hash', sa.String(length=128), nullable=True),
        sa.Column('quarantine_reason', sa.String(length=255), nullable=False),
        sa.Column('incident_reference', sa.String(length=64), nullable=False),
        sa.Column('policy_version', sa.String(length=32), server_default='BSEA-QUARANTINE-v1', nullable=False),
        sa.Column('authorization_nonce', sa.String(length=64), nullable=False),
        sa.Column('operator_1_id', sa.String(length=64), nullable=False),
        sa.Column('operator_1_key_id', sa.String(length=128), nullable=False),
        sa.Column('operator_1_signature_b64', sa.Text(), nullable=False),
        sa.Column('operator_2_id', sa.String(length=64), nullable=False),
        sa.Column('operator_2_key_id', sa.String(length=128), nullable=False),
        sa.Column('operator_2_signature_b64', sa.Text(), nullable=False),
        sa.Column('quarantined_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('quarantine_id', name='pk_audit_poison_quarantine'),
        sa.ForeignKeyConstraint(['audit_log_id'], ['audit_logs.id'], name='fk_audit_poison_quarantine_audit_log_id', ondelete='RESTRICT'),
        sa.UniqueConstraint('audit_log_id', name='uq_quarantine_audit_log_id'),
        sa.UniqueConstraint('authorization_nonce', name='uq_quarantine_nonce'),
        sa.CheckConstraint('operator_1_id != operator_2_id', name='ck_quarantine_distinct_operators'),
        sa.CheckConstraint('operator_1_key_id != operator_2_key_id', name='ck_quarantine_distinct_keys'),
    )
    op.create_index('ix_audit_poison_quarantine_log_id', 'audit_poison_quarantine', ['audit_log_id'])
    op.create_index('ix_audit_poison_quarantine_created_at', 'audit_poison_quarantine', ['quarantined_at'])

    # ── 2. Attach immutability trigger ───────────────────────────────────────
    op.execute("""
    CREATE TRIGGER trg_audit_poison_quarantine_immutable
    BEFORE UPDATE OR DELETE ON audit_poison_quarantine
    FOR EACH ROW EXECUTE FUNCTION trg_prevent_audit_mutation();
    """)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_audit_poison_quarantine_immutable ON audit_poison_quarantine;")
    op.drop_index('ix_audit_poison_quarantine_created_at', table_name='audit_poison_quarantine')
    op.drop_index('ix_audit_poison_quarantine_log_id', table_name='audit_poison_quarantine')
    op.drop_table('audit_poison_quarantine')
