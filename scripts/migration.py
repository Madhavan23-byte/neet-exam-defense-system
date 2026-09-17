"""Phase 3C-4A decoupled audit architecture and append-only database foundation

Revision ID: e5f6a7b8c9d0
Revises: c4b2d3e4f5a6
Create Date: 2026-09-14 11:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e5f6a7b8c9d0'
down_revision: Union[str, None] = 'c4b2d3e4f5a6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── 1. Modify audit_logs table ───────────────────────────────────────────
    # Add created_at, trace_id, and kms_request_id
    op.add_column('audit_logs', sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True))
    op.add_column('audit_logs', sa.Column('trace_id', sa.String(length=64), nullable=True))
    op.add_column('audit_logs', sa.Column('kms_request_id', sa.String(length=64), nullable=True))

    # Backfill created_at from timestamp for existing historical records
    op.execute("UPDATE audit_logs SET created_at = timestamp WHERE created_at IS NULL")

    # Set created_at to NOT NULL
    op.alter_column('audit_logs', 'created_at', nullable=False, server_default=sa.text('now()'))

    # Make legacy seq and prev_hash nullable (canonical ordering is now assigned in audit_chain_links)
    op.alter_column('audit_logs', 'seq', nullable=True)
    op.alter_column('audit_logs', 'prev_hash', nullable=True)

    # Indexes on audit_logs
    op.create_index('ix_audit_created_at', 'audit_logs', ['created_at'])
    op.create_index('ix_audit_created_at_id', 'audit_logs', ['created_at', 'id'])
    op.create_index('ix_audit_trace_id', 'audit_logs', ['trace_id'])

    # ── 2. Create audit_chain_links table ────────────────────────────────────
    op.create_table(
        'audit_chain_links',
        sa.Column('link_id', sa.BigInteger(), autoincrement=True, nullable=False),
        sa.Column('chain_seq', sa.BigInteger(), nullable=False),
        sa.Column('audit_log_id', sa.String(length=36), nullable=False),
        sa.Column('event_hash', sa.String(length=64), nullable=False),
        sa.Column('prev_chain_hash', sa.String(length=64), nullable=False),
        sa.Column('chain_hash', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('link_id', name='pk_audit_chain_links'),
        sa.ForeignKeyConstraint(['audit_log_id'], ['audit_logs.id'], name='fk_audit_chain_links_audit_log_id', ondelete='RESTRICT'),
        sa.UniqueConstraint('chain_seq', name='uq_audit_chain_links_chain_seq'),
        sa.UniqueConstraint('audit_log_id', name='uq_audit_chain_links_audit_log_id'),
    )
    op.create_index('ix_audit_chain_links_chain_seq', 'audit_chain_links', ['chain_seq'])
    op.create_index('ix_audit_chain_links_audit_log_id', 'audit_chain_links', ['audit_log_id'])
    op.create_index('ix_audit_chain_links_created_at', 'audit_chain_links', ['created_at'])

    # ── 3. Create audit_epoch_seals table ────────────────────────────────────
    op.create_table(
        'audit_epoch_seals',
        sa.Column('epoch_id', sa.BigInteger(), nullable=False),
        sa.Column('policy_version', sa.String(length=32), nullable=False),
        sa.Column('start_chain_seq', sa.BigInteger(), nullable=False),
        sa.Column('end_chain_seq', sa.BigInteger(), nullable=False),
        sa.Column('record_count', sa.Integer(), nullable=False),
        sa.Column('prev_seal_hash', sa.String(length=64), nullable=False),
        sa.Column('final_chain_hash', sa.String(length=64), nullable=False),
        sa.Column('epoch_root_hash', sa.String(length=64), nullable=False),
        sa.Column('signature_b64', sa.Text(), nullable=False),
        sa.Column('kms_key_id', sa.String(length=256), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('epoch_id', name='pk_audit_epoch_seals'),
        sa.UniqueConstraint('end_chain_seq', name='uq_audit_epoch_seals_end_chain_seq'),
        sa.CheckConstraint('start_chain_seq >= 1', name='ck_audit_epoch_seals_positive_seq'),
        sa.CheckConstraint('start_chain_seq <= end_chain_seq', name='ck_audit_epoch_seals_seq_range'),
        sa.CheckConstraint('record_count > 0', name='ck_audit_epoch_seals_record_count'),
        sa.CheckConstraint('record_count = (end_chain_seq - start_chain_seq + 1)', name='ck_audit_epoch_seals_count_match'),
    )
    op.create_index('ix_audit_epoch_seals_start_chain_seq', 'audit_epoch_seals', ['start_chain_seq'])
    op.create_index('ix_audit_epoch_seals_created_at', 'audit_epoch_seals', ['created_at'])

    # ── 4. PostgreSQL Immutability Triggers ───────────────────────────────────
    op.execute("""
    CREATE OR REPLACE FUNCTION trg_prevent_audit_mutation()
    RETURNS TRIGGER AS $$
    BEGIN
        RAISE EXCEPTION 'Table % is strictly immutable. UPDATE and DELETE operations are forbidden.', TG_TABLE_NAME
            USING ERRCODE = 'integrity_constraint_violation';
    END;
    $$ LANGUAGE plpgsql;
    """)

    op.execute("""
    CREATE TRIGGER trg_audit_logs_immutable
    BEFORE UPDATE OR DELETE ON audit_logs
    FOR EACH ROW
    EXECUTE FUNCTION trg_prevent_audit_mutation();
    """)

    op.execute("""
    CREATE TRIGGER trg_audit_chain_links_immutable
    BEFORE UPDATE OR DELETE ON audit_chain_links
    FOR EACH ROW
    EXECUTE FUNCTION trg_prevent_audit_mutation();
    """)

    op.execute("""
    CREATE TRIGGER trg_audit_epoch_seals_immutable
    BEFORE UPDATE OR DELETE ON audit_epoch_seals
    FOR EACH ROW
    EXECUTE FUNCTION trg_prevent_audit_mutation();
    """)


def downgrade() -> None:
    # ── 1. Drop Immutability Triggers ────────────────────────────────────────
    op.execute("DROP TRIGGER IF EXISTS trg_audit_epoch_seals_immutable ON audit_epoch_seals;")
    op.execute("DROP TRIGGER IF EXISTS trg_audit_chain_links_immutable ON audit_chain_links;")
    op.execute("DROP TRIGGER IF EXISTS trg_audit_logs_immutable ON audit_logs;")
    op.execute("DROP FUNCTION IF EXISTS trg_prevent_audit_mutation();")

    # ── 2. Drop audit_epoch_seals table ──────────────────────────────────────
    op.drop_index('ix_audit_epoch_seals_created_at', table_name='audit_epoch_seals')
    op.drop_index('ix_audit_epoch_seals_start_chain_seq', table_name='audit_epoch_seals')
    op.drop_table('audit_epoch_seals')

    # ── 3. Drop audit_chain_links table ──────────────────────────────────────
    op.drop_index('ix_audit_chain_links_created_at', table_name='audit_chain_links')
    op.drop_index('ix_audit_chain_links_audit_log_id', table_name='audit_chain_links')
    op.drop_index('ix_audit_chain_links_chain_seq', table_name='audit_chain_links')
    op.drop_table('audit_chain_links')

    # ── 4. Revert audit_logs columns and indexes ─────────────────────────────
    op.drop_index('ix_audit_trace_id', table_name='audit_logs')
    op.drop_index('ix_audit_created_at_id', table_name='audit_logs')
    op.drop_index('ix_audit_created_at', table_name='audit_logs')
    op.drop_column('audit_logs', 'kms_request_id')
    op.drop_column('audit_logs', 'trace_id')
    op.drop_column('audit_logs', 'created_at')

    # Backfill nulls if any before restoring NOT NULL constraints
    op.execute("UPDATE audit_logs SET seq = 0 WHERE seq IS NULL;")
    op.execute("UPDATE audit_logs SET prev_hash = 'GENESIS' WHERE prev_hash IS NULL;")
    op.alter_column('audit_logs', 'prev_hash', nullable=False)
    op.alter_column('audit_logs', 'seq', nullable=False)
