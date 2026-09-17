"""Phase 3C-5D security incident management foundation schema, indexes, and immutability triggers

Revision ID: a1b2c3d4e5f6
Revises: f1a2b3c4d5e6
Create Date: 2026-09-16 18:45:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a1b2c3d4e5f6'
down_revision: Union[str, None] = 'f1a2b3c4d5e6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── 1. Create Enums ───────────────────────────────────────────────────────
    securityincidentstatus_enum = sa.Enum(
        'TRIAGE', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'CLOSED', 'FALSE_POSITIVE', 'DUPLICATE',
        name='securityincidentstatus'
    )
    securityincidentseverity_enum = sa.Enum(
        'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO',
        name='securityincidentseverity'
    )
    correlationstatus_enum = sa.Enum(
        'OPEN', 'CLOSED',
        name='correlationstatus'
    )
    sealverificationstatus_enum = sa.Enum(
        'UNCONTAINED', 'PENDING_SEAL', 'SEALED_VERIFIED',
        name='sealverificationstatus'
    )
    evidencetype_enum = sa.Enum(
        'AUDIT_EVENT', 'DETECTION_SIGNAL', 'CLOUDTRAIL_EVENT',
        name='evidencetype'
    )

    # ── 2. Create security_incidents table ────────────────────────────────────
    op.create_table(
        'security_incidents',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('incident_number', sa.String(length=32), nullable=False),
        sa.Column('threat_vector_key', sa.String(length=64), nullable=False),
        sa.Column('generation', sa.Integer(), server_default='1', nullable=False),
        sa.Column('correlation_status', correlationstatus_enum, server_default='OPEN', nullable=False),
        sa.Column('preceding_incident_id', sa.String(length=36), nullable=True),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=False),
        sa.Column('incident_type', sa.String(length=64), nullable=False),
        sa.Column('severity', securityincidentseverity_enum, server_default='MEDIUM', nullable=False),
        sa.Column('status', securityincidentstatus_enum, server_default='TRIAGE', nullable=False),
        sa.Column('rule_id', sa.String(length=64), nullable=False),
        sa.Column('canonical_rule_id', sa.String(length=64), nullable=False),
        sa.Column('policy_version', sa.String(length=32), server_default='v1', nullable=False),
        sa.Column('dimensions_json', sa.JSON(), nullable=False),
        sa.Column('exam_id', sa.String(length=64), nullable=False),
        sa.Column('assigned_to', sa.String(length=36), nullable=True),
        sa.Column('duplicate_of_incident_id', sa.String(length=36), nullable=True),
        sa.Column('first_signal_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('latest_signal_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('containment_reference_id', sa.String(length=128), nullable=True),
        sa.Column('authorization_principal', sa.String(length=128), nullable=True),
        sa.Column('containment_timestamp', sa.DateTime(timezone=True), nullable=True),
        sa.Column('containment_mechanism', sa.String(length=64), nullable=True),
        sa.Column('audit_event_reference', sa.String(length=128), nullable=True),
        sa.Column('seal_verification_status', sealverificationstatus_enum, server_default='UNCONTAINED', nullable=False),
        sa.Column('sealed_epoch_id', sa.String(length=36), nullable=True),
        sa.Column('seal_block_hash', sa.String(length=64), nullable=True),
        sa.Column('resolution_summary', sa.Text(), nullable=True),
        sa.Column('resolution_category', sa.String(length=64), nullable=True),
        sa.Column('version', sa.Integer(), server_default='1', nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id', name='pk_security_incidents'),
        sa.UniqueConstraint('incident_number', name='uq_security_incidents_incident_number'),
        sa.UniqueConstraint('threat_vector_key', 'generation', name='uq_threat_vector_generation'),
        sa.ForeignKeyConstraint(['preceding_incident_id'], ['security_incidents.id'], name='fk_security_incidents_preceding_incident_id', ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(['duplicate_of_incident_id'], ['security_incidents.id'], name='fk_security_incidents_duplicate_of_incident_id', ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(['assigned_to'], ['users.id'], name='fk_security_incidents_assigned_to', ondelete='SET NULL'),
        sa.CheckConstraint('duplicate_of_incident_id IS NULL OR duplicate_of_incident_id != id', name='ck_no_self_duplicate'),
        sa.CheckConstraint('preceding_incident_id IS NULL OR preceding_incident_id != id', name='ck_no_self_preceding'),
    )

    # Partial Unique Index: Exactly ONE generation OPEN per threat_vector_key
    op.create_index(
        'uq_active_correlation_token',
        'security_incidents',
        ['threat_vector_key'],
        unique=True,
        postgresql_where=sa.text("correlation_status = 'OPEN'"),
        sqlite_where=sa.text("correlation_status = 'OPEN'"),
    )

    op.create_index('ix_incidents_threat_vector', 'security_incidents', ['threat_vector_key'])
    op.create_index('ix_incidents_status', 'security_incidents', ['status'])
    op.create_index('ix_incidents_correlation_status', 'security_incidents', ['correlation_status'])
    op.create_index('ix_incidents_severity', 'security_incidents', ['severity'])
    op.create_index('ix_incidents_assigned_to', 'security_incidents', ['assigned_to'])
    op.create_index('ix_incidents_exam_id', 'security_incidents', ['exam_id'])
    op.create_index('ix_incidents_latest_signal', 'security_incidents', [sa.text('latest_signal_at DESC')])
    op.create_index('ix_incidents_created_at', 'security_incidents', [sa.text('created_at DESC')])

    # ── 3. Create incident_evidence_links table ───────────────────────────────
    op.create_table(
        'incident_evidence_links',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('incident_id', sa.String(length=36), nullable=False),
        sa.Column('evidence_type', evidencetype_enum, nullable=False),
        sa.Column('evidence_reference_id', sa.String(length=128), nullable=False),
        sa.Column('evidence_hash', sa.String(length=64), nullable=False),
        sa.Column('attached_by', sa.String(length=36), nullable=False),
        sa.Column('attached_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id', name='pk_incident_evidence_links'),
        sa.ForeignKeyConstraint(['incident_id'], ['security_incidents.id'], name='fk_incident_evidence_links_incident_id', ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(['attached_by'], ['users.id'], name='fk_incident_evidence_links_attached_by', ondelete='RESTRICT'),
        sa.UniqueConstraint('incident_id', 'evidence_reference_id', name='uq_incident_evidence'),
    )
    op.create_index('ix_evidence_incident_id', 'incident_evidence_links', ['incident_id'])
    op.create_index('ix_evidence_attached_at', 'incident_evidence_links', ['attached_at'])

    # ── 4. Create incident_comments table ─────────────────────────────────────
    op.create_table(
        'incident_comments',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('incident_id', sa.String(length=36), nullable=False),
        sa.Column('author_id', sa.String(length=36), nullable=False),
        sa.Column('comment_text', sa.String(length=2000), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id', name='pk_incident_comments'),
        sa.ForeignKeyConstraint(['incident_id'], ['security_incidents.id'], name='fk_incident_comments_incident_id', ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(['author_id'], ['users.id'], name='fk_incident_comments_author_id', ondelete='RESTRICT'),
        sa.CheckConstraint('length(comment_text) <= 2000', name='ck_incident_comments_max_length'),
    )
    op.create_index('ix_comments_incident_id', 'incident_comments', ['incident_id', sa.text('created_at ASC')])

    # ── 5. Attach PostgreSQL Immutability Triggers ────────────────────────────
    op.execute("""
    CREATE TRIGGER trg_incident_evidence_links_immutable
    BEFORE UPDATE OR DELETE ON incident_evidence_links
    FOR EACH ROW EXECUTE FUNCTION trg_prevent_audit_mutation();
    """)

    op.execute("""
    CREATE TRIGGER trg_incident_comments_immutable
    BEFORE UPDATE OR DELETE ON incident_comments
    FOR EACH ROW EXECUTE FUNCTION trg_prevent_audit_mutation();
    """)

    op.execute("""
    CREATE TRIGGER trg_security_incidents_no_delete
    BEFORE DELETE ON security_incidents
    FOR EACH ROW EXECUTE FUNCTION trg_prevent_audit_mutation();
    """)


def downgrade() -> None:
    # ── 1. Drop Immutability Triggers ─────────────────────────────────────────
    op.execute("DROP TRIGGER IF EXISTS trg_security_incidents_no_delete ON security_incidents;")
    op.execute("DROP TRIGGER IF EXISTS trg_incident_comments_immutable ON incident_comments;")
    op.execute("DROP TRIGGER IF EXISTS trg_incident_evidence_links_immutable ON incident_evidence_links;")

    # ── 2. Drop incident_comments ─────────────────────────────────────────────
    op.drop_index('ix_comments_incident_id', table_name='incident_comments')
    op.drop_table('incident_comments')

    # ── 3. Drop incident_evidence_links ───────────────────────────────────────
    op.drop_index('ix_evidence_attached_at', table_name='incident_evidence_links')
    op.drop_index('ix_evidence_incident_id', table_name='incident_evidence_links')
    op.drop_table('incident_evidence_links')

    # ── 4. Drop security_incidents ────────────────────────────────────────────
    op.drop_index('ix_incidents_created_at', table_name='security_incidents')
    op.drop_index('ix_incidents_latest_signal', table_name='security_incidents')
    op.drop_index('ix_incidents_exam_id', table_name='security_incidents')
    op.drop_index('ix_incidents_assigned_to', table_name='security_incidents')
    op.drop_index('ix_incidents_severity', table_name='security_incidents')
    op.drop_index('ix_incidents_correlation_status', table_name='security_incidents')
    op.drop_index('ix_incidents_status', table_name='security_incidents')
    op.drop_index('ix_incidents_threat_vector', table_name='security_incidents')
    op.drop_index('uq_active_correlation_token', table_name='security_incidents')
    op.drop_table('security_incidents')

    # ── 5. Drop Enums ─────────────────────────────────────────────────────────
    sa.Enum(name='evidencetype').drop(op.get_bind(), checkfirst=True)
    sa.Enum(name='sealverificationstatus').drop(op.get_bind(), checkfirst=True)
    sa.Enum(name='correlationstatus').drop(op.get_bind(), checkfirst=True)
    sa.Enum(name='securityincidentseverity').drop(op.get_bind(), checkfirst=True)
    sa.Enum(name='securityincidentstatus').drop(op.get_bind(), checkfirst=True)
