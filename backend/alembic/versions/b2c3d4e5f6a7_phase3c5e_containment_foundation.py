"""phase3c5e_containment_foundation

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-09-16 23:00:00.000000

B-SEA Phase 3C-5E: Policy-Governed Security Containment Foundation Migration
Conforming strictly to docs/BSEA_PHASE3C5E_ARCHITECTURE_REV04_1.md.
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = 'b2c3d4e5f6a7'
down_revision: Union[str, None] = 'a1b2c3d4e5f6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── 1. Create Enums (PostgreSQL safe) ─────────────────────────────────────
    intent_status_enum = sa.Enum(
        'REGISTERED', 'IN_PROGRESS', 'CONTAINED', 'EXPIRED', 'FAILED',
        name='containmentintentstatus'
    )
    request_status_enum = sa.Enum(
        'REQUESTED', 'POLICY_EVALUATED', 'AWAITING_AUTHORIZATION', 'AUTHORIZED',
        'EXECUTING', 'EXECUTED', 'VERIFYING_PENDING', 'VERIFIED', 'FAILED',
        'EXPIRED', 'CANCELLED', 'QUARANTINED',
        name='containmentrequeststatus'
    )
    action_risk_enum = sa.Enum(
        'LOW', 'MEDIUM', 'HIGH', 'CRITICAL',
        name='containmentactionrisk'
    )
    action_type_enum = sa.Enum(
        'ACT_CAND_SESSION_TERM', 'ACT_ACCT_DISABLE', 'ACT_Q_PREVENT_ASSIGN',
        'ACT_CENTRE_RESTRICT', 'ACT_FORM_SUSPEND', 'ACT_CENTRE_SUSPEND',
        'ACT_CRYPTO_REVOKE_MASTER',
        name='containmentactiontype'
    )
    exec_outcome_enum = sa.Enum(
        'EXECUTION_SUCCEEDED', 'EXECUTION_FAILED', 'EXECUTION_UNKNOWN',
        name='executionoutcome'
    )
    verif_outcome_enum = sa.Enum(
        'VERIFICATION_VERIFIED', 'VERIFICATION_FAILED', 'VERIFICATION_INCONCLUSIVE',
        name='verificationoutcome'
    )
    bg_status_enum = sa.Enum(
        'ISSUED', 'CONSUMED', 'EXPIRED', 'REVOKED', 'UNDER_REVIEW', 'RATIFIED', 'BREACH_DECLARED',
        name='breakglasstokenstatus'
    )

    # ── 2. Table: containment_intents ────────────────────────────────────────
    op.create_table(
        'containment_intents',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('intent_key', sa.String(length=64), nullable=False),
        sa.Column('incident_id', sa.String(length=36), nullable=False),
        sa.Column('incident_generation', sa.Integer(), nullable=False),
        sa.Column('action_type', action_type_enum, nullable=False),
        sa.Column('canonical_target_urn', sa.String(length=256), nullable=False),
        sa.Column('risk_tier', action_risk_enum, nullable=False),
        sa.Column('status', intent_status_enum, server_default='REGISTERED', nullable=False),
        sa.Column('version', sa.Integer(), server_default='1', nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['incident_id'], ['security_incidents.id'], name='fk_containment_intents_incident_id', ondelete='RESTRICT'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('intent_key', name='uq_containment_intents_key')
    )
    op.create_index('ix_containment_intents_key', 'containment_intents', ['intent_key'])
    op.create_index('ix_containment_intents_target', 'containment_intents', ['canonical_target_urn'])
    op.create_index('ix_intents_incident_gen', 'containment_intents', ['incident_id', 'incident_generation'])
    op.create_index('ix_intents_status', 'containment_intents', ['status'])

    # ── 3. Table: containment_requests ───────────────────────────────────────
    op.create_table(
        'containment_requests',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('request_key', sa.String(length=64), nullable=False),
        sa.Column('intent_key', sa.String(length=64), nullable=False),
        sa.Column('requester_id', sa.String(length=36), nullable=False),
        sa.Column('target_snapshot_hash', sa.String(length=64), nullable=False),
        sa.Column('scope_hash', sa.String(length=64), nullable=False),
        sa.Column('max_allowed_entities', sa.Integer(), server_default='1', nullable=False),
        sa.Column('policy_version', sa.String(length=64), nullable=False),
        sa.Column('policy_fingerprint', sa.String(length=64), nullable=False),
        sa.Column('policy_decision', sa.String(length=64), nullable=True),
        sa.Column('status', request_status_enum, server_default='REQUESTED', nullable=False),
        sa.Column('execution_lease_expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('version', sa.Integer(), server_default='1', nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['intent_key'], ['containment_intents.intent_key'], name='fk_containment_requests_intent_key', ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(['requester_id'], ['users.id'], name='fk_containment_requests_requester_id', ondelete='RESTRICT'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('request_key', name='uq_containment_requests_key')
    )
    op.create_index('ix_containment_requests_intent_key', 'containment_requests', ['intent_key'])
    op.create_index('ix_requests_status', 'containment_requests', ['status'])
    op.create_index('ix_requests_requester', 'containment_requests', ['requester_id'])

    # ── 4. Table: containment_authorizations ─────────────────────────────────
    op.create_table(
        'containment_authorizations',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('request_id', sa.String(length=36), nullable=False),
        sa.Column('approver_id', sa.String(length=36), nullable=False),
        sa.Column('auth_nonce', sa.String(length=64), nullable=False),
        sa.Column('signature', sa.String(length=512), nullable=False),
        sa.Column('is_break_glass', sa.Boolean(), server_default='false', nullable=False),
        sa.Column('break_glass_token_id', sa.String(length=64), nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['approver_id'], ['users.id'], name='fk_containment_auth_approver_id', ondelete='RESTRICT'),
        sa.ForeignKeyConstraint(['request_id'], ['containment_requests.id'], name='fk_containment_auth_request_id', ondelete='RESTRICT'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('auth_nonce', name='uq_containment_auth_nonce')
    )
    op.create_index('ix_authorizations_request_id', 'containment_authorizations', ['request_id'])

    # ── 5. Table: break_glass_tokens ─────────────────────────────────────────
    op.create_table(
        'break_glass_tokens',
        sa.Column('id', sa.String(length=64), nullable=False),
        sa.Column('token_nonce', sa.String(length=64), nullable=False),
        sa.Column('intent_key', sa.String(length=64), nullable=False),
        sa.Column('incident_id', sa.String(length=36), nullable=False),
        sa.Column('incident_generation', sa.Integer(), nullable=False),
        sa.Column('canonical_target_urn', sa.String(length=256), nullable=False),
        sa.Column('target_scope_hash', sa.String(length=64), nullable=False),
        sa.Column('action_type', action_type_enum, nullable=False),
        sa.Column('policy_version', sa.String(length=64), nullable=False),
        sa.Column('issuer_id', sa.String(length=36), nullable=False),
        sa.Column('fido2_assertion_hash', sa.String(length=64), nullable=False),
        sa.Column('status', bg_status_enum, server_default='ISSUED', nullable=False),
        sa.Column('issued_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('consumed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('token_nonce', name='uq_break_glass_tokens_nonce')
    )
    op.create_index('ix_bg_tokens_intent', 'break_glass_tokens', ['intent_key'])
    op.create_index('ix_bg_tokens_status', 'break_glass_tokens', ['status'])

    # ── 6. Table: containment_execution_records ──────────────────────────────
    op.create_table(
        'containment_execution_records',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('request_id', sa.String(length=36), nullable=False),
        sa.Column('external_operation_id', sa.String(length=64), nullable=False),
        sa.Column('adapter_name', sa.String(length=64), nullable=False),
        sa.Column('raw_outcome', exec_outcome_enum, nullable=False),
        sa.Column('latency_ms', sa.Integer(), nullable=True),
        sa.Column('error_code', sa.String(length=64), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['request_id'], ['containment_requests.id'], name='fk_containment_exec_request_id', ondelete='RESTRICT'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('external_operation_id', name='uq_containment_exec_ext_op_id')
    )
    op.create_index('ix_containment_exec_request_id', 'containment_execution_records', ['request_id'])

    # ── 7. Table: containment_verification_proofs ────────────────────────────
    op.create_table(
        'containment_verification_proofs',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('execution_id', sa.String(length=36), nullable=False),
        sa.Column('verifier_name', sa.String(length=64), nullable=False),
        sa.Column('verification_outcome', verif_outcome_enum, nullable=False),
        sa.Column('observed_target_state', sa.String(length=64), nullable=True),
        sa.Column('proof_hash', sa.String(length=64), nullable=False),
        sa.Column('proof_payload', postgresql.JSONB(astext_type=sa.Text()).with_variant(sa.Text(), 'sqlite'), nullable=False),
        sa.Column('manual_attestation_officer_id', sa.String(length=36), nullable=True),
        sa.Column('manual_attestation_notes', sa.Text(), nullable=True),
        sa.Column('verified_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['execution_id'], ['containment_execution_records.id'], name='fk_containment_verif_exec_id', ondelete='RESTRICT'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('execution_id', name='uq_containment_verif_exec_id')
    )
    op.create_index('ix_containment_verif_exec_id', 'containment_verification_proofs', ['execution_id'])

    # ── 8. Table: containment_consumed_nonces ────────────────────────────────
    op.create_table(
        'containment_consumed_nonces',
        sa.Column('nonce', sa.String(length=64), nullable=False),
        sa.Column('nonce_type', sa.String(length=32), nullable=False),
        sa.Column('consumed_by', sa.String(length=36), nullable=False),
        sa.Column('consumed_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.PrimaryKeyConstraint('nonce')
    )


def downgrade() -> None:
    op.drop_table('containment_consumed_nonces')
    op.drop_index('ix_containment_verif_exec_id', table_name='containment_verification_proofs')
    op.drop_table('containment_verification_proofs')
    op.drop_index('ix_containment_exec_request_id', table_name='containment_execution_records')
    op.drop_table('containment_execution_records')
    op.drop_index('ix_bg_tokens_status', table_name='break_glass_tokens')
    op.drop_index('ix_bg_tokens_intent', table_name='break_glass_tokens')
    op.drop_table('break_glass_tokens')
    op.drop_index('ix_authorizations_request_id', table_name='containment_authorizations')
    op.drop_table('containment_authorizations')
    op.drop_index('ix_requests_requester', table_name='containment_requests')
    op.drop_index('ix_requests_status', table_name='containment_requests')
    op.drop_index('ix_containment_requests_intent_key', table_name='containment_requests')
    op.drop_table('containment_requests')
    op.drop_index('ix_intents_status', table_name='containment_intents')
    op.drop_index('ix_intents_incident_gen', table_name='containment_intents')
    op.drop_index('ix_containment_intents_target', table_name='containment_intents')
    op.drop_index('ix_containment_intents_key', table_name='containment_intents')
    op.drop_table('containment_intents')

    # Drop enums
    sa.Enum(name='breakglasstokenstatus').drop(op.get_bind(), checkfirst=True)
    sa.Enum(name='verificationoutcome').drop(op.get_bind(), checkfirst=True)
    sa.Enum(name='executionoutcome').drop(op.get_bind(), checkfirst=True)
    sa.Enum(name='containmentactiontype').drop(op.get_bind(), checkfirst=True)
    sa.Enum(name='containmentactionrisk').drop(op.get_bind(), checkfirst=True)
    sa.Enum(name='containmentrequeststatus').drop(op.get_bind(), checkfirst=True)
    sa.Enum(name='containmentintentstatus').drop(op.get_bind(), checkfirst=True)
