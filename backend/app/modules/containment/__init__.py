"""
B-SEA Phase 3C-5E Containment Module
Public interface for policy-governed security containment.
"""
from app.modules.containment.models import (
    ContainmentIntent,
    ContainmentIntentStatus,
    ContainmentRequest,
    ContainmentRequestStatus,
    ContainmentAuthorization,
    BreakGlassToken,
    BreakGlassTokenStatus,
    ContainmentExecutionRecord,
    ContainmentVerificationProof,
    ContainmentConsumedNonce,
    ContainmentActionType,
    ContainmentActionRisk,
    ExecutionOutcome,
    VerificationOutcome,
)
from app.modules.containment.identity import (
    canonicalize_target_urn,
    compute_intent_key,
    compute_request_key,
    compute_scope_hash,
    compute_target_snapshot_hash,
    compute_policy_fingerprint,
    compute_external_operation_id,
    generate_crypto_nonce,
    jcs_canonicalize,
)
from app.modules.containment.policy import (
    ContainmentPolicyEngine,
    StandardPolicyDecision,
    BreakGlassPolicyDecision,
    PolicyEvaluationResult,
    CURRENT_POLICY_VERSION,
)
from app.modules.containment.authorization import (
    AuthorizationService,
    DualControlSelfApprovalError,
    InsufficientQuorumError,
    AuthorizationExpiredError,
    ReplayAttackError,
)
from app.modules.containment.break_glass import (
    BreakGlassTokenCoordinator,
    BreakGlassError,
    BreakGlassCriticalProhibitedError,
    BreakGlassTokenExpiredError,
    BreakGlassReplayError,
)
from app.modules.containment.adapters import (
    SubsystemExecutionRegistry,
    ExecutionAdapterResult,
)
from app.modules.containment.verifier import (
    IndependentVerificationEngine,
    IndependentVerificationResult,
)
from app.modules.containment.reconciliation import (
    ReconciliationService,
)

def __getattr__(name: str):
    if name in {
        "ContainmentCoordinatorService",
        "ContainmentServiceError",
        "ContainmentPolicyDeniedError",
        "TargetStateMismatchError",
        "ExecutionLeaseExpiredError",
    }:
        from app.modules.containment import service
        return getattr(service, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = [
    "ContainmentIntent",
    "ContainmentIntentStatus",
    "ContainmentRequest",
    "ContainmentRequestStatus",
    "ContainmentAuthorization",
    "BreakGlassToken",
    "BreakGlassTokenStatus",
    "ContainmentExecutionRecord",
    "ContainmentVerificationProof",
    "ContainmentConsumedNonce",
    "ContainmentActionType",
    "ContainmentActionRisk",
    "ExecutionOutcome",
    "VerificationOutcome",
    "canonicalize_target_urn",
    "compute_intent_key",
    "compute_request_key",
    "compute_scope_hash",
    "compute_target_snapshot_hash",
    "compute_policy_fingerprint",
    "compute_external_operation_id",
    "generate_crypto_nonce",
    "jcs_canonicalize",
    "ContainmentPolicyEngine",
    "StandardPolicyDecision",
    "BreakGlassPolicyDecision",
    "PolicyEvaluationResult",
    "CURRENT_POLICY_VERSION",
    "AuthorizationService",
    "DualControlSelfApprovalError",
    "InsufficientQuorumError",
    "AuthorizationExpiredError",
    "ReplayAttackError",
    "BreakGlassTokenCoordinator",
    "BreakGlassError",
    "BreakGlassCriticalProhibitedError",
    "BreakGlassTokenExpiredError",
    "BreakGlassReplayError",
    "SubsystemExecutionRegistry",
    "ExecutionAdapterResult",
    "IndependentVerificationEngine",
    "IndependentVerificationResult",
    "ReconciliationService",
    "ContainmentCoordinatorService",
    "ContainmentServiceError",
    "ContainmentPolicyDeniedError",
    "TargetStateMismatchError",
    "ExecutionLeaseExpiredError",
]
