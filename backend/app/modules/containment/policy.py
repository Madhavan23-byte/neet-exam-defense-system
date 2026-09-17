"""
B-SEA Phase 3C-5E: Policy Engine & Dual Decision Pipelines
Conforming strictly to docs/BSEA_PHASE3C5E_ARCHITECTURE_REV04_1.md Sections 1, 2, 3, 4.

Implements two deterministic policy decision pipelines:
1. Standard Policy Pipeline:
   Yields: ALLOW, DENY, REQUIRE_SECOND_AUTHORIZER, REQUIRE_ADDITIONAL_EVIDENCE
2. Emergency Break-Glass Pipeline:
   Yields: BREAK_GLASS_ALLOWED, BREAK_GLASS_DENIED

CRITICAL INVARIANTS:
- Emergency Break-Glass NEVER reinterprets REQUIRE_SECOND_AUTHORIZER as automatic authorization.
- CRITICAL risk actions (ACT_FORM_SUSPEND, ACT_CENTRE_SUSPEND, ACT_CRYPTO_REVOKE_MASTER)
  are permanently and categorically prohibited from Break-Glass.
- Incident Severity and Action Risk are orthogonal.
"""
from __future__ import annotations

import enum
from typing import Any, Dict, List, Optional, Tuple, Set

from app.core.models import UserRoleEnum, SecurityIncidentStatus, SecurityIncidentSeverity
from app.modules.containment.models import (
    ContainmentActionType,
    ContainmentActionRisk,
)


class StandardPolicyDecision(str, enum.Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REQUIRE_SECOND_AUTHORIZER = "REQUIRE_SECOND_AUTHORIZER"
    REQUIRE_ADDITIONAL_EVIDENCE = "REQUIRE_ADDITIONAL_EVIDENCE"


class BreakGlassPolicyDecision(str, enum.Enum):
    BREAK_GLASS_ALLOWED = "BREAK_GLASS_ALLOWED"
    BREAK_GLASS_DENIED = "BREAK_GLASS_DENIED"


class PolicyEvaluationResult:
    def __init__(
        self,
        decision: str,
        risk_tier: ContainmentActionRisk,
        policy_version: str,
        policy_fingerprint: str,
        reason: str,
        requires_dual_approval: bool = False,
    ):
        self.decision = decision
        self.risk_tier = risk_tier
        self.policy_version = policy_version
        self.policy_fingerprint = policy_fingerprint
        self.reason = reason
        self.requires_dual_approval = requires_dual_approval

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision,
            "risk_tier": self.risk_tier.value,
            "policy_version": self.policy_version,
            "policy_fingerprint": self.policy_fingerprint,
            "reason": self.reason,
            "requires_dual_approval": self.requires_dual_approval,
        }


# ─── ACTION RISK MAPPING ───────────────────────────────────────────────────────

ACTION_RISK_MAP: Dict[ContainmentActionType, ContainmentActionRisk] = {
    ContainmentActionType.ACT_CAND_SESSION_TERM: ContainmentActionRisk.LOW,
    ContainmentActionType.ACT_ACCT_DISABLE: ContainmentActionRisk.HIGH,
    ContainmentActionType.ACT_Q_PREVENT_ASSIGN: ContainmentActionRisk.HIGH,
    ContainmentActionType.ACT_CENTRE_RESTRICT: ContainmentActionRisk.HIGH,
    ContainmentActionType.ACT_FORM_SUSPEND: ContainmentActionRisk.CRITICAL,
    ContainmentActionType.ACT_CENTRE_SUSPEND: ContainmentActionRisk.CRITICAL,
    ContainmentActionType.ACT_CRYPTO_REVOKE_MASTER: ContainmentActionRisk.CRITICAL,
}

# Pre-approved single-entity actions eligible for emergency break-glass
BREAK_GLASS_ELIGIBLE_ACTIONS: Set[ContainmentActionType] = {
    ContainmentActionType.ACT_CAND_SESSION_TERM,
    ContainmentActionType.ACT_ACCT_DISABLE,
    ContainmentActionType.ACT_Q_PREVENT_ASSIGN,
}

CURRENT_POLICY_VERSION = "POL-CONTAIN-2026-v04.1"
CURRENT_CATALOG_HASH = "8f3b2c1a0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3210fedcba9876543210ab"


class ContainmentPolicyEngine:
    """
    Authoritative Policy Engine for Phase 3C-5E Containment Actions.
    """

    def __init__(
        self,
        policy_version: str = CURRENT_POLICY_VERSION,
        catalog_hash: str = CURRENT_CATALOG_HASH,
    ):
        self.policy_version = policy_version
        self.catalog_hash = catalog_hash

    @property
    def policy_fingerprint(self) -> str:
        from app.modules.containment.identity import compute_policy_fingerprint
        return compute_policy_fingerprint(self.policy_version, self.catalog_hash)

    def get_action_risk(self, action_type: ContainmentActionType) -> ContainmentActionRisk:
        return ACTION_RISK_MAP.get(action_type, ContainmentActionRisk.CRITICAL)

    def evaluate_standard_policy(
        self,
        action_type: ContainmentActionType,
        incident_status: SecurityIncidentStatus,
        incident_severity: SecurityIncidentSeverity,
        target_urn: str,
        max_entities: int,
        requester_role: UserRoleEnum,
        is_target_allowlisted: bool = False,
        signal_confidence: float = 1.0,
    ) -> PolicyEvaluationResult:
        """
        Evaluate standard containment policy pipeline.
        Yields: ALLOW, DENY, REQUIRE_SECOND_AUTHORIZER, or REQUIRE_ADDITIONAL_EVIDENCE.
        """
        risk_tier = self.get_action_risk(action_type)

        # 1. Target Allowlist Check
        if is_target_allowlisted:
            return PolicyEvaluationResult(
                decision=StandardPolicyDecision.DENY.value,
                risk_tier=risk_tier,
                policy_version=self.policy_version,
                policy_fingerprint=self.policy_fingerprint,
                reason=f"Target entity '{target_urn}' is protected by active allowlist rule.",
            )

        # 2. Incident Status Check: Must be in active investigation
        if incident_status != SecurityIncidentStatus.INVESTIGATING:
            return PolicyEvaluationResult(
                decision=StandardPolicyDecision.DENY.value,
                risk_tier=risk_tier,
                policy_version=self.policy_version,
                policy_fingerprint=self.policy_fingerprint,
                reason=f"Containment actions can only be requested for incidents in INVESTIGATING status (current: {incident_status}).",
            )

        # 3. Requester Role Authorization
        valid_roles = {UserRoleEnum.SECURITY_OFFICER, UserRoleEnum.SUPER_ADMIN}
        if requester_role not in valid_roles:
            return PolicyEvaluationResult(
                decision=StandardPolicyDecision.DENY.value,
                risk_tier=risk_tier,
                policy_version=self.policy_version,
                policy_fingerprint=self.policy_fingerprint,
                reason=f"Role '{requester_role}' lacks authority to request security containment actions.",
            )

        # 4. Proportionality Check: LOW/INFO incidents cannot trigger HIGH/CRITICAL actions
        if incident_severity in {SecurityIncidentSeverity.LOW, SecurityIncidentSeverity.INFO}:
            if risk_tier in {ContainmentActionRisk.HIGH, ContainmentActionRisk.CRITICAL}:
                return PolicyEvaluationResult(
                    decision=StandardPolicyDecision.DENY.value,
                    risk_tier=risk_tier,
                    policy_version=self.policy_version,
                    policy_fingerprint=self.policy_fingerprint,
                    reason=f"Disproportionate blast radius: Incident severity '{incident_severity}' cannot authorize '{risk_tier}' action.",
                )

        # 5. Signal Confidence Check
        if signal_confidence < 0.70:
            return PolicyEvaluationResult(
                decision=StandardPolicyDecision.REQUIRE_ADDITIONAL_EVIDENCE.value,
                risk_tier=risk_tier,
                policy_version=self.policy_version,
                policy_fingerprint=self.policy_fingerprint,
                reason=f"Detection signal confidence {signal_confidence:.2f} is below minimum threshold 0.70.",
            )

        # 6. Risk Tier Routing
        if risk_tier in {ContainmentActionRisk.LOW, ContainmentActionRisk.MEDIUM}:
            return PolicyEvaluationResult(
                decision=StandardPolicyDecision.ALLOW.value,
                risk_tier=risk_tier,
                policy_version=self.policy_version,
                policy_fingerprint=self.policy_fingerprint,
                reason="Single-person authorization permitted for LOW/MEDIUM risk action.",
                requires_dual_approval=False,
            )
        else:
            # HIGH or CRITICAL risk mandates Two-Person Control
            return PolicyEvaluationResult(
                decision=StandardPolicyDecision.REQUIRE_SECOND_AUTHORIZER.value,
                risk_tier=risk_tier,
                policy_version=self.policy_version,
                policy_fingerprint=self.policy_fingerprint,
                reason=f"Action classified as {risk_tier.value} risk. Two-Person Control strictly mandated.",
                requires_dual_approval=True,
            )

    def evaluate_break_glass_policy(
        self,
        action_type: ContainmentActionType,
        incident_status: SecurityIncidentStatus,
        incident_severity: SecurityIncidentSeverity,
        target_urn: str,
        max_entities: int,
        requester_role: UserRoleEnum,
        is_exam_in_progress: bool,
        recent_break_glass_count_by_user: int = 0,
        total_break_glass_count_for_exam: int = 0,
    ) -> PolicyEvaluationResult:
        """
        Evaluate emergency Break-Glass crisis pipeline.
        Yields: BREAK_GLASS_ALLOWED or BREAK_GLASS_DENIED.
        """
        risk_tier = self.get_action_risk(action_type)

        # INVIOLABLE RULE 1: CRITICAL risk actions are CATEGORICALLY PROHIBITED from Break-Glass
        if risk_tier == ContainmentActionRisk.CRITICAL:
            return PolicyEvaluationResult(
                decision=BreakGlassPolicyDecision.BREAK_GLASS_DENIED.value,
                risk_tier=risk_tier,
                policy_version=self.policy_version,
                policy_fingerprint=self.policy_fingerprint,
                reason="BREAK_GLASS_CRITICAL_PROHIBITED: Actions with CRITICAL blast radius (form, centre, crypto) categorically require two-person executive authorization.",
            )

        # INVIOLABLE RULE 2: Single-entity scope ceiling (max_allowed_entities == 1)
        if max_entities != 1:
            return PolicyEvaluationResult(
                decision=BreakGlassPolicyDecision.BREAK_GLASS_DENIED.value,
                risk_tier=risk_tier,
                policy_version=self.policy_version,
                policy_fingerprint=self.policy_fingerprint,
                reason=f"ERR_BREAK_GLASS_SCOPE_VIOLATION: Break-Glass strictly enforces max_allowed_entities == 1 (requested: {max_entities}).",
            )

        # INVIOLABLE RULE 3: Eligible action subset check
        if action_type not in BREAK_GLASS_ELIGIBLE_ACTIONS:
            return PolicyEvaluationResult(
                decision=BreakGlassPolicyDecision.BREAK_GLASS_DENIED.value,
                risk_tier=risk_tier,
                policy_version=self.policy_version,
                policy_fingerprint=self.policy_fingerprint,
                reason=f"Action '{action_type.value}' is not within the approved emergency single-entity break-glass subset.",
            )

        # INVIOLABLE RULE 4: Incident status must be INVESTIGATING
        if incident_status != SecurityIncidentStatus.INVESTIGATING:
            return PolicyEvaluationResult(
                decision=BreakGlassPolicyDecision.BREAK_GLASS_DENIED.value,
                risk_tier=risk_tier,
                policy_version=self.policy_version,
                policy_fingerprint=self.policy_fingerprint,
                reason=f"Break-Glass requires incident status INVESTIGATING (current: {incident_status}).",
            )

        # INVIOLABLE RULE 5: Incident severity must be HIGH or CRITICAL
        if incident_severity not in {SecurityIncidentSeverity.HIGH, SecurityIncidentSeverity.CRITICAL}:
            return PolicyEvaluationResult(
                decision=BreakGlassPolicyDecision.BREAK_GLASS_DENIED.value,
                risk_tier=risk_tier,
                policy_version=self.policy_version,
                policy_fingerprint=self.policy_fingerprint,
                reason=f"Break-Glass permitted only for HIGH or CRITICAL incident severity (current: {incident_severity}).",
            )

        # INVIOLABLE RULE 6: Active examination delivery window
        if not is_exam_in_progress:
            return PolicyEvaluationResult(
                decision=BreakGlassPolicyDecision.BREAK_GLASS_DENIED.value,
                risk_tier=risk_tier,
                policy_version=self.policy_version,
                policy_fingerprint=self.policy_fingerprint,
                reason="Break-Glass is permitted strictly during active live examination delivery windows.",
            )

        # INVIOLABLE RULE 7: Requester role must be strictly SUPER_ADMIN
        if requester_role != UserRoleEnum.SUPER_ADMIN:
            return PolicyEvaluationResult(
                decision=BreakGlassPolicyDecision.BREAK_GLASS_DENIED.value,
                risk_tier=risk_tier,
                policy_version=self.policy_version,
                policy_fingerprint=self.policy_fingerprint,
                reason=f"Role '{requester_role}' cannot issue break-glass tokens; strictly restricted to SUPER_ADMIN.",
            )

        # INVIOLABLE RULE 8: Rate Limiting
        # Max 2 break-glass actions per 60 min per super-admin
        if recent_break_glass_count_by_user >= 2:
            return PolicyEvaluationResult(
                decision=BreakGlassPolicyDecision.BREAK_GLASS_DENIED.value,
                risk_tier=risk_tier,
                policy_version=self.policy_version,
                policy_fingerprint=self.policy_fingerprint,
                reason="ERR_BREAK_GLASS_RATE_LIMIT_EXCEEDED: Principal has exceeded maximum 2 break-glass actions per 60-minute window.",
            )

        # Max 5 break-glass actions across all super-admins for this exam slot
        if total_break_glass_count_for_exam >= 5:
            return PolicyEvaluationResult(
                decision=BreakGlassPolicyDecision.BREAK_GLASS_DENIED.value,
                risk_tier=risk_tier,
                policy_version=self.policy_version,
                policy_fingerprint=self.policy_fingerprint,
                reason="ERR_BREAK_GLASS_RATE_LIMIT_EXCEEDED: Examination slot has reached maximum 5 total break-glass actions. Automated override suspended.",
            )

        # All emergency criteria met
        return PolicyEvaluationResult(
            decision=BreakGlassPolicyDecision.BREAK_GLASS_ALLOWED.value,
            risk_tier=risk_tier,
            policy_version=self.policy_version,
            policy_fingerprint=self.policy_fingerprint,
            reason="BREAK_GLASS_ALLOWED: All 8 emergency eligibility invariants satisfied. Authorized for single-use token issuance.",
            requires_dual_approval=False,
        )
