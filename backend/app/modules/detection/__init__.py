"""
B-SEA Phase 3C-5C Detection & Correlation Foundation Module
Conforming strictly to BSEA_PHASE3C_5C_DETECTION_CORRELATION_ARCHITECTURE_REVIEW_REV03.md

Exports the core detection and correlation foundation interfaces:
  - DetectionEngine
  - CorrelationManager
  - EventNormalizer
  - RuleCatalog
  - CloudTrailKMSReconciler
  - DurableAuditSQSDispatcher
  - SQSDetectionWorker
  - SecurityEventNormalized, SecuritySignal, CloudTrailKMSEvent
"""
from app.modules.detection.cloudtrail import CloudTrailKMSReconciler
from app.modules.detection.correlation import CorrelationManager
from app.modules.detection.engine import (
    DetectionEngine,
    DurableAuditSQSDispatcher,
    SQSDetectionWorker,
)
from app.modules.detection.models import (
    AuditEvidenceState,
    BreakGlassScopeReference,
    CloudTrailKMSEvent,
    CloudTrailReconciliationState,
    DetectionMode,
    DetectionRuleDefinition,
    DetectionSeverity,
    IdentityCorrelationStrength,
    RuleEvaluationResult,
    ScopeEvaluationState,
    SecurityEventNormalized,
    SecuritySignal,
)
from app.modules.detection.normalizer import EventNormalizer
from app.modules.detection.rules import (
    BaseRuleEvaluator,
    RuleAEvaluator,
    RuleBEvaluator,
    RuleCatalog,
    RuleCEvaluator,
    RuleDEvaluator,
    RuleEEvaluator,
    RuleFEvaluator,
    RuleGEvaluator,
    RuleHEvaluator,
    RuleIEvaluator,
    RuleJEvaluator,
)

__all__ = [
    "AuditEvidenceState",
    "BaseRuleEvaluator",
    "BreakGlassScopeReference",
    "CloudTrailKMSEvent",
    "CloudTrailKMSReconciler",
    "CloudTrailReconciliationState",
    "CorrelationManager",
    "DetectionEngine",
    "DetectionMode",
    "DetectionRuleDefinition",
    "DetectionSeverity",
    "DurableAuditSQSDispatcher",
    "EventNormalizer",
    "IdentityCorrelationStrength",
    "RuleAEvaluator",
    "RuleBEvaluator",
    "RuleCatalog",
    "RuleCEvaluator",
    "RuleDEvaluator",
    "RuleEEvaluator",
    "RuleEvaluationResult",
    "RuleFEvaluator",
    "RuleGEvaluator",
    "RuleHEvaluator",
    "RuleIEvaluator",
    "RuleJEvaluator",
    "SQSDetectionWorker",
    "ScopeEvaluationState",
    "SecurityEventNormalized",
    "SecuritySignal",
]
