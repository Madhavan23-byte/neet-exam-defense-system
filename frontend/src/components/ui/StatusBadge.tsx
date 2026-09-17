import React from 'react';
import { CheckCircle2, AlertTriangle, Clock, ShieldCheck, XCircle, FileLock2, AlertCircle } from 'lucide-react';

interface StatusBadgeProps {
  status: string;
  type?: 'incident' | 'exam' | 'containment' | 'audit' | 'general';
}

export default function StatusBadge({ status, type = 'general' }: StatusBadgeProps) {
  const norm = (status || '').toUpperCase();

  // 5D Incident States
  if (norm === 'TRIAGE') {
    return <span className="badge-warning"><AlertCircle className="w-3 h-3" /> Triage</span>;
  }
  if (norm === 'INVESTIGATING') {
    return <span className="badge-warning"><Clock className="w-3 h-3" /> Investigating</span>;
  }
  if (norm === 'CONTAINED') {
    return <span className="badge-secure"><ShieldCheck className="w-3 h-3" /> Contained</span>;
  }
  if (norm === 'RESOLVED') {
    return <span className="badge-info"><CheckCircle2 className="w-3 h-3" /> Resolved</span>;
  }
  if (norm === 'CLOSED') {
    return <span className="badge-neutral"><CheckCircle2 className="w-3 h-3" /> Closed</span>;
  }
  if (norm === 'FALSE_POSITIVE') {
    return <span className="badge-neutral"><XCircle className="w-3 h-3" /> False Positive</span>;
  }
  if (norm === 'DUPLICATE') {
    return <span className="badge-neutral"><AlertCircle className="w-3 h-3" /> Duplicate</span>;
  }

  // 5E Containment Statuses
  if (norm === 'REQUESTED' || norm === 'PENDING') {
    return <span className="badge-warning"><Clock className="w-3 h-3" /> Pending Authorization</span>;
  }
  if (norm === 'AUTHORIZED') {
    return <span className="badge-info"><ShieldCheck className="w-3 h-3" /> Authorized</span>;
  }
  if (norm === 'EXECUTING') {
    return <span className="badge-warning"><Clock className="w-3 h-3" /> Executing</span>;
  }
  if (norm === 'EXECUTION_SUCCEEDED' || norm === 'VERIFICATION_VERIFIED' || norm === 'ACTIVE') {
    return <span className="badge-secure"><CheckCircle2 className="w-3 h-3" /> {norm.replace('_', ' ')}</span>;
  }
  if (norm === 'EXECUTION_FAILED' || norm === 'VERIFICATION_FAILED' || norm === 'DENIED') {
    return <span className="badge-critical"><XCircle className="w-3 h-3" /> {norm.replace('_', ' ')}</span>;
  }
  if (norm === 'EXECUTION_UNKNOWN' || norm === 'VERIFICATION_INCONCLUSIVE') {
    return <span className="badge-warning"><AlertTriangle className="w-3 h-3" /> Quarantined (Unknown)</span>;
  }

  // Exam Statuses
  if (norm === 'DRAFT') {
    return <span className="badge-neutral">Draft</span>;
  }
  if (norm === 'BLUEPRINT_CREATED') {
    return <span className="badge-info">Blueprint Created</span>;
  }
  if (norm === 'FORMS_GENERATED') {
    return <span className="badge-info">Forms Generated</span>;
  }
  if (norm === 'RELEASE_PENDING_APPROVAL') {
    return <span className="badge-warning"><Clock className="w-3 h-3" /> Quorum Required</span>;
  }
  if (norm === 'RELEASED' || norm === 'ONGOING') {
    return <span className="badge-secure"><ShieldCheck className="w-3 h-3" /> Active / Ongoing</span>;
  }
  if (norm === 'CONCLUDED') {
    return <span className="badge-neutral">Concluded</span>;
  }

  // Fallback
  return <span className="badge-neutral">{status}</span>;
}
