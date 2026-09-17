import React, { useState } from 'react';
import { Shield, CheckCircle2, AlertTriangle, KeyRound, Lock, X } from 'lucide-react';
import { containmentApi } from '../../services/api';
import ActionModal from '../ui/ActionModal';

interface QuorumApprovalModalProps {
  isOpen: boolean;
  onClose: () => void;
  request: any;
  onAuthorized: () => void;
}

export default function QuorumApprovalModal({
  isOpen,
  onClose,
  request,
  onAuthorized,
}: QuorumApprovalModalProps) {
  const [authNonce, setAuthNonce] = useState(() => 'nonce_' + Math.random().toString(36).substring(2, 12));
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState('');

  if (!request) return null;

  const handleAuthorize = async (decision: 'APPROVE' | 'DENY') => {
    setIsSubmitting(true);
    setError('');
    try {
      await containmentApi.authorizeRequest(request.id, {
        auth_nonce: authNonce,
        decision,
      });
      onAuthorized();
      onClose();
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || 'Authorization failed');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <ActionModal
      isOpen={isOpen}
      onClose={onClose}
      title="Two-Person Quorum Authorization"
      subtitle={`Containment Action: ${request.action_type}`}
      maxWidth="max-w-xl"
    >
      <div className="space-y-4 text-xs">
        {error && (
          <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-red-700 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        <div className="p-3 bg-[var(--gov-surface-warm)] rounded-lg border border-[var(--gov-border)] space-y-2">
          <div className="flex justify-between">
            <span className="text-slate-500 font-semibold">Request ID:</span>
            <span className="font-mono text-slate-800">{request.id}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-slate-500 font-semibold">Intent Key:</span>
            <span className="font-mono text-slate-800 truncate max-w-[300px]">{request.intent_key}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-slate-500 font-semibold">Blast Radius Risk:</span>
            <span className="font-semibold text-amber-800">{request.risk_tier || 'HIGH'}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-slate-500 font-semibold">Requester ID:</span>
            <span className="font-mono text-slate-800">{request.requester_id}</span>
          </div>
        </div>

        <div>
          <label className="form-label">Justification Provided</label>
          <div className="p-2.5 bg-slate-50 border border-slate-200 rounded-md text-slate-700 font-medium">
            {request.justification || 'No justification specified.'}
          </div>
        </div>

        <div className="p-3 bg-amber-500/10 border border-amber-500/30 rounded-lg">
          <div className="font-bold text-amber-900 flex items-center gap-1.5 mb-1">
            <Shield className="w-4 h-4 text-amber-700" />
            Quorum Integrity Safeguard
          </div>
          <p className="text-amber-800 leading-relaxed text-[11px]">
            In accordance with Rev-04.1 security specifications, the authorizer must be distinct from the original requester. Self-authorization is strictly prohibited by cryptographic nonce validation.
          </p>
        </div>

        <div>
          <label className="form-label">Cryptographic Authorization Nonce</label>
          <input
            type="text"
            className="form-input font-mono text-xs"
            value={authNonce}
            onChange={(e) => setAuthNonce(e.target.value)}
          />
        </div>

        <div className="pt-2 flex items-center justify-end gap-3">
          <button
            type="button"
            className="btn btn-outline text-xs"
            onClick={onClose}
            disabled={isSubmitting}
          >
            Cancel
          </button>
          <button
            type="button"
            className="btn btn-danger text-xs"
            onClick={() => handleAuthorize('DENY')}
            disabled={isSubmitting}
          >
            Reject Request
          </button>
          <button
            type="button"
            className="btn btn-primary text-xs"
            onClick={() => handleAuthorize('APPROVE')}
            disabled={isSubmitting || !authNonce}
          >
            {isSubmitting ? 'Authorizing...' : 'Authorize Execution'}
          </button>
        </div>
      </div>
    </ActionModal>
  );
}
