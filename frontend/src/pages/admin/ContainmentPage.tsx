import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  ShieldAlert, Shield, CheckCircle2, AlertTriangle, Clock,
  KeyRound, RefreshCw, Plus, FileText, Lock, Flame, Eye,
  HelpCircle, ArrowRight, Sparkles, CheckSquare, Layers
} from 'lucide-react';
import { containmentApi, incidentsApi } from '../../services/api';
import StatusBadge from '../../components/ui/StatusBadge';
import ActionModal from '../../components/ui/ActionModal';
import QuorumApprovalModal from '../../components/security/QuorumApprovalModal';
import EmptyState from '../../components/ui/EmptyState';

const CONTAINMENT_ACTIONS = [
  { value: 'CONTAIN_CANDIDATE_SESSION', label: 'Contain Candidate Session', desc: 'Revokes active CBT token and quarantines session' },
  { value: 'DISABLE_ACCOUNT', label: 'Disable User Account', desc: 'Locks suspicious user account across all portals' },
  { value: 'QUARANTINE_QUESTION', label: 'Quarantine Compromised Question', desc: 'Isolates question from active candidate generation pools' },
  { value: 'RESTRICT_EXAM_CENTRE', label: 'Restrict Examination Centre', desc: 'Places centre under heightened proctoring surveillance' },
  { value: 'SUSPEND_EXAM_CENTRE', label: 'Suspend Examination Centre', desc: 'Halts all ongoing testing sessions at centre immediately' },
  { value: 'SUSPEND_EXAM_FORM', label: 'Suspend Exam Form', desc: 'Suspends specific form variant from candidate assignment' },
  { value: 'REVOKE_MASTER_CRYPTO_KEY', label: 'Revoke Master Crypto Key', desc: 'Extreme blast radius: immediately revokes exam KMS key' },
];

export default function ContainmentPage() {
  const queryClient = useQueryClient();

  // Modals state
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showQuorumModal, setShowQuorumModal] = useState(false);
  const [showBreakGlassModal, setShowBreakGlassModal] = useState(false);
  const [showAttestModal, setShowAttestModal] = useState(false);
  const [selectedRequest, setSelectedRequest] = useState<any>(null);

  // Form states
  const [actionType, setActionType] = useState(CONTAINMENT_ACTIONS[0].value);
  const [incidentId, setIncidentId] = useState('');
  const [targetJson, setTargetJson] = useState('{\n  "candidate_id": "cand_demo_01",\n  "reason": "Anomalous telemetry detected"\n}');
  const [justification, setJustification] = useState('');
  const [msg, setMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // Break-glass modal state
  const [bgTokenId, setBgTokenId] = useState('');
  const [bgIncidentId, setBgIncidentId] = useState('');
  const [bgFidoPayload, setBgFidoPayload] = useState('{"authenticator_data": "mock_webauthn_assertion"}');

  // Attestation modal state
  const [attestUrn, setAttestUrn] = useState('');
  const [attestNote, setAttestNote] = useState('');

  // Local state for demonstration requests list
  const [localRequests, setLocalRequests] = useState<any[]>([
    {
      id: 'req_5e_001',
      action_type: 'CONTAIN_CANDIDATE_SESSION',
      target_urn: 'urn:bsea:candidate_session:sess_cand_9812',
      intent_key: 'ik_7b9d21e8fa2948',
      risk_tier: 'MEDIUM',
      status: 'AUTHORIZED',
      requester_id: 'usr_sec_officer_1',
      justification: 'Repeated tab switches exceeding tolerance threshold.',
      created_at: new Date(Date.now() - 1000 * 60 * 15).toISOString(),
    },
    {
      id: 'req_5e_002',
      action_type: 'QUARANTINE_QUESTION',
      target_urn: 'urn:bsea:question:q_chem_049',
      intent_key: 'ik_4f2a8901bc3312',
      risk_tier: 'HIGH',
      status: 'REQUESTED',
      requester_id: 'usr_sec_officer_2',
      justification: 'External Telegram leak allegation reported on social forum.',
      created_at: new Date(Date.now() - 1000 * 60 * 5).toISOString(),
    },
  ]);

  // Fetch open incidents for dropdown
  const { data: incidents = [] } = useQuery({
    queryKey: ['incidents-for-containment'],
    queryFn: () => incidentsApi.list().then((r) => r.data || []),
  });

  const handleCreateRequest = async (e: React.FormEvent) => {
    e.preventDefault();
    setMsg(null);
    try {
      let parsedTarget = {};
      try {
        parsedTarget = JSON.parse(targetJson);
      } catch {
        setMsg({ type: 'error', text: 'Target JSON is not valid JSON syntax.' });
        return;
      }

      const res = await containmentApi.createRequest({
        action_type: actionType,
        incident_id: incidentId || (incidents.length > 0 ? incidents[0].id : 'inc_mock_01'),
        target_dict: parsedTarget,
        justification,
      });

      const newReq = {
        id: res.data.request_id || 'req_' + Math.random().toString(36).substring(2, 8),
        action_type: actionType,
        target_urn: `urn:bsea:${actionType.toLowerCase()}:${JSON.stringify(parsedTarget).substring(0, 20)}`,
        intent_key: 'ik_' + Math.random().toString(36).substring(2, 12),
        risk_tier: actionType === 'REVOKE_MASTER_CRYPTO_KEY' ? 'CRITICAL' : 'HIGH',
        status: res.data.decision === 'ALLOW' ? 'AUTHORIZED' : 'REQUESTED',
        requester_id: 'current_user',
        justification,
        created_at: new Date().toISOString(),
      };

      setLocalRequests([newReq, ...localRequests]);
      setShowCreateModal(false);
      setMsg({ type: 'success', text: `Containment request created. Decision: ${res.data.decision}` });
    } catch (err: any) {
      setMsg({ type: 'error', text: err?.response?.data?.detail || err.message || 'Request creation failed' });
    }
  };

  const handleExecute = async (req: any) => {
    setMsg(null);
    try {
      await containmentApi.executeRequest(req.id, {
        target_dict: { target_urn: req.target_urn },
      });
      setLocalRequests(
        localRequests.map((r) => (r.id === req.id ? { ...r, status: 'EXECUTION_SUCCEEDED' } : r))
      );
      setMsg({ type: 'success', text: `Containment action ${req.action_type} executed and verified.` });
    } catch (err: any) {
      setMsg({ type: 'error', text: err?.response?.data?.detail || err.message || 'Execution failed' });
    }
  };

  const handleReconcile = async () => {
    setMsg(null);
    try {
      const res = await containmentApi.reconcile();
      setMsg({
        type: 'success',
        text: `Reconciliation completed: ${res.data.reconciled_count || 0} items scanned. DB & engine state in sync.`,
      });
    } catch (err: any) {
      setMsg({ type: 'error', text: err?.response?.data?.detail || err.message || 'Reconciliation failed' });
    }
  };

  const handleAttest = async (e: React.FormEvent) => {
    e.preventDefault();
    setMsg(null);
    try {
      await containmentApi.attest({
        target_urn: attestUrn,
        attestation_note: attestNote,
      });
      setShowAttestModal(false);
      setMsg({ type: 'success', text: `Operator attestation recorded for ${attestUrn}.` });
    } catch (err: any) {
      setMsg({ type: 'error', text: err?.response?.data?.detail || err.message || 'Attestation failed' });
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="gov-card-warm flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <h1 className="text-xl font-bold text-[var(--gov-navy-dark)]">
              Policy-Governed Security Containment
            </h1>
            <span className="badge-secure">Phase 3C-5E Engine Active</span>
          </div>
          <p className="text-xs text-slate-500">
            Deterministic, quorum-governed containment pipeline with independent out-of-band verification
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={handleReconcile}
            className="btn btn-outline text-xs"
            title="Scan database for divergences and quarantined targets"
          >
            <RefreshCw className="w-3.5 h-3.5" /> Reconcile Engine
          </button>
          <button
            onClick={() => setShowAttestModal(true)}
            className="btn btn-outline text-xs"
          >
            <CheckSquare className="w-3.5 h-3.5" /> Attest Resource
          </button>
          <button
            onClick={() => setShowCreateModal(true)}
            className="btn btn-amber text-xs"
          >
            <Plus className="w-4 h-4" /> Request Containment
          </button>
        </div>
      </div>

      {msg && (
        <div className={`p-3 rounded-lg text-xs flex items-center gap-2 ${
          msg.type === 'success' ? 'bg-emerald-50 border border-emerald-200 text-emerald-800' : 'bg-red-50 border border-red-200 text-red-700'
        }`}>
          {msg.type === 'success' ? <CheckCircle2 className="w-4 h-4 shrink-0" /> : <AlertTriangle className="w-4 h-4 shrink-0" />}
          <span>{msg.text}</span>
        </div>
      )}

      {/* 6-Step Verification Architecture Pipeline Visualizer */}
      <div className="gov-card">
        <h2 className="text-xs font-bold uppercase tracking-wider text-[var(--gov-navy-dark)] mb-3 flex items-center gap-1.5">
          <Layers className="w-4 h-4 text-amber-600" />
          Rev-04.1 Containment Execution Pipeline
        </h2>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 text-center text-xs">
          <div className="p-2.5 rounded-lg bg-[var(--gov-surface-warm)] border border-[var(--gov-border)]">
            <div className="w-6 h-6 rounded-full bg-[var(--gov-navy)] text-white font-bold text-[10px] mx-auto mb-1.5 flex items-center justify-center">1</div>
            <div className="font-bold text-slate-800 text-[11px]">Identity & Intent</div>
            <div className="text-[10px] text-slate-500 mt-0.5">RFC 8785 Canonical JCS</div>
          </div>
          <div className="p-2.5 rounded-lg bg-[var(--gov-surface-warm)] border border-[var(--gov-border)]">
            <div className="w-6 h-6 rounded-full bg-[var(--gov-navy)] text-white font-bold text-[10px] mx-auto mb-1.5 flex items-center justify-center">2</div>
            <div className="font-bold text-slate-800 text-[11px]">Policy Evaluation</div>
            <div className="text-[10px] text-slate-500 mt-0.5">Dual Rule Pipelines</div>
          </div>
          <div className="p-2.5 rounded-lg bg-[var(--gov-surface-warm)] border border-[var(--gov-border)]">
            <div className="w-6 h-6 rounded-full bg-[var(--gov-navy)] text-white font-bold text-[10px] mx-auto mb-1.5 flex items-center justify-center">3</div>
            <div className="font-bold text-slate-800 text-[11px]">Quorum Auth</div>
            <div className="text-[10px] text-slate-500 mt-0.5">2-Person Distinct Role</div>
          </div>
          <div className="p-2.5 rounded-lg bg-[var(--gov-surface-warm)] border border-[var(--gov-border)]">
            <div className="w-6 h-6 rounded-full bg-[var(--gov-navy)] text-white font-bold text-[10px] mx-auto mb-1.5 flex items-center justify-center">4</div>
            <div className="font-bold text-slate-800 text-[11px]">Target Snapshot</div>
            <div className="text-[10px] text-slate-500 mt-0.5">Pre-Execution Hash Lock</div>
          </div>
          <div className="p-2.5 rounded-lg bg-[var(--gov-surface-warm)] border border-[var(--gov-border)]">
            <div className="w-6 h-6 rounded-full bg-[var(--gov-navy)] text-white font-bold text-[10px] mx-auto mb-1.5 flex items-center justify-center">5</div>
            <div className="font-bold text-slate-800 text-[11px]">OOB Verification</div>
            <div className="text-[10px] text-slate-500 mt-0.5">Independent DB Readback</div>
          </div>
          <div className="p-2.5 rounded-lg bg-[var(--gov-surface-warm)] border border-[var(--gov-border)]">
            <div className="w-6 h-6 rounded-full bg-[var(--gov-navy)] text-white font-bold text-[10px] mx-auto mb-1.5 flex items-center justify-center">6</div>
            <div className="font-bold text-slate-800 text-[11px]">Mode B Audit</div>
            <div className="text-[10px] text-slate-500 mt-0.5">SHA-256 Chained Seal</div>
          </div>
        </div>
      </div>

      {/* Containment Requests Table */}
      <div className="gov-card">
        <div className="flex items-center justify-between pb-3 border-b border-[var(--gov-border)] mb-4">
          <h2 className="text-sm font-bold text-[var(--gov-navy-dark)]">
            Active Containment Directives & Authorizations
          </h2>
          <span className="text-xs text-slate-500">{localRequests.length} Directive Records</span>
        </div>

        <div className="overflow-x-auto">
          <table className="gov-table">
            <thead>
              <tr>
                <th>Action Type</th>
                <th>Target URN</th>
                <th>Intent Key</th>
                <th>Blast Risk</th>
                <th>Lifecycle Status</th>
                <th>Initiated</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {localRequests.map((req) => (
                <tr key={req.id}>
                  <td className="font-bold text-slate-800 text-xs">{req.action_type}</td>
                  <td className="font-mono text-xs text-slate-600 truncate max-w-[180px]" title={req.target_urn}>
                    {req.target_urn}
                  </td>
                  <td className="font-mono text-[11px] text-slate-500">{req.intent_key}</td>
                  <td>
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                      req.risk_tier === 'CRITICAL' ? 'bg-red-100 text-red-800' : 'bg-amber-100 text-amber-800'
                    }`}>
                      {req.risk_tier}
                    </span>
                  </td>
                  <td>
                    <StatusBadge status={req.status} type="containment" />
                  </td>
                  <td className="text-xs text-slate-500 font-mono">
                    {new Date(req.created_at).toLocaleTimeString('en-IN')}
                  </td>
                  <td>
                    <div className="flex items-center gap-1.5">
                      {req.status === 'REQUESTED' && (
                        <button
                          onClick={() => {
                            setSelectedRequest(req);
                            setShowQuorumModal(true);
                          }}
                          className="btn btn-outline text-[11px] py-1 px-2 text-amber-800 hover:bg-amber-50"
                        >
                          <KeyRound className="w-3 h-3" /> Authorize
                        </button>
                      )}
                      {req.status === 'AUTHORIZED' && (
                        <button
                          onClick={() => handleExecute(req)}
                          className="btn btn-primary text-[11px] py-1 px-2"
                        >
                          <ShieldAlert className="w-3 h-3" /> Execute
                        </button>
                      )}
                      {req.status === 'EXECUTION_SUCCEEDED' && (
                        <span className="text-[11px] font-semibold text-emerald-700 flex items-center gap-1">
                          <CheckCircle2 className="w-3.5 h-3.5" /> Enforced
                        </span>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Request Containment Modal */}
      <ActionModal
        isOpen={showCreateModal}
        onClose={() => setShowCreateModal(false)}
        title="Initiate Security Containment Action"
        subtitle="Specify containment action parameters and link with active security incident"
        maxWidth="max-w-xl"
      >
        <form onSubmit={handleCreateRequest} className="space-y-4 text-xs">
          <div>
            <label className="form-label">Containment Action Type</label>
            <select
              className="form-input text-xs"
              value={actionType}
              onChange={(e) => setActionType(e.target.value)}
            >
              {CONTAINMENT_ACTIONS.map((a) => (
                <option key={a.value} value={a.value}>
                  {a.label} ({a.desc})
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="form-label">Linked Security Incident (5D)</label>
            <select
              className="form-input text-xs"
              value={incidentId}
              onChange={(e) => setIncidentId(e.target.value)}
            >
              <option value="">Select correlated incident...</option>
              {incidents.map((inc: any) => (
                <option key={inc.id} value={inc.id}>
                  {inc.title} ({inc.severity})
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="form-label">Target Dictionary (JSON Format)</label>
            <textarea
              className="form-input text-xs font-mono min-h-[90px]"
              value={targetJson}
              onChange={(e) => setTargetJson(e.target.value)}
              required
            />
          </div>

          <div>
            <label className="form-label">Operational Justification</label>
            <textarea
              className="form-input text-xs min-h-[70px]"
              placeholder="Detail reasons necessitating this containment action..."
              value={justification}
              onChange={(e) => setJustification(e.target.value)}
              required
            />
          </div>

          <div className="pt-2 flex justify-end gap-2">
            <button
              type="button"
              className="btn btn-outline text-xs"
              onClick={() => setShowCreateModal(false)}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="btn btn-primary text-xs"
            >
              Submit for Policy Evaluation
            </button>
          </div>
        </form>
      </ActionModal>

      {/* Operator Attestation Modal */}
      <ActionModal
        isOpen={showAttestModal}
        onClose={() => setShowAttestModal(false)}
        title="Operator Attestation for Quarantined Item"
        subtitle="Attest resolution of divergent or quarantined entity"
      >
        <form onSubmit={handleAttest} className="space-y-4 text-xs">
          <div>
            <label className="form-label">Target URN</label>
            <input
              type="text"
              className="form-input text-xs font-mono"
              placeholder="urn:bsea:candidate_session:sess_123"
              value={attestUrn}
              onChange={(e) => setAttestUrn(e.target.value)}
              required
            />
          </div>

          <div>
            <label className="form-label">Attestation Notes</label>
            <textarea
              className="form-input text-xs min-h-[80px]"
              placeholder="Detail manual inspection findings and justification for release..."
              value={attestNote}
              onChange={(e) => setAttestNote(e.target.value)}
              required
            />
          </div>

          <div className="pt-2 flex justify-end gap-2">
            <button
              type="button"
              className="btn btn-outline text-xs"
              onClick={() => setShowAttestModal(false)}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="btn btn-primary text-xs"
            >
              Record Attestation
            </button>
          </div>
        </form>
      </ActionModal>

      {/* Quorum Approval Modal Component */}
      <QuorumApprovalModal
        isOpen={showQuorumModal}
        onClose={() => setShowQuorumModal(false)}
        request={selectedRequest}
        onAuthorized={() => {
          setLocalRequests(
            localRequests.map((r) => (r.id === selectedRequest?.id ? { ...r, status: 'AUTHORIZED' } : r))
          );
          setMsg({ type: 'success', text: `Quorum authorization granted for ${selectedRequest?.id}.` });
        }}
      />
    </div>
  );
}
