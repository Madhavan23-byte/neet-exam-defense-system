import React, { useState, useEffect } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import {
  ShieldAlert,
  Flame,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Clock,
  KeyRound,
  FileCheck2,
  Users2,
  Lock,
  Eye,
  Ban,
  Fingerprint,
  RefreshCw,
  Sparkles,
  Info,
  ChevronRight,
  ShieldCheck,
  Building2,
  Terminal,
} from 'lucide-react';
import { breakGlassApi, examsApi } from '../../services/api';
import type {
  BreakGlassRequest,
  BreakGlassScope,
  BreakGlassRequestStatus,
  AssembledPaperResponse,
} from '../../services/api';
import { useAuthStore } from '../../stores/authStore';

export default function BreakGlassCenter() {
  const { user } = useAuthStore();
  const [selectedExamId, setSelectedExamId] = useState('');
  const [statusFilter, setStatusFilter] = useState<BreakGlassRequestStatus | ''>('');
  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [activePaper, setActivePaper] = useState<AssembledPaperResponse | null>(null);
  const [selectedRequestForPaper, setSelectedRequestForPaper] = useState<BreakGlassRequest | null>(null);

  // Modal states
  const [approvalModalReq, setApprovalModalReq] = useState<BreakGlassRequest | null>(null);
  const [rejectionModalReq, setRejectionModalReq] = useState<BreakGlassRequest | null>(null);
  const [revokeModalReq, setRevokeModalReq] = useState<BreakGlassRequest | null>(null);
  const [actionComments, setActionComments] = useState('');
  const [revokeReason, setRevokeReason] = useState('');

  // Form state
  const [formData, setFormData] = useState({
    exam_id: '',
    scope: 'COMPLETE_EXAM_PAPER' as BreakGlassScope,
    form_label: '',
    justification: '',
    incident_id: '',
    requested_duration_minutes: 30,
  });
  const [formError, setFormError] = useState('');

  // Queries
  const { data: exams = [] } = useQuery({
    queryKey: ['exams'],
    queryFn: () => examsApi.list().then((r) => r.data),
  });

  const {
    data: requests = [],
    refetch: refetchRequests,
    isFetching,
  } = useQuery({
    queryKey: ['break-glass-requests', selectedExamId, statusFilter],
    queryFn: () =>
      breakGlassApi
        .listRequests(
          selectedExamId || undefined,
          statusFilter ? (statusFilter as BreakGlassRequestStatus) : undefined
        )
        .then((r) => r.data),
    refetchInterval: 6000,
  });

  // Mutations
  const createMutation = useMutation({
    mutationFn: (data: typeof formData) =>
      breakGlassApi.createRequest({
        ...data,
        form_label: data.scope === 'EXAM_FORM_PREVIEW' ? data.form_label : undefined,
      }),
    onSuccess: () => {
      setIsCreateOpen(false);
      setFormData({
        exam_id: '',
        scope: 'COMPLETE_EXAM_PAPER',
        form_label: '',
        justification: '',
        incident_id: '',
        requested_duration_minutes: 30,
      });
      setFormError('');
      refetchRequests();
    },
    onError: (err: any) => {
      setFormError(err.response?.data?.detail || 'Failed to create break-glass request');
    },
  });

  const approveMutation = useMutation({
    mutationFn: ({ id, comments }: { id: string; comments?: string }) =>
      breakGlassApi.approveRequest(id, comments),
    onSuccess: () => {
      setApprovalModalReq(null);
      setActionComments('');
      refetchRequests();
    },
  });

  const rejectMutation = useMutation({
    mutationFn: ({ id, comments }: { id: string; comments?: string }) =>
      breakGlassApi.rejectRequest(id, comments),
    onSuccess: () => {
      setRejectionModalReq(null);
      setActionComments('');
      refetchRequests();
    },
  });

  const activateMutation = useMutation({
    mutationFn: (id: string) => breakGlassApi.activateRequest(id),
    onSuccess: () => {
      refetchRequests();
    },
  });

  const revokeMutation = useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      breakGlassApi.revokeRequest(id, reason),
    onSuccess: () => {
      setRevokeModalReq(null);
      setRevokeReason('');
      if (activePaper) setActivePaper(null);
      refetchRequests();
    },
  });

  const fetchPaperMutation = useMutation({
    mutationFn: (req: BreakGlassRequest) =>
      breakGlassApi.getAssembledPaper(req.id).then((r) => {
        setActivePaper(r.data);
        setSelectedRequestForPaper(req);
      }),
  });

  // Countdown timer helper
  const [timeLeftMap, setTimeLeftMap] = useState<Record<string, string>>({});

  useEffect(() => {
    const timer = setInterval(() => {
      const now = new Date().getTime();
      const updated: Record<string, string> = {};

      requests.forEach((req) => {
        if (req.status === 'ACTIVATED' && req.expires_at) {
          const exp = new Date(req.expires_at).getTime();
          const diff = exp - now;
          if (diff <= 0) {
            updated[req.id] = 'EXPIRED';
          } else {
            const mins = Math.floor(diff / 60000);
            const secs = Math.floor((diff % 60000) / 1000);
            updated[req.id] = `${mins}m ${secs < 10 ? '0' : ''}${secs}s`;
          }
        }
      });
      setTimeLeftMap(updated);
    }, 1000);

    return () => clearInterval(timer);
  }, [requests]);

  const handleCreateSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!formData.exam_id) {
      setFormError('Examination selection is required');
      return;
    }
    if (formData.justification.trim().length < 20) {
      setFormError('Mandatory justification must be at least 20 characters');
      return;
    }
    if (formData.scope === 'EXAM_FORM_PREVIEW' && !formData.form_label.trim()) {
      setFormError('Form label is mandatory when scope is EXAM_FORM_PREVIEW');
      return;
    }
    createMutation.mutate(formData);
  };

  const isEligibleApprover = [
    'SUPER_ADMIN',
    'EXAM_AUTHORITY',
    'SECURITY_OFFICER',
    'RELEASE_AUTHORITY',
  ].includes(user?.role || '');

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-8">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-blue-900/20 pb-6">
        <div>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-amber-500/10 border border-amber-500/30 flex items-center justify-center">
              <Flame className="w-6 h-6 text-amber-400" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white flex items-center gap-2">
                Break-Glass Operations Center
                <span className="text-xs px-2.5 py-0.5 rounded-full font-mono bg-amber-500/20 text-amber-300 border border-amber-500/30">
                  Phase 3B
                </span>
              </h1>
              <p className="text-slate-400 text-sm mt-0.5">
                Emergency multi-party quorum authorization for ephemeral complete-paper inspection
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => refetchRequests()}
            className="p-2 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors"
            title="Refresh requests"
          >
            <RefreshCw className={`w-4 h-4 ${isFetching ? 'animate-spin text-blue-400' : ''}`} />
          </button>
          <button
            onClick={() => setIsCreateOpen(true)}
            className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-amber-600 to-red-600 hover:from-amber-500 hover:to-red-500 text-white font-medium text-sm rounded-lg shadow-lg shadow-amber-900/20 transition-all cursor-pointer"
          >
            <Flame className="w-4 h-4" />
            Emergency Request
          </button>
        </div>
      </div>

      {/* Security Architecture Invariant Callout */}
      <div className="p-4 rounded-xl border border-amber-500/20 bg-amber-950/10 grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
        <div className="flex gap-3">
          <ShieldAlert className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
          <div>
            <span className="font-semibold text-amber-300 block">Server-Side No-Persistent-Plaintext Invariant</span>
            <span className="text-slate-400">
              Plaintext questions are decrypted strictly in process memory and never written to PostgreSQL, Redis,
              disk, or audit logs.
            </span>
          </div>
        </div>
        <div className="flex gap-3">
          <Lock className="w-5 h-5 text-purple-400 shrink-0 mt-0.5" />
          <div>
            <span className="font-semibold text-purple-300 block">Strict Answer-Key Isolation</span>
            <span className="text-slate-400">
              AnswerKey table is never queried. Evaluation metadata and correct options remain completely excluded from
              all responses.
            </span>
          </div>
        </div>
        <div className="flex gap-3">
          <Fingerprint className="w-5 h-5 text-blue-400 shrink-0 mt-0.5" />
          <div>
            <span className="font-semibold text-blue-300 block">Attribution Dynamic Watermark</span>
            <span className="text-slate-400">
              Every assembled render is bound to requester identity, session JTI, and UTC timestamps with per-read
              tamper-evident audit.
            </span>
          </div>
        </div>
      </div>

      {/* Filter Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-4 bg-slate-900/40 p-4 rounded-xl border border-slate-800">
        <div className="flex items-center gap-3 flex-wrap">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Exam:</span>
          <select
            className="form-input text-xs py-1.5 px-3 w-56 bg-slate-950 border-slate-800 text-slate-200 rounded-lg"
            value={selectedExamId}
            onChange={(e) => setSelectedExamId(e.target.value)}
          >
            <option value="">All Examinations</option>
            {exams.map((e: any) => (
              <option key={e.id} value={e.id}>
                {e.title}
              </option>
            ))}
          </select>
        </div>

        <div className="flex items-center gap-1 bg-slate-950/60 p-1 rounded-lg border border-slate-800/80">
          {(['', 'PENDING', 'APPROVED', 'ACTIVATED', 'EXPIRED', 'REVOKED', 'REJECTED'] as const).map((st) => (
            <button
              key={st}
              onClick={() => setStatusFilter(st)}
              className={`px-3 py-1 rounded text-xs font-medium transition-all ${
                statusFilter === st
                  ? 'bg-blue-600/30 text-blue-300 border border-blue-500/30 shadow'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              {st === '' ? 'ALL' : st}
            </button>
          ))}
        </div>
      </div>

      {/* Request Cards Grid */}
      <div className="space-y-4">
        {requests.length === 0 ? (
          <div className="text-center py-16 card border border-dashed border-slate-800 rounded-2xl bg-slate-950/20">
            <ShieldCheck className="w-12 h-12 text-slate-600 mx-auto mb-3" />
            <div className="text-base font-semibold text-slate-300">No Break-Glass Requests Found</div>
            <p className="text-slate-500 text-xs mt-1 max-w-md mx-auto">
              Break-glass emergency requests allow strictly controlled, time-bounded, multi-party approved complete-paper
              assembly during verified operational incidents.
            </p>
          </div>
        ) : (
          requests.map((req) => {
            const isRequester = req.requester_id === user?.id;
            const hasApproved = req.approvals.some(
              (a) => a.approver_id === user?.id && a.decision === 'APPROVE' && a.is_valid
            );
            const remaining = timeLeftMap[req.id];

            return (
              <div
                key={req.id}
                className={`card p-6 border rounded-2xl transition-all ${
                  req.status === 'ACTIVATED'
                    ? 'border-emerald-500/40 bg-emerald-950/10 shadow-lg shadow-emerald-950/20'
                    : req.status === 'APPROVED'
                    ? 'border-blue-500/40 bg-blue-950/10'
                    : req.status === 'PENDING'
                    ? 'border-amber-500/30 bg-slate-900/40'
                    : 'border-slate-800 bg-slate-950/40 opacity-75'
                }`}
              >
                <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 border-b border-slate-800/80 pb-4">
                  <div>
                    <div className="flex items-center gap-3 flex-wrap">
                      <span className="font-mono text-xs text-slate-400 bg-slate-800/60 px-2 py-0.5 rounded border border-slate-700">
                        {req.id.substring(0, 8)}...
                      </span>
                      <span
                        className={`text-xs px-2.5 py-0.5 rounded-full font-bold uppercase tracking-wider border ${
                          req.status === 'ACTIVATED'
                            ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30 animate-pulse'
                            : req.status === 'APPROVED'
                            ? 'bg-blue-500/20 text-blue-300 border-blue-500/30'
                            : req.status === 'PENDING'
                            ? 'bg-amber-500/20 text-amber-300 border-amber-500/30'
                            : req.status === 'REJECTED'
                            ? 'bg-red-500/20 text-red-300 border-red-500/30'
                            : req.status === 'REVOKED'
                            ? 'bg-purple-500/20 text-purple-300 border-purple-500/30'
                            : 'bg-slate-700/40 text-slate-400 border-slate-600'
                        }`}
                      >
                        {req.status}
                      </span>
                      <span className="text-xs text-slate-400 flex items-center gap-1">
                        <Clock className="w-3.5 h-3.5 text-slate-500" />
                        {new Date(req.created_at).toLocaleString()}
                      </span>
                      {req.scope === 'EXAM_FORM_PREVIEW' ? (
                        <span className="text-xs bg-indigo-500/20 text-indigo-300 px-2 py-0.5 rounded border border-indigo-500/30">
                          Form: {req.form_label}
                        </span>
                      ) : (
                        <span className="text-xs bg-slate-800 text-slate-300 px-2 py-0.5 rounded border border-slate-700">
                          Scope: Complete Paper
                        </span>
                      )}
                    </div>
                    <div className="text-sm font-semibold text-white mt-2 flex items-center gap-2">
                      <span>Exam ID: {req.exam_id}</span>
                      <span className="text-xs text-slate-500 font-mono">(v{req.exam_version})</span>
                    </div>
                  </div>

                  {/* Right side status / timer */}
                  <div className="flex items-center gap-4">
                    {req.status === 'ACTIVATED' && (
                      <div className="bg-emerald-950/60 border border-emerald-500/30 px-4 py-2 rounded-xl text-center">
                        <div className="text-xs text-emerald-400 font-medium uppercase tracking-wider flex items-center gap-1.5 justify-center">
                          <Clock className="w-3.5 h-3.5 animate-spin" />
                          Session Active
                        </div>
                        <div className="text-base font-mono font-bold text-emerald-300">
                          {remaining || 'Active'}
                        </div>
                      </div>
                    )}

                    {/* Action Buttons */}
                    <div className="flex items-center gap-2 flex-wrap">
                      {req.status === 'PENDING' && (
                        <>
                          {isRequester ? (
                            <span className="text-xs text-amber-400 bg-amber-500/10 px-3 py-1.5 rounded-lg border border-amber-500/20">
                              Requester (Awaiting Approvers)
                            </span>
                          ) : isEligibleApprover && !hasApproved ? (
                            <>
                              <button
                                onClick={() => setApprovalModalReq(req)}
                                className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all shadow cursor-pointer"
                              >
                                <CheckCircle2 className="w-3.5 h-3.5" />
                                Approve
                              </button>
                              <button
                                onClick={() => setRejectionModalReq(req)}
                                className="px-3 py-1.5 bg-red-600/80 hover:bg-red-600 text-white rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all shadow cursor-pointer"
                              >
                                <XCircle className="w-3.5 h-3.5" />
                                Reject
                              </button>
                            </>
                          ) : hasApproved ? (
                            <span className="text-xs text-emerald-400 bg-emerald-500/10 px-3 py-1.5 rounded-lg border border-emerald-500/20 flex items-center gap-1">
                              <CheckCircle2 className="w-3.5 h-3.5" /> Approved by You
                            </span>
                          ) : null}
                        </>
                      )}

                      {req.status === 'APPROVED' && (
                        <>
                          {isRequester ? (
                            <button
                              onClick={() => activateMutation.mutate(req.id)}
                              disabled={activateMutation.isPending}
                              className="px-4 py-2 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white rounded-lg text-xs font-bold flex items-center gap-2 shadow-lg shadow-blue-900/20 transition-all cursor-pointer"
                            >
                              <KeyRound className="w-4 h-4" />
                              Activate Ephemeral Session
                            </button>
                          ) : (
                            <span className="text-xs text-blue-400 bg-blue-500/10 px-3 py-1.5 rounded-lg border border-blue-500/20">
                              Quorum Achieved (Awaiting Requester Activation)
                            </span>
                          )}
                        </>
                      )}

                      {req.status === 'ACTIVATED' && (
                        <>
                          {isRequester && (
                            <button
                              onClick={() => fetchPaperMutation.mutate(req)}
                              disabled={fetchPaperMutation.isPending}
                              className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-xs font-bold flex items-center gap-2 shadow-lg shadow-emerald-900/30 transition-all cursor-pointer"
                            >
                              <Eye className="w-4 h-4" />
                              Inspect Paper (Ephemeral)
                            </button>
                          )}
                          <button
                            onClick={() => setRevokeModalReq(req)}
                            className="px-3 py-1.5 bg-red-950/60 hover:bg-red-900 border border-red-800 text-red-300 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all cursor-pointer"
                          >
                            <Ban className="w-3.5 h-3.5" />
                            Revoke
                          </button>
                        </>
                      )}
                    </div>
                  </div>
                </div>

                {/* Quorum Progress Tracker & Justification */}
                <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Left: Quorum Status */}
                  <div className="p-3.5 rounded-xl bg-slate-900/50 border border-slate-800/80 space-y-2.5">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-slate-300 flex items-center gap-1.5">
                        <Users2 className="w-4 h-4 text-blue-400" />
                        Multi-Party Quorum & Role Diversity
                      </span>
                      <span className="font-mono text-xs text-slate-400">
                        Fingerprint: {req.content_fingerprint.substring(0, 10)}...
                      </span>
                    </div>

                    <div className="grid grid-cols-2 gap-3 pt-1">
                      {/* Headcount */}
                      <div className="p-2 rounded-lg bg-slate-950/60 border border-slate-800">
                        <div className="text-[11px] text-slate-400 font-medium">Headcount Quorum</div>
                        <div className="flex items-center gap-2 mt-1">
                          <div className="text-sm font-bold text-white">
                            {req.approvals_count} / {req.required_quorum}
                          </div>
                          {req.approvals_count >= req.required_quorum ? (
                            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                          ) : (
                            <Clock className="w-4 h-4 text-amber-400" />
                          )}
                        </div>
                      </div>

                      {/* Role Diversity */}
                      <div className="p-2 rounded-lg bg-slate-950/60 border border-slate-800">
                        <div className="text-[11px] text-slate-400 font-medium">Role Diversity</div>
                        <div className="flex items-center gap-2 mt-1">
                          <div className="text-sm font-bold text-white">
                            {req.distinct_roles_count} / {req.min_distinct_roles} classes
                          </div>
                          {req.distinct_roles_count >= req.min_distinct_roles ? (
                            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                          ) : (
                            <Clock className="w-4 h-4 text-amber-400" />
                          )}
                        </div>
                      </div>
                    </div>

                    {/* Approvers list */}
                    {req.approvals.length > 0 && (
                      <div className="pt-1 flex flex-wrap gap-1.5">
                        {req.approvals.map((a) => (
                          <span
                            key={a.id}
                            className={`text-[11px] px-2 py-0.5 rounded font-medium border flex items-center gap-1 ${
                              a.decision === 'APPROVE'
                                ? 'bg-emerald-950/50 text-emerald-300 border-emerald-800/60'
                                : 'bg-red-950/50 text-red-300 border-red-800/60'
                            }`}
                          >
                            <span className="w-1.5 h-1.5 rounded-full bg-current" />
                            {a.approver_role}: {a.decision}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Right: Justification & Metadata */}
                  <div className="p-3.5 rounded-xl bg-slate-900/50 border border-slate-800/80 space-y-2">
                    <span className="text-xs font-bold text-slate-300 block">Emergency Justification:</span>
                    <p className="text-xs text-slate-300 bg-slate-950/60 p-2.5 rounded-lg border border-slate-800/80 leading-relaxed font-mono">
                      "{req.justification}"
                    </p>
                    <div className="flex items-center justify-between text-[11px] text-slate-500 pt-1">
                      <span>Requester: {req.requester_id.substring(0, 8)}...</span>
                      <span>Duration: {req.requested_duration_minutes} mins</span>
                      {req.incident_id && <span>Incident: {req.incident_id}</span>}
                    </div>
                  </div>
                </div>

                {/* Revocation Details (if revoked) */}
                {req.status === 'REVOKED' && req.revocation_reason && (
                  <div className="mt-3 p-3 rounded-lg bg-red-950/20 border border-red-900/30 text-xs text-red-300 flex items-center gap-2">
                    <Ban className="w-4 h-4 text-red-400 shrink-0" />
                    <span>
                      <strong>Revocation Reason:</strong> {req.revocation_reason} (at{' '}
                      {req.revoked_at ? new Date(req.revoked_at).toLocaleString() : 'N/A'})
                    </span>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>

      {/* CREATE EMERGENCY REQUEST MODAL */}
      {isCreateOpen && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="card-elevated max-w-xl w-full border border-amber-500/30 p-6 space-y-6 animate-in fade-in zoom-in-95">
            <div className="flex items-center justify-between border-b border-slate-800 pb-4">
              <div className="flex items-center gap-2 text-amber-400 font-bold text-lg">
                <Flame className="w-5 h-5" />
                <span>Create Break-Glass Emergency Request</span>
              </div>
              <button
                onClick={() => setIsCreateOpen(false)}
                className="text-slate-400 hover:text-white p-1 rounded-lg"
              >
                ✕
              </button>
            </div>

            {formError && (
              <div className="p-3 bg-red-950/60 border border-red-800 text-red-300 rounded-lg text-xs flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>{formError}</span>
              </div>
            )}

            <form onSubmit={handleCreateSubmit} className="space-y-4">
              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1">
                  Examination <span className="text-red-400">*</span>
                </label>
                <select
                  className="form-input w-full"
                  value={formData.exam_id}
                  onChange={(e) => setFormData({ ...formData, exam_id: e.target.value })}
                  required
                >
                  <option value="">Select target examination...</option>
                  {exams.map((e: any) => (
                    <option key={e.id} value={e.id}>
                      {e.title} ({e.status})
                    </option>
                  ))}
                </select>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="text-xs font-semibold text-slate-300 block mb-1">Scope</label>
                  <select
                    className="form-input w-full"
                    value={formData.scope}
                    onChange={(e) =>
                      setFormData({
                        ...formData,
                        scope: e.target.value as BreakGlassScope,
                      })
                    }
                  >
                    <option value="COMPLETE_EXAM_PAPER">Complete Exam Paper</option>
                    <option value="EXAM_FORM_PREVIEW">Exam Form Preview</option>
                  </select>
                </div>

                <div>
                  <label className="text-xs font-semibold text-slate-300 block mb-1">
                    Duration (10-60 mins)
                  </label>
                  <input
                    type="number"
                    min={10}
                    max={60}
                    className="form-input w-full"
                    value={formData.requested_duration_minutes}
                    onChange={(e) =>
                      setFormData({
                        ...formData,
                        requested_duration_minutes: parseInt(e.target.value) || 30,
                      })
                    }
                  />
                </div>
              </div>

              {formData.scope === 'EXAM_FORM_PREVIEW' && (
                <div>
                  <label className="text-xs font-semibold text-slate-300 block mb-1">
                    Form Label <span className="text-red-400">*</span>
                  </label>
                  <input
                    type="text"
                    placeholder="e.g. FORM_A"
                    className="form-input w-full"
                    value={formData.form_label}
                    onChange={(e) => setFormData({ ...formData, form_label: e.target.value })}
                  />
                </div>
              )}

              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1">
                  Mandatory Operational Justification (min 20 chars) <span className="text-red-400">*</span>
                </label>
                <textarea
                  rows={3}
                  placeholder="Explain why break-glass complete paper assembly is operationally essential..."
                  className="form-input w-full font-mono text-xs"
                  value={formData.justification}
                  onChange={(e) => setFormData({ ...formData, justification: e.target.value })}
                  required
                />
              </div>

              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1">Incident ID (Optional)</label>
                <input
                  type="text"
                  placeholder="INC-2026-XXXX"
                  className="form-input w-full"
                  value={formData.incident_id}
                  onChange={(e) => setFormData({ ...formData, incident_id: e.target.value })}
                />
              </div>

              <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-[11px] text-slate-400 space-y-1">
                <div className="font-semibold text-slate-300">Policy Constraints:</div>
                <div>• Quorum Required: 2 distinct authorities</div>
                <div>• Role Diversity Required: At least 2 distinct role classes</div>
                <div>• Fresh session binding required at activation</div>
              </div>

              <div className="flex items-center justify-end gap-3 pt-4 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setIsCreateOpen(false)}
                  className="px-4 py-2 rounded-lg text-xs text-slate-400 hover:text-white"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={createMutation.isPending}
                  className="px-5 py-2 bg-gradient-to-r from-amber-600 to-red-600 hover:from-amber-500 hover:to-red-500 text-white font-bold text-xs rounded-lg shadow-lg cursor-pointer"
                >
                  {createMutation.isPending ? 'Submitting...' : 'Submit Emergency Request'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* APPROVAL CONFIRMATION MODAL */}
      {approvalModalReq && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="card-elevated max-w-md w-full border border-emerald-500/30 p-6 space-y-4">
            <div className="flex items-center gap-3 text-emerald-400 font-bold text-lg">
              <CheckCircle2 className="w-5 h-5" />
              <span>Submit Signed Cryptographic Approval</span>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed">
              You are voting to authorize break-glass access for Request ID{' '}
              <span className="font-mono text-emerald-300">{approvalModalReq.id.substring(0, 8)}...</span>.
              This action will be digitally signed using your role credentials and recorded into the tamper-evident audit
              log.
            </p>

            <div>
              <label className="text-xs font-semibold text-slate-300 block mb-1">Approval Comments (Optional)</label>
              <textarea
                rows={2}
                placeholder="Operational validation verified..."
                className="form-input w-full text-xs"
                value={actionComments}
                onChange={(e) => setActionComments(e.target.value)}
              />
            </div>

            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                onClick={() => setApprovalModalReq(null)}
                className="px-3 py-1.5 text-xs text-slate-400 hover:text-white"
              >
                Cancel
              </button>
              <button
                onClick={() =>
                  approveMutation.mutate({
                    id: approvalModalReq.id,
                    comments: actionComments,
                  })
                }
                disabled={approveMutation.isPending}
                className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold rounded-lg cursor-pointer shadow"
              >
                {approveMutation.isPending ? 'Signing...' : 'Sign & Approve'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* TERMINAL REJECTION MODAL */}
      {rejectionModalReq && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="card-elevated max-w-md w-full border border-red-500/30 p-6 space-y-4">
            <div className="flex items-center gap-3 text-red-400 font-bold text-lg">
              <XCircle className="w-5 h-5" />
              <span>Terminal Rejection of Break-Glass Request</span>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed">
              Warning: A single rejection permanently transitions the request to terminal{' '}
              <strong className="text-red-400">REJECTED</strong>. It can never become approved.
            </p>

            <div>
              <label className="text-xs font-semibold text-slate-300 block mb-1">Rejection Comments</label>
              <textarea
                rows={2}
                placeholder="Reason for rejecting emergency access..."
                className="form-input w-full text-xs"
                value={actionComments}
                onChange={(e) => setActionComments(e.target.value)}
              />
            </div>

            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                onClick={() => setRejectionModalReq(null)}
                className="px-3 py-1.5 text-xs text-slate-400 hover:text-white"
              >
                Cancel
              </button>
              <button
                onClick={() =>
                  rejectMutation.mutate({
                    id: rejectionModalReq.id,
                    comments: actionComments,
                  })
                }
                disabled={rejectMutation.isPending}
                className="px-4 py-2 bg-red-600 hover:bg-red-500 text-white text-xs font-bold rounded-lg cursor-pointer shadow"
              >
                {rejectMutation.isPending ? 'Rejecting...' : 'Confirm Terminal Reject'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* EMERGENCY REVOCATION MODAL */}
      {revokeModalReq && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="card-elevated max-w-md w-full border border-red-500/40 p-6 space-y-4">
            <div className="flex items-center gap-3 text-red-400 font-bold text-lg">
              <Ban className="w-5 h-5" />
              <span>Explicit Break-Glass Revocation</span>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed">
              Explicit revocation immediately and permanently prevents all subsequent server-authorized access and
              invalidates all prior approvals.
            </p>

            <div>
              <label className="text-xs font-semibold text-slate-300 block mb-1">
                Revocation Reason <span className="text-red-400">*</span>
              </label>
              <textarea
                rows={2}
                placeholder="Security incident resolved / premature termination..."
                className="form-input w-full text-xs"
                value={revokeReason}
                onChange={(e) => setRevokeReason(e.target.value)}
                required
              />
            </div>

            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                onClick={() => setRevokeModalReq(null)}
                className="px-3 py-1.5 text-xs text-slate-400 hover:text-white"
              >
                Cancel
              </button>
              <button
                onClick={() => {
                  if (!revokeReason.trim()) return;
                  revokeMutation.mutate({
                    id: revokeModalReq.id,
                    reason: revokeReason,
                  });
                }}
                disabled={revokeMutation.isPending || !revokeReason.trim()}
                className="px-4 py-2 bg-red-600 hover:bg-red-500 text-white text-xs font-bold rounded-lg cursor-pointer shadow"
              >
                {revokeMutation.isPending ? 'Revoking...' : 'Revoke Immediately'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* EPHEMERAL ASSEMBLED PAPER INSPECTION VIEW */}
      {activePaper && (
        <div className="fixed inset-0 z-50 bg-black/90 backdrop-blur-md flex flex-col p-4 md:p-8 overflow-hidden">
          {/* Viewer Top Bar */}
          <div className="flex items-center justify-between pb-4 border-b border-slate-800 bg-slate-950/80 px-6 py-4 rounded-t-2xl">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-lg bg-emerald-500/20 border border-emerald-500/30 flex items-center justify-center">
                <FileCheck2 className="w-5 h-5 text-emerald-400" />
              </div>
              <div>
                <h2 className="text-lg font-bold text-white flex items-center gap-2">
                  {activePaper.exam_title}
                  <span className="text-xs bg-emerald-500/20 text-emerald-300 px-2 py-0.5 rounded border border-emerald-500/30 font-mono">
                    {activePaper.question_count} Questions
                  </span>
                </h2>
                <p className="text-xs text-slate-400">
                  Ephemeral in-memory paper assembly • Answer keys isolated • Forensic dynamic watermark active
                </p>
              </div>
            </div>

            <div className="flex items-center gap-4">
              {selectedRequestForPaper && (
                <button
                  onClick={() => setRevokeModalReq(selectedRequestForPaper)}
                  className="px-3 py-1.5 bg-red-950/80 hover:bg-red-900 border border-red-800 text-red-300 rounded-lg text-xs font-semibold flex items-center gap-1.5 transition-all cursor-pointer"
                >
                  <Ban className="w-3.5 h-3.5" />
                  Emergency Revoke
                </button>
              )}
              <button
                onClick={() => setActivePaper(null)}
                className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg transition-all cursor-pointer"
              >
                Close Viewer
              </button>
            </div>
          </div>

          {/* Forensic Dynamic Watermark Banner */}
          <div className="bg-amber-950/40 border-x border-b border-amber-500/30 px-6 py-2.5 flex flex-wrap items-center justify-between text-[11px] font-mono text-amber-300">
            <div className="flex items-center gap-4">
              <span>ACTOR: {activePaper.attribution_watermark.requester_username}</span>
              <span>SESSION JTI: {activePaper.attribution_watermark.activation_session_id.substring(0, 12)}...</span>
              <span>ASSEMBLED UTC: {activePaper.attribution_watermark.assembled_at_utc}</span>
            </div>
            <div className="text-amber-400 font-semibold">{activePaper.attribution_watermark.security_notice}</div>
          </div>

          {/* Content Area with Watermark Overlay */}
          <div className="relative flex-1 overflow-y-auto p-6 md:p-10 bg-slate-950/60 border-x border-b border-slate-800 rounded-b-2xl">
            {/* Dynamic Watermark Pattern Overlay */}
            <div className="pointer-events-none absolute inset-0 select-none overflow-hidden opacity-[0.06] flex flex-col justify-around rotate-[-20deg]">
              {Array.from({ length: 8 }).map((_, i) => (
                <div key={i} className="whitespace-nowrap text-3xl font-black text-red-500 font-mono text-center">
                  CONFIDENTIAL • {activePaper.attribution_watermark.requester_username} •{' '}
                  {activePaper.attribution_watermark.request_id} • FORENSIC ATTRIBUTION
                </div>
              ))}
            </div>

            {/* Questions list */}
            <div className="max-w-4xl mx-auto space-y-6 relative z-10">
              {activePaper.questions.map((q, idx) => (
                <div key={q.id} className="card p-6 border border-slate-800 rounded-xl space-y-4 bg-slate-900/60">
                  <div className="flex items-center justify-between text-xs border-b border-slate-800/80 pb-3">
                    <span className="font-bold text-blue-400">Question {idx + 1}</span>
                    <div className="flex items-center gap-2">
                      <span className="bg-slate-800 px-2 py-0.5 rounded text-slate-300">{q.subject}</span>
                      {q.section && <span className="bg-slate-800 px-2 py-0.5 rounded text-slate-400">{q.section}</span>}
                      <span className="bg-blue-900/30 text-blue-300 px-2 py-0.5 rounded border border-blue-800/40">
                        {q.marks} Marks
                      </span>
                    </div>
                  </div>

                  <div className="text-sm font-medium text-slate-200 leading-relaxed font-sans">{q.content}</div>

                  {q.options && q.options.length > 0 && (
                    <div className="space-y-2 pt-2">
                      {q.options.map((opt, oIdx) => (
                        <div
                          key={oIdx}
                          className="flex items-center gap-3 p-3 rounded-lg border border-slate-800/70 bg-slate-950/40 text-xs text-slate-300"
                        >
                          <span className="w-5 h-5 rounded-full bg-slate-800 text-slate-400 flex items-center justify-center font-bold text-[10px]">
                            {String.fromCharCode(65 + oIdx)}
                          </span>
                          <span>{opt}</span>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Defense-in-depth indicator */}
                  <div className="pt-2 border-t border-slate-800/60 flex items-center justify-between text-[10px] text-slate-500 font-mono">
                    <span>ID: {q.id}</span>
                    <span className="text-emerald-500 flex items-center gap-1">
                      <CheckCircle2 className="w-3 h-3" /> Answer Key Isolated
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
