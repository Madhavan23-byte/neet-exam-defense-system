import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { KeyRound, Shield, CheckCircle2, AlertTriangle, Lock, Unlock, Clock } from 'lucide-react';
import { releaseApi, examsApi } from '../../services/api';
import StatusBadge from '../../components/ui/StatusBadge';

export default function ReleasePage() {
  const queryClient = useQueryClient();
  const [selectedExamId, setSelectedExamId] = useState('');
  const [statusMsg, setStatusMsg] = useState('');

  const { data: exams = [] } = useQuery({
    queryKey: ['release-exams'],
    queryFn: () => examsApi.list().then((r) => r.data || []),
  });

  const activeExamId = selectedExamId || (exams.length > 0 ? exams[0].id : '');

  const { data: statusData, isLoading } = useQuery({
    queryKey: ['release-status', activeExamId],
    queryFn: () => (activeExamId ? releaseApi.getStatus(activeExamId).then((r) => r.data) : null),
    enabled: !!activeExamId,
  });

  const approveMutation = useMutation({
    mutationFn: () => releaseApi.approve(activeExamId),
    onSuccess: (res) => {
      queryClient.invalidateQueries({ queryKey: ['release-status', activeExamId] });
      setStatusMsg('Quorum approval token cryptographically recorded.');
    },
    onError: (err: any) => {
      setStatusMsg(err?.response?.data?.detail || 'Quorum approval failed');
    },
  });

  return (
    <div className="space-y-6">
      <div className="gov-card-warm flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-[var(--gov-navy-dark)]">
            Quorum Release & Time-Locked Cryptography
          </h1>
          <p className="text-xs text-slate-500 mt-1">
            Exam decryption keys require independent cryptographic authorizations from designated authorities
          </p>
        </div>
        <select
          className="form-input text-xs max-w-[240px]"
          value={activeExamId}
          onChange={(e) => setSelectedExamId(e.target.value)}
        >
          {exams.map((ex: any) => (
            <option key={ex.id} value={ex.id}>
              {ex.title}
            </option>
          ))}
        </select>
      </div>

      {statusMsg && (
        <div className="p-3 bg-amber-50 border border-amber-200 text-amber-900 rounded-lg text-xs flex items-center gap-2">
          <KeyRound className="w-4 h-4 text-amber-600" />
          <span>{statusMsg}</span>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="gov-card md:col-span-2 space-y-4">
          <h2 className="font-bold text-sm text-[var(--gov-navy-dark)] pb-2 border-b border-[var(--gov-border)]">
            Release Ceremony Quorum Progress
          </h2>

          <div className="p-4 bg-[var(--gov-surface-warm)] rounded-xl border border-[var(--gov-border)] space-y-3">
            <div className="flex justify-between text-xs">
              <span className="font-semibold text-slate-600">Threshold Required:</span>
              <span className="font-mono font-bold text-slate-800">
                {statusData?.required_approvals || 1} Independent Authorities
              </span>
            </div>
            <div className="flex justify-between text-xs">
              <span className="font-semibold text-slate-600">Approvals Granted:</span>
              <span className="font-mono font-bold text-emerald-700">
                {statusData?.approvals_count || 0}
              </span>
            </div>
            <div className="flex justify-between text-xs">
              <span className="font-semibold text-slate-600">Release Status:</span>
              <StatusBadge status={statusData?.status || 'RELEASE_PENDING_APPROVAL'} type="exam" />
            </div>
          </div>

          <div className="p-3 bg-blue-50/50 border border-blue-200 rounded-lg text-xs text-blue-900 leading-relaxed">
            <p className="font-semibold mb-1">Time-Lock Policy Invariant:</p>
            Plaintext question content cannot be unsealed prior to the scheduled exam start time, even if all quorum approvals are recorded in advance.
          </div>
        </div>

        {/* Action Column */}
        <div className="gov-card flex flex-col justify-between space-y-4">
          <div>
            <h2 className="font-bold text-sm text-[var(--gov-navy-dark)] pb-2 border-b border-[var(--gov-border)] mb-3">
              Authorize Release
            </h2>
            <p className="text-xs text-slate-600 leading-relaxed">
              Submit your cryptographic authorization as an official Release Authority.
            </p>
          </div>

          <button
            onClick={() => approveMutation.mutate()}
            disabled={approveMutation.isPending || !activeExamId}
            className="btn btn-primary w-full justify-center text-xs py-2.5"
          >
            <KeyRound className="w-4 h-4 text-amber-400" />
            {approveMutation.isPending ? 'Signing Release...' : 'Sign Quorum Release'}
          </button>
        </div>
      </div>
    </div>
  );
}
