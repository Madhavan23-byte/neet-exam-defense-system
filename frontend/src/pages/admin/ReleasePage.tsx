import { useQuery, useMutation } from '@tanstack/react-query';
import { releaseApi, examsApi } from '../../services/api';
import { useState } from 'react';
import { Key, CheckCircle, XCircle, Shield, AlertTriangle, Clock } from 'lucide-react';

export default function ReleasePage() {
  const [selectedExamId, setSelectedExamId] = useState('');
  const [freezeReason, setFreezeReason] = useState('');

  const { data: exams = [] } = useQuery({
    queryKey: ['exams'],
    queryFn: () => examsApi.list().then(r => r.data),
  });

  const { data: status, refetch } = useQuery({
    queryKey: ['release-status', selectedExamId],
    queryFn: () => releaseApi.getStatus(selectedExamId).then(r => r.data),
    enabled: !!selectedExamId,
    refetchInterval: 5000,
  });

  const approveMutation = useMutation({
    mutationFn: () => releaseApi.approve(selectedExamId),
    onSuccess: () => refetch(),
  });

  const checkMutation = useMutation({
    mutationFn: () => releaseApi.check(selectedExamId),
    onSuccess: () => refetch(),
  });

  const freezeMutation = useMutation({
    mutationFn: () => releaseApi.freeze(selectedExamId, freezeReason),
    onSuccess: () => refetch(),
  });

  return (
    <div className="p-8">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold text-white">Release Control</h1>
          <p className="text-slate-400 text-sm mt-1">Threshold authorization and time-locked release management</p>
        </div>
        <select
          className="form-input w-72"
          value={selectedExamId}
          onChange={e => setSelectedExamId(e.target.value)}
        >
          <option value="">Select exam...</option>
          {exams.map((e: any) => <option key={e.id} value={e.id}>{e.title}</option>)}
        </select>
      </div>

      {/* Architecture note */}
      <div className="mb-6 p-4 rounded-xl border border-blue-900/20 bg-blue-950/10">
        <div className="flex gap-3">
          <Shield className="w-5 h-5 text-blue-400 shrink-0 mt-0.5" />
          <div className="text-sm text-slate-400">
            <strong className="text-blue-400">Threshold Authorization Model:</strong>{' '}
            Exam release requires simultaneous cryptographic approval from {status?.required_approvals || 'N'} independent
            Release Authorities. No single authority or administrator can trigger release alone.
            All approvals are Ed25519 signed and audit logged. Release is automated — all conditions must pass simultaneously.
          </div>
        </div>
      </div>

      {selectedExamId && status ? (
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
          {/* Conditions panel */}
          <div className="card-elevated">
            <h2 className="font-bold text-white mb-4 flex items-center gap-2">
              <Clock className="w-4 h-4 text-blue-400" />
              Release Conditions
            </h2>

            <div className="space-y-3">
              {Object.entries(status.release_conditions || {}).map(([key, value]) => (
                <div key={key} className="flex items-center justify-between p-3 rounded-lg border border-slate-800/50">
                  <div>
                    <div className="text-sm font-medium text-slate-300">{key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}</div>
                    <div className="text-xs text-slate-500 mt-0.5">
                      {key === 'time_condition' && status.scheduled_start_utc && (
                        `Scheduled: ${new Date(status.scheduled_start_utc).toLocaleString()}`
                      )}
                      {key === 'threshold_condition' && (
                        `${status.received_approvals}/${status.required_approvals} approvals received`
                      )}
                    </div>
                  </div>
                  {value ? (
                    <CheckCircle className="w-5 h-5 text-emerald-400 shrink-0" />
                  ) : (
                    <XCircle className="w-5 h-5 text-red-400 shrink-0" />
                  )}
                </div>
              ))}
            </div>

            <div className={`mt-4 p-3 rounded-lg border text-sm font-semibold text-center ${
              status.all_conditions_met
                ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                : 'bg-slate-800 border-slate-700 text-slate-400'
            }`}>
              {status.all_conditions_met ? '✅ ALL CONDITIONS MET — RELEASE AUTHORIZED' : '⏳ Waiting for conditions...'}
            </div>

            {status.all_conditions_met && (
              <button
                className="btn btn-success w-full justify-center mt-3"
                onClick={() => checkMutation.mutate()}
                disabled={checkMutation.isPending}
              >
                {checkMutation.isPending ? 'Processing...' : 'Trigger Automated Release'}
              </button>
            )}
            {checkMutation.isSuccess && (
              <div className="text-xs text-emerald-400 mt-2 text-center">
                {(checkMutation.data as any)?.data?.released ? '✅ Exam released!' : (checkMutation.data as any)?.data?.reason}
              </div>
            )}
          </div>

          {/* Approval panel */}
          <div className="card-elevated">
            <h2 className="font-bold text-white mb-4 flex items-center gap-2">
              <Key className="w-4 h-4 text-purple-400" />
              Threshold Approvals
            </h2>

            <div className="mb-4">
              <div className="flex justify-between text-xs text-slate-400 mb-1">
                <span>Approvals received</span>
                <span className="font-mono">{status.received_approvals}/{status.required_approvals}</span>
              </div>
              <div className="h-3 bg-slate-800 rounded-full overflow-hidden">
                <div
                  className={`h-full transition-all rounded-full ${
                    status.received_approvals >= status.required_approvals
                      ? 'bg-gradient-to-r from-emerald-600 to-emerald-400'
                      : 'bg-gradient-to-r from-blue-600 to-purple-600'
                  }`}
                  style={{ width: `${Math.min(100, (status.received_approvals / status.required_approvals) * 100)}%` }}
                />
              </div>
            </div>

            {/* Approvals list */}
            {(status.approvals || []).map((a: any, i: number) => (
              <div key={i} className="flex items-center gap-2 p-2 rounded-lg bg-emerald-500/5 border border-emerald-500/10 mb-2">
                <CheckCircle className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <div className="text-xs text-slate-400">
                  Authority <span className="font-mono text-slate-300">{a.authority_id.slice(0, 12)}...</span>
                  · {new Date(a.approved_at).toLocaleString()}
                </div>
              </div>
            ))}

            <button
              className="btn btn-primary w-full justify-center mt-3"
              onClick={() => approveMutation.mutate()}
              disabled={approveMutation.isPending}
            >
              <Key className="w-4 h-4" />
              {approveMutation.isPending ? 'Signing Approval...' : 'Submit My Approval'}
            </button>

            {approveMutation.isSuccess && (
              <div className="text-xs text-emerald-400 mt-2 text-center">✅ Approval signed and recorded</div>
            )}
            {approveMutation.isError && (
              <div className="text-xs text-red-400 mt-2 text-center">
                {(approveMutation.error as any)?.response?.data?.detail}
              </div>
            )}

            {/* Emergency Freeze */}
            <div className="mt-6 pt-5 border-t border-red-900/20">
              <div className="badge-critical mb-3">Emergency Freeze</div>
              <input
                className="form-input mb-2 text-sm"
                placeholder="Reason for freeze..."
                value={freezeReason}
                onChange={e => setFreezeReason(e.target.value)}
              />
              <button
                className="btn btn-danger w-full justify-center text-sm"
                onClick={() => freezeMutation.mutate()}
                disabled={!freezeReason || freezeMutation.isPending}
              >
                <AlertTriangle className="w-4 h-4" />
                {freezeMutation.isPending ? 'Freezing...' : 'Emergency Freeze Release'}
              </button>
            </div>
          </div>
        </div>
      ) : (
        <div className="card text-center py-16">
          <Key className="w-12 h-12 text-slate-600 mx-auto mb-4" />
          <div className="text-slate-400">Select an exam to manage its release</div>
        </div>
      )}
    </div>
  );
}
