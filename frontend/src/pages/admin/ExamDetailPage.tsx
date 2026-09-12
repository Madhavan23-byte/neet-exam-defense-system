import { useParams } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { examsApi, releaseApi, questionsApi } from '../../services/api';
import { Shield, Lock, CheckCircle, XCircle, Clock, FileText, Key } from 'lucide-react';

export default function ExamDetailPage() {
  const { examId } = useParams<{ examId: string }>();
  const qc = useQueryClient();

  const { data: exam } = useQuery({
    queryKey: ['exam', examId],
    queryFn: () => examsApi.get(examId!).then(r => r.data),
  });

  const { data: releaseStatus, refetch: refetchRelease } = useQuery({
    queryKey: ['release-status', examId],
    queryFn: () => releaseApi.getStatus(examId!).then(r => r.data),
    refetchInterval: 5000,
  });

  const { data: questions = [] } = useQuery({
    queryKey: ['questions', examId],
    queryFn: () => questionsApi.list(examId!).then(r => r.data),
  });

  const approveMutation = useMutation({
    mutationFn: () => releaseApi.approve(examId!),
    onSuccess: () => refetchRelease(),
  });

  const generateFormsMutation = useMutation({
    mutationFn: () => examsApi.generateForms(examId!),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['exam', examId] }),
  });

  const approveBlueprintMutation = useMutation({
    mutationFn: () => examsApi.approveBlueprint(examId!),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['exam', examId] });
      refetchRelease();
    },
  });

  return (
    <div className="p-8">
      {/* Header */}
      <div className="mb-8">
        <a href="/admin/exams" className="text-xs text-slate-500 hover:text-white mb-2 block">← Back to Exams</a>
        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-2xl font-bold text-white">{exam?.title || 'Loading...'}</h1>
            <div className="flex items-center gap-3 mt-2">
              <span className={`badge-${exam?.status === 'RELEASED' ? 'secure' : exam?.status === 'FROZEN' ? 'critical' : 'info'}`}>
                {exam?.status}
              </span>
              <span className="badge-warning">{exam?.security_mode}</span>
              <span className="text-xs text-slate-500 font-mono">{examId}</span>
            </div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Question bank */}
        <div className="xl:col-span-2 card">
          <div className="flex items-center justify-between mb-4">
            <h2 className="font-bold text-white">Question Bank</h2>
            <span className="text-sm text-slate-500">{questions.length} questions</span>
          </div>
          <div className="space-y-2 max-h-80 overflow-y-auto">
            {questions.map((q: any) => (
              <div key={q.id} className="flex items-center justify-between py-2.5 px-3 rounded-lg border border-slate-800/50 hover:border-slate-700/50 transition-colors">
                <div className="min-w-0">
                  <div className="text-sm font-medium text-slate-300 flex items-center gap-2">
                    {q.subject} — {q.topic || 'General'}
                    {q.has_encrypted_content && <Lock className="w-3 h-3 text-emerald-400" />}
                  </div>
                  <div className="text-xs text-slate-500 mt-0.5">
                    {q.difficulty} · {q.has_encrypted_content ? `Hash: ${(q.integrity_hash || '').slice(0, 12)}...` : 'No hash yet'}
                  </div>
                </div>
                <span className={`badge-${q.status === 'ENCRYPTED' ? 'secure' : q.status === 'REJECTED' ? 'critical' : 'info'} text-xs shrink-0 ml-3`}>
                  {q.status}
                </span>
              </div>
            ))}
            {questions.length === 0 && (
              <div className="text-center py-8 text-slate-500 text-sm">No questions added yet. Go to Authoring.</div>
            )}
          </div>

          <div className="flex gap-3 mt-4 pt-4 border-t border-slate-800">
            <button
              className="btn btn-primary text-sm"
              onClick={() => approveBlueprintMutation.mutate()}
              disabled={approveBlueprintMutation.isPending}
            >
              {approveBlueprintMutation.isPending ? 'Approving...' : 'Approve Blueprint'}
            </button>
            <button
              className="btn btn-ghost text-sm"
              onClick={() => generateFormsMutation.mutate()}
              disabled={generateFormsMutation.isPending || questions.length === 0}
            >
              {generateFormsMutation.isPending ? 'Generating...' : 'Generate Exam Forms'}
            </button>
          </div>
          {generateFormsMutation.isSuccess && (
            <div className="mt-3 p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs">
              ✅ Forms generated. Questions randomized with cryptographically secure shuffle. No plaintext exam paper created.
            </div>
          )}
        </div>

        {/* Release status */}
        <div className="card">
          <div className="flex items-center gap-2 mb-4">
            <Key className="w-4 h-4 text-purple-400" />
            <h2 className="font-bold text-white">Release Control</h2>
          </div>

          {releaseStatus ? (
            <div className="space-y-3">
              <div className="text-xs text-slate-400 font-semibold uppercase tracking-wider mb-2">Release Conditions</div>
              {Object.entries(releaseStatus.release_conditions || {}).map(([key, value]) => (
                <div key={key} className="flex items-center justify-between text-sm">
                  <span className="text-slate-400 text-xs">{key.replace(/_/g, ' ')}</span>
                  {value ? (
                    <CheckCircle className="w-4 h-4 text-emerald-400" />
                  ) : (
                    <XCircle className="w-4 h-4 text-red-400" />
                  )}
                </div>
              ))}

              <div className="mt-4 pt-4 border-t border-slate-800">
                <div className="text-xs text-slate-400 mb-2">
                  Threshold: {releaseStatus.received_approvals}/{releaseStatus.required_approvals}
                </div>
                <div className="h-2 bg-slate-800 rounded-full overflow-hidden mb-3">
                  <div
                    className="h-full bg-gradient-to-r from-blue-600 to-purple-600 transition-all"
                    style={{ width: `${Math.min(100, (releaseStatus.received_approvals / releaseStatus.required_approvals) * 100)}%` }}
                  />
                </div>
                <button
                  className="btn btn-primary w-full justify-center text-sm"
                  onClick={() => approveMutation.mutate()}
                  disabled={approveMutation.isPending}
                >
                  {approveMutation.isPending ? 'Signing...' : 'Submit Approval'}
                </button>
                {approveMutation.isError && (
                  <div className="text-xs text-red-400 mt-2">
                    {(approveMutation.error as any)?.response?.data?.detail || 'Approval failed'}
                  </div>
                )}
                {approveMutation.isSuccess && (
                  <div className="text-xs text-emerald-400 mt-2">✅ Approval submitted and signed</div>
                )}
              </div>
            </div>
          ) : (
            <div className="text-slate-500 text-sm">Loading release status...</div>
          )}
        </div>
      </div>
    </div>
  );
}
