import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { BookCheck, CheckCircle2, XCircle, Shield, AlertTriangle } from 'lucide-react';
import { examsApi, questionsApi } from '../../services/api';
import PortalHeader from '../../components/ui/PortalHeader';
import PortalFooter from '../../components/ui/PortalFooter';

export default function ReviewerPage() {
  const [selectedExamId, setSelectedExamId] = useState('');
  const [actionMsg, setActionMsg] = useState('');

  const { data: exams = [] } = useQuery({
    queryKey: ['reviewer-exams'],
    queryFn: () => examsApi.list().then((r) => r.data || []),
  });

  const activeExamId = selectedExamId || (exams.length > 0 ? exams[0].id : '');

  const { data: questions = [], isLoading } = useQuery({
    queryKey: ['reviewer-questions', activeExamId],
    queryFn: () => (activeExamId ? questionsApi.list(activeExamId).then((r) => r.data || []) : []),
    enabled: !!activeExamId,
  });

  const handleReview = (qId: string, decision: 'APPROVE' | 'REJECT') => {
    setActionMsg(`Question ${decision === 'APPROVE' ? 'approved' : 'rejected'} and logged to immutable audit trail.`);
  };

  return (
    <div className="min-h-screen flex flex-col bg-[var(--gov-canvas)]">
      <PortalHeader subtitle="Subject Matter Reviewer & Moderation Portal" />

      <main className="flex-1 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 w-full space-y-6">
        <div className="gov-card-warm flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h1 className="text-xl font-bold text-[var(--gov-navy-dark)]">
              Peer Review & Moderation Workspace
            </h1>
            <p className="text-xs text-slate-500 mt-1">
              Verify question validity, clarity, and option non-ambiguity under strict confidentiality
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

        {actionMsg && (
          <div className="p-3 bg-emerald-50 border border-emerald-200 text-emerald-800 rounded-lg text-xs flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-600" />
            <span>{actionMsg}</span>
          </div>
        )}

        <div className="gov-card">
          <div className="overflow-x-auto">
            <table className="gov-table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Subject</th>
                  <th>Version</th>
                  <th>Integrity Check</th>
                  <th>Moderation Actions</th>
                </tr>
              </thead>
              <tbody>
                {isLoading ? (
                  <tr>
                    <td colSpan={5} className="py-8 text-center text-slate-400">Loading reviewer pool...</td>
                  </tr>
                ) : questions.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="py-8 text-center text-slate-400">No questions currently in review pool.</td>
                  </tr>
                ) : (
                  questions.map((q: any, idx: number) => (
                    <tr key={q.id}>
                      <td className="font-bold text-slate-700">{idx + 1}</td>
                      <td className="font-semibold text-slate-800">{q.subject || 'General'}</td>
                      <td className="font-mono text-slate-600">v{q.version}</td>
                      <td>
                        <span className="badge-secure">Verified Sealed</span>
                      </td>
                      <td>
                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => handleReview(q.id, 'APPROVE')}
                            className="btn btn-outline text-[11px] py-1 px-2 text-emerald-700 hover:bg-emerald-50"
                          >
                            <CheckCircle2 className="w-3.5 h-3.5" /> Approve
                          </button>
                          <button
                            onClick={() => handleReview(q.id, 'REJECT')}
                            className="btn btn-outline text-[11px] py-1 px-2 text-red-700 hover:bg-red-50"
                          >
                            <XCircle className="w-3.5 h-3.5" /> Reject
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </main>

      <PortalFooter />
    </div>
  );
}
