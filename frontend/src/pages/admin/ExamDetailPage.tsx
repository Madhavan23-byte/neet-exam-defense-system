import React, { useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import {
  FileText, ArrowLeft, Shield, Lock, CheckCircle2,
  AlertCircle, KeyRound, Layers, Sparkles
} from 'lucide-react';
import { examsApi } from '../../services/api';
import StatusBadge from '../../components/ui/StatusBadge';

export default function ExamDetailPage() {
  const { examId } = useParams<{ examId: string }>();
  const queryClient = useQueryClient();
  const [formMsg, setFormMsg] = useState('');

  const { data: exam, isLoading, error } = useQuery({
    queryKey: ['exam-detail', examId],
    queryFn: () => examsApi.get(examId!).then((r) => r.data),
    enabled: !!examId,
  });

  const generateFormsMutation = useMutation({
    mutationFn: () => examsApi.generateForms(examId!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['exam-detail', examId] });
      setFormMsg('Candidate forms generated successfully with randomized option order.');
    },
    onError: (err: any) => {
      setFormMsg(err?.response?.data?.detail || 'Form generation failed');
    },
  });

  if (isLoading) {
    return <div className="py-20 text-center text-xs text-slate-400">Loading examination specifications...</div>;
  }
  if (error || !exam) {
    return <div className="p-4 bg-red-50 text-red-700 text-xs rounded-lg">Examination not found.</div>;
  }

  return (
    <div className="space-y-6">
      {/* Back link */}
      <div>
        <Link to="/admin/exams" className="inline-flex items-center gap-1.5 text-xs text-slate-500 hover:text-amber-700 font-semibold">
          <ArrowLeft className="w-4 h-4" /> Back to Examinations
        </Link>
      </div>

      {/* Main Header */}
      <div className="gov-card-warm flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <h1 className="text-xl font-bold text-[var(--gov-navy-dark)]">{exam.title}</h1>
            <StatusBadge status={exam.status} type="exam" />
          </div>
          <p className="text-xs text-slate-500 font-mono">Exam ID: {exam.id}</p>
        </div>
        <div className="flex items-center gap-2">
          <Link to="/admin/authoring" className="btn btn-outline text-xs">
            Manage Questions
          </Link>
          <Link to="/admin/release" className="btn btn-navy text-xs">
            Quorum Release
          </Link>
        </div>
      </div>

      {formMsg && (
        <div className="p-3 bg-amber-50 border border-amber-200 rounded-lg text-xs text-amber-900 flex items-center gap-2">
          <Sparkles className="w-4 h-4 text-amber-600" />
          <span>{formMsg}</span>
        </div>
      )}

      {/* Details Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="gov-card space-y-3 text-xs md:col-span-2">
          <h2 className="font-bold text-sm text-[var(--gov-navy-dark)] pb-2 border-b border-[var(--gov-border)]">
            Examination Parameters
          </h2>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <span className="text-slate-500 font-semibold">Exam Type:</span>
              <p className="font-bold text-slate-800 mt-0.5">{exam.exam_type || 'CBT'}</p>
            </div>
            <div>
              <span className="text-slate-500 font-semibold">Security Mode:</span>
              <p className="font-bold text-slate-800 mt-0.5">{exam.security_mode}</p>
            </div>
            <div>
              <span className="text-slate-500 font-semibold">Duration:</span>
              <p className="font-bold text-slate-800 mt-0.5">{exam.duration_minutes} minutes</p>
            </div>
            <div>
              <span className="text-slate-500 font-semibold">Required Quorum Approvals:</span>
              <p className="font-bold text-slate-800 mt-0.5">{exam.required_approvals || 1} independent authorities</p>
            </div>
          </div>
        </div>

        {/* Blueprint & Forms Action */}
        <div className="gov-card flex flex-col justify-between text-xs space-y-4">
          <div>
            <h2 className="font-bold text-sm text-[var(--gov-navy-dark)] pb-2 border-b border-[var(--gov-border)] mb-3">
              Candidate Forms Compilation
            </h2>
            <p className="text-slate-600 leading-relaxed text-[11px]">
              Compiles randomized candidate exam forms with integrity hashes and randomized option orders.
            </p>
          </div>

          <button
            onClick={() => generateFormsMutation.mutate()}
            disabled={generateFormsMutation.isPending}
            className="btn btn-amber w-full justify-center text-xs"
          >
            <Layers className="w-4 h-4" />
            {generateFormsMutation.isPending ? 'Compiling Forms...' : 'Generate Candidate Forms'}
          </button>
        </div>
      </div>
    </div>
  );
}
