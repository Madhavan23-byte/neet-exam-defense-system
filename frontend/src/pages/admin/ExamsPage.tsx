import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { useState } from 'react';
import { FileText, Plus, ChevronRight, Lock, Shield, Calendar } from 'lucide-react';
import { examsApi } from '../../services/api';

const STATUS_BADGE: Record<string, string> = {
  DRAFT: 'badge-info',
  BLUEPRINT_CREATED: 'badge-purple',
  FORMS_GENERATED: 'badge-purple',
  THRESHOLD_PENDING: 'badge-warning',
  THRESHOLD_APPROVED: 'badge-purple',
  RELEASED: 'badge-secure',
  ONGOING: 'badge-secure',
  COMPLETED: 'badge-info',
  FROZEN: 'badge-critical',
};

function CreateExamModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [form, setForm] = useState({
    title: '',
    description: '',
    exam_type: 'CBT',
    security_mode: 'HIGH',
    scheduled_start_utc: '',
    duration_minutes: 180,
    required_approvals: 3,
  });

  const mutation = useMutation({
    mutationFn: () => examsApi.create(form),
    onSuccess: () => { onCreated(); onClose(); },
  });

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="w-full max-w-lg card-elevated animate-fade-in">
        <h2 className="text-lg font-bold text-white mb-5">Create New Exam</h2>
        <div className="space-y-4">
          <div>
            <label className="form-label">Exam Title</label>
            <input className="form-input" placeholder="e.g. BSEA National Certification 2026"
              value={form.title} onChange={e => setForm({ ...form, title: e.target.value })} />
          </div>
          <div>
            <label className="form-label">Description</label>
            <textarea className="form-input" rows={2} placeholder="Exam description..."
              value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="form-label">Security Mode</label>
              <select className="form-input" value={form.security_mode}
                onChange={e => setForm({ ...form, security_mode: e.target.value })}>
                <option value="STANDARD">STANDARD</option>
                <option value="HIGH">HIGH</option>
                <option value="CRITICAL">CRITICAL</option>
              </select>
            </div>
            <div>
              <label className="form-label">Required Approvals</label>
              <select className="form-input" value={form.required_approvals}
                onChange={e => setForm({ ...form, required_approvals: Number(e.target.value) })}>
                <option value={1}>1</option>
                <option value={2}>2</option>
                <option value={3}>3</option>
                <option value={5}>5</option>
              </select>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="form-label">Scheduled Start (UTC)</label>
              <input type="datetime-local" className="form-input"
                onChange={e => setForm({ ...form, scheduled_start_utc: new Date(e.target.value).toISOString() })} />
            </div>
            <div>
              <label className="form-label">Duration (minutes)</label>
              <input type="number" className="form-input" value={form.duration_minutes}
                onChange={e => setForm({ ...form, duration_minutes: Number(e.target.value) })} />
            </div>
          </div>
        </div>
        <div className="flex gap-3 mt-6">
          <button className="btn btn-primary flex-1 justify-center"
            onClick={() => mutation.mutate()} disabled={!form.title || mutation.isPending}>
            {mutation.isPending ? 'Creating...' : 'Create Exam'}
          </button>
          <button className="btn btn-ghost" onClick={onClose}>Cancel</button>
        </div>
        {mutation.isError && (
          <div className="mt-3 text-xs text-red-400">
            Failed to create exam. Check your permissions.
          </div>
        )}
      </div>
    </div>
  );
}

export default function ExamsPage() {
  const qc = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);

  const { data: exams = [], isLoading } = useQuery({
    queryKey: ['exams'],
    queryFn: () => examsApi.list().then(r => r.data),
    refetchInterval: 15000,
  });

  return (
    <div className="p-8">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold text-white">Examinations</h1>
          <p className="text-slate-400 text-sm mt-1">Manage exam lifecycle, blueprints, and release control</p>
        </div>
        <button className="btn btn-primary" onClick={() => setShowCreate(true)}>
          <Plus className="w-4 h-4" /> Create Exam
        </button>
      </div>

      {isLoading ? (
        <div className="text-slate-500">Loading exams...</div>
      ) : (
        <div className="space-y-3">
          {exams.map((exam: any) => (
            <Link
              key={exam.id}
              to={`/admin/exams/${exam.id}`}
              className="card flex items-center justify-between hover:border-blue-500/30 hover:bg-blue-950/10 transition-all group"
            >
              <div className="flex items-center gap-4">
                <div className="w-10 h-10 rounded-xl bg-blue-500/10 flex items-center justify-center">
                  <FileText className="w-5 h-5 text-blue-400" />
                </div>
                <div>
                  <div className="font-semibold text-white group-hover:text-blue-300 transition-colors">{exam.title}</div>
                  <div className="flex items-center gap-3 mt-1">
                    <span className={STATUS_BADGE[exam.status] || 'badge-info'}>{exam.status}</span>
                    <span className="badge-warning text-xs">{exam.security_mode}</span>
                    {exam.release_frozen && <span className="badge-critical text-xs">FROZEN</span>}
                    {exam.scheduled_start_utc && (
                      <span className="text-xs text-slate-500 flex items-center gap-1">
                        <Calendar className="w-3 h-3" />
                        {new Date(exam.scheduled_start_utc).toLocaleDateString('en-IN')}
                      </span>
                    )}
                    <span className="text-xs text-slate-600 font-mono">
                      {exam.required_approvals}-of-N threshold
                    </span>
                  </div>
                </div>
              </div>
              <ChevronRight className="w-4 h-4 text-slate-600 group-hover:text-blue-400 transition-colors" />
            </Link>
          ))}
          {exams.length === 0 && (
            <div className="card text-center py-12">
              <FileText className="w-12 h-12 text-slate-600 mx-auto mb-4" />
              <div className="text-slate-400">No exams created yet</div>
              <button className="btn btn-primary mt-4" onClick={() => setShowCreate(true)}>Create First Exam</button>
            </div>
          )}
        </div>
      )}

      {showCreate && (
        <CreateExamModal
          onClose={() => setShowCreate(false)}
          onCreated={() => qc.invalidateQueries({ queryKey: ['exams'] })}
        />
      )}
    </div>
  );
}
