import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { FileText, Plus, ChevronRight, Lock, Shield, Calendar, AlertCircle } from 'lucide-react';
import { examsApi } from '../../services/api';
import StatusBadge from '../../components/ui/StatusBadge';
import ActionModal from '../../components/ui/ActionModal';
import EmptyState from '../../components/ui/EmptyState';

export default function ExamsPage() {
  const queryClient = useQueryClient();
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [newTitle, setNewTitle] = useState('');
  const [newType, setNewType] = useState('CBT');
  const [newSecMode, setNewSecMode] = useState('STANDARD');
  const [newDuration, setNewDuration] = useState('180');
  const [error, setError] = useState('');

  const { data: exams = [], isLoading } = useQuery({
    queryKey: ['exams-list'],
    queryFn: () => examsApi.list().then((r) => r.data || []),
  });

  const createMutation = useMutation({
    mutationFn: (data: any) => examsApi.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['exams-list'] });
      setShowCreateModal(false);
      setNewTitle('');
      setError('');
    },
    onError: (err: any) => {
      setError(err?.response?.data?.detail || err.message || 'Failed to create exam');
    },
  });

  const handleCreate = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle.trim()) return;
    createMutation.mutate({
      title: newTitle,
      exam_type: newType,
      security_mode: newSecMode,
      duration_minutes: parseInt(newDuration, 10) || 180,
    });
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="gov-card-warm flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-[var(--gov-navy-dark)]">
            Examination Administration
          </h1>
          <p className="text-xs text-slate-500 mt-1">
            Configure examination blueprints, generate randomized candidate forms, and track release status
          </p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="btn btn-navy text-xs"
        >
          <Plus className="w-4 h-4" /> Create Examination
        </button>
      </div>

      {/* Table */}
      <div className="gov-card">
        {isLoading ? (
          <div className="py-12 text-center text-xs text-slate-400">Loading examinations...</div>
        ) : exams.length === 0 ? (
          <EmptyState
            title="No examinations found"
            description="Create your first examination to configure blueprints and questions."
            actionText="Create Examination"
            onAction={() => setShowCreateModal(true)}
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="gov-table">
              <thead>
                <tr>
                  <th>Title</th>
                  <th>Type</th>
                  <th>Security Mode</th>
                  <th>Duration</th>
                  <th>Status</th>
                  <th>Created</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {exams.map((ex: any) => (
                  <tr key={ex.id}>
                    <td>
                      <Link
                        to={`/admin/exams/${ex.id}`}
                        className="font-bold text-slate-800 hover:text-amber-700"
                      >
                        {ex.title}
                      </Link>
                    </td>
                    <td className="text-xs text-slate-600 font-mono">{ex.exam_type || 'CBT'}</td>
                    <td className="text-xs text-slate-600 font-mono">{ex.security_mode}</td>
                    <td className="text-xs text-slate-600 font-mono">{ex.duration_minutes} min</td>
                    <td>
                      <StatusBadge status={ex.status} type="exam" />
                    </td>
                    <td className="text-xs text-slate-500 font-mono">
                      {ex.created_at ? new Date(ex.created_at).toLocaleDateString('en-IN') : '—'}
                    </td>
                    <td>
                      <Link
                        to={`/admin/exams/${ex.id}`}
                        className="btn btn-outline text-xs py-1 px-2.5"
                      >
                        Manage <ChevronRight className="w-3.5 h-3.5" />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Create Exam Modal */}
      <ActionModal
        isOpen={showCreateModal}
        onClose={() => setShowCreateModal(false)}
        title="Create New Examination"
        subtitle="Establish examination metadata and parameters"
      >
        <form onSubmit={handleCreate} className="space-y-4 text-xs">
          {error && (
            <div className="p-3 bg-red-50 border border-red-200 rounded-lg text-red-700 flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <div>
            <label className="form-label">Examination Title</label>
            <input
              type="text"
              className="form-input text-xs"
              placeholder="e.g. National Entrance Exam 2026"
              value={newTitle}
              onChange={(e) => setNewTitle(e.target.value)}
              required
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="form-label">Exam Type</label>
              <select
                className="form-input text-xs"
                value={newType}
                onChange={(e) => setNewType(e.target.value)}
              >
                <option value="CBT">Computer-Based Test (CBT)</option>
                <option value="PROCTORED_REMOTE">Proctored Remote</option>
              </select>
            </div>
            <div>
              <label className="form-label">Security Mode</label>
              <select
                className="form-input text-xs"
                value={newSecMode}
                onChange={(e) => setNewSecMode(e.target.value)}
              >
                <option value="STANDARD">STANDARD</option>
                <option value="HIGH_ASSURANCE">HIGH_ASSURANCE</option>
              </select>
            </div>
          </div>

          <div>
            <label className="form-label">Duration (Minutes)</label>
            <input
              type="number"
              className="form-input text-xs font-mono"
              value={newDuration}
              onChange={(e) => setNewDuration(e.target.value)}
              min="10"
              max="600"
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
              disabled={createMutation.isPending || !newTitle.trim()}
            >
              {createMutation.isPending ? 'Creating...' : 'Create Examination'}
            </button>
          </div>
        </form>
      </ActionModal>
    </div>
  );
}
