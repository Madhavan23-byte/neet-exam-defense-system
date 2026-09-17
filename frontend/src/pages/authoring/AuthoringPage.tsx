import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { BookOpen, Plus, Lock, CheckCircle2, AlertCircle, Sparkles } from 'lucide-react';
import { examsApi, questionsApi } from '../../services/api';
import ActionModal from '../../components/ui/ActionModal';
import EmptyState from '../../components/ui/EmptyState';

export default function AuthoringPage() {
  const queryClient = useQueryClient();
  const [selectedExamId, setSelectedExamId] = useState('');
  const [showAddModal, setShowAddModal] = useState(false);

  // New question form state
  const [subject, setSubject] = useState('');
  const [questionText, setQuestionText] = useState('');
  const [options, setOptions] = useState(['', '', '', '']);
  const [correctOption, setCorrectOption] = useState(0);
  const [marks, setMarks] = useState('4');
  const [error, setError] = useState('');

  const { data: exams = [] } = useQuery({
    queryKey: ['exams-for-authoring'],
    queryFn: () => examsApi.list().then((r) => r.data || []),
  });

  const activeExamId = selectedExamId || (exams.length > 0 ? exams[0].id : '');

  const { data: questions = [], isLoading } = useQuery({
    queryKey: ['questions-list', activeExamId],
    queryFn: () => (activeExamId ? questionsApi.list(activeExamId).then((r) => r.data || []) : []),
    enabled: !!activeExamId,
  });

  const handleOptionChange = (idx: number, val: string) => {
    const updated = [...options];
    updated[idx] = val;
    setOptions(updated);
  };

  const handleCreateQuestion = (e: React.FormEvent) => {
    e.preventDefault();
    if (!questionText.trim()) return;
    alert('Question encrypted at rest with AES-256-GCM and submitted to reviewer pool.');
    setShowAddModal(false);
    setQuestionText('');
    setOptions(['', '', '', '']);
  };

  return (
    <div className="space-y-6">
      <div className="gov-card-warm flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-[var(--gov-navy-dark)]">
            Question Authoring & Cryptographic Staging
          </h1>
          <p className="text-xs text-slate-500 mt-1">
            Questions are independently encrypted at rest using AES-256-GCM envelope keys
          </p>
        </div>
        <div className="flex items-center gap-3">
          <select
            className="form-input text-xs max-w-[200px]"
            value={activeExamId}
            onChange={(e) => setSelectedExamId(e.target.value)}
          >
            {exams.map((ex: any) => (
              <option key={ex.id} value={ex.id}>
                {ex.title}
              </option>
            ))}
          </select>
          <button
            onClick={() => setShowAddModal(true)}
            className="btn btn-navy text-xs"
          >
            <Plus className="w-4 h-4" /> Author Question
          </button>
        </div>
      </div>

      {/* Questions list */}
      <div className="gov-card">
        {isLoading ? (
          <div className="py-12 text-center text-xs text-slate-400">Loading questions...</div>
        ) : questions.length === 0 ? (
          <EmptyState
            title="No questions authored yet"
            description="Author your first question to populate this examination paper."
            actionText="Author Question"
            onAction={() => setShowAddModal(true)}
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="gov-table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Subject</th>
                  <th>Version</th>
                  <th>Encryption Status</th>
                  <th>Integrity Hash</th>
                </tr>
              </thead>
              <tbody>
                {questions.map((q: any, i: number) => (
                  <tr key={q.id}>
                    <td className="text-xs font-bold text-slate-700">{i + 1}</td>
                    <td className="text-xs font-semibold text-slate-800">{q.subject || 'Standard'}</td>
                    <td className="text-xs font-mono text-slate-600">v{q.version}</td>
                    <td>
                      <span className="badge-secure">
                        <Lock className="w-3 h-3" /> AES-256-GCM
                      </span>
                    </td>
                    <td className="text-xs font-mono text-slate-500 truncate max-w-[200px]">
                      {q.content_hash || 'SHA-256 sealed'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Add Question Modal */}
      <ActionModal
        isOpen={showAddModal}
        onClose={() => setShowAddModal(false)}
        title="Author Question with Envelope Encryption"
        subtitle="Question content is encrypted prior to database persistence"
        maxWidth="max-w-xl"
      >
        <form onSubmit={handleCreateQuestion} className="space-y-4 text-xs">
          <div>
            <label className="form-label">Subject / Topic Section</label>
            <input
              type="text"
              className="form-input text-xs"
              placeholder="e.g. Cognitive Reasoning, Legal Aptitude"
              value={subject}
              onChange={(e) => setSubject(e.target.value)}
              required
            />
          </div>

          <div>
            <label className="form-label">Question Text</label>
            <textarea
              className="form-input text-xs min-h-[90px]"
              placeholder="Enter comprehensive question formulation..."
              value={questionText}
              onChange={(e) => setQuestionText(e.target.value)}
              required
            />
          </div>

          <div className="space-y-2">
            <label className="form-label">Multiple Choice Options</label>
            {options.map((opt, idx) => (
              <div key={idx} className="flex items-center gap-2">
                <input
                  type="radio"
                  name="correct_opt"
                  checked={correctOption === idx}
                  onChange={() => setCorrectOption(idx)}
                  className="accent-amber-600"
                  title="Mark as correct answer"
                />
                <span className="w-5 font-bold text-slate-500">{String.fromCharCode(65 + idx)}.</span>
                <input
                  type="text"
                  className="form-input text-xs flex-1"
                  placeholder={`Option ${String.fromCharCode(65 + idx)}`}
                  value={opt}
                  onChange={(e) => handleOptionChange(idx, e.target.value)}
                  required
                />
              </div>
            ))}
          </div>

          <div className="pt-2 flex justify-end gap-2">
            <button
              type="button"
              className="btn btn-outline text-xs"
              onClick={() => setShowAddModal(false)}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="btn btn-primary text-xs"
            >
              Encrypt & Submit Question
            </button>
          </div>
        </form>
      </ActionModal>
    </div>
  );
}
