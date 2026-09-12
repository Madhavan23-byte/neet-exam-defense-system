import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { examsApi, questionsApi } from '../../services/api';
import { BookOpen, Plus, Lock, CheckCircle, XCircle, Send } from 'lucide-react';

const SUBJECTS = ['Physics', 'Chemistry', 'Mathematics', 'Biology', 'Computer Science', 'English', 'History', 'Geography'];
const DIFFICULTIES = ['easy', 'medium', 'hard'];
const BLOOM_LEVELS = ['Remember', 'Understand', 'Apply', 'Analyze', 'Evaluate', 'Create'];

function QuestionForm({ examId, onDone }: { examId: string; onDone: () => void }) {
  const [form, setForm] = useState({
    exam_id: examId,
    subject: 'Physics',
    topic: '',
    difficulty: 'medium',
    bloom_level: 'Apply',
    question_text: '',
    option_a: '', option_b: '', option_c: '', option_d: '',
    correct_option: 0,
    marks_positive: 4,
    marks_negative: 1,
  });

  const mutation = useMutation({
    mutationFn: () => {
      const content = JSON.stringify({
        text: form.question_text,
        options: [form.option_a, form.option_b, form.option_c, form.option_d],
        type: 'MCQ',
      });
      return questionsApi.create({
        exam_id: form.exam_id,
        subject: form.subject,
        topic: form.topic,
        difficulty: form.difficulty,
        bloom_level: form.bloom_level,
        content,
        correct_option: form.correct_option,
        marks_positive: form.marks_positive,
        marks_negative: form.marks_negative,
      });
    },
    onSuccess: onDone,
  });

  return (
    <div className="card-elevated space-y-4">
      <div className="flex items-center gap-2 mb-2">
        <BookOpen className="w-4 h-4 text-blue-400" />
        <h3 className="font-bold text-white">New Question</h3>
      </div>

      <div className="grid grid-cols-3 gap-4">
        <div>
          <label className="form-label">Subject</label>
          <select className="form-input" value={form.subject} onChange={e => setForm({ ...form, subject: e.target.value })}>
            {SUBJECTS.map(s => <option key={s}>{s}</option>)}
          </select>
        </div>
        <div>
          <label className="form-label">Difficulty</label>
          <select className="form-input" value={form.difficulty} onChange={e => setForm({ ...form, difficulty: e.target.value })}>
            {DIFFICULTIES.map(d => <option key={d}>{d}</option>)}
          </select>
        </div>
        <div>
          <label className="form-label">Bloom's Level</label>
          <select className="form-input" value={form.bloom_level} onChange={e => setForm({ ...form, bloom_level: e.target.value })}>
            {BLOOM_LEVELS.map(b => <option key={b}>{b}</option>)}
          </select>
        </div>
      </div>

      <div>
        <label className="form-label">Topic</label>
        <input className="form-input" placeholder="e.g. Mechanics, Thermodynamics..."
          value={form.topic} onChange={e => setForm({ ...form, topic: e.target.value })} />
      </div>

      <div>
        <label className="form-label">Question Text</label>
        <textarea className="form-input" rows={3} placeholder="Enter the question..."
          value={form.question_text} onChange={e => setForm({ ...form, question_text: e.target.value })} />
      </div>

      <div className="grid grid-cols-2 gap-3">
        {['a', 'b', 'c', 'd'].map((opt, i) => (
          <div key={opt}>
            <label className="form-label">Option {opt.toUpperCase()}</label>
            <div className="flex gap-2">
              <input
                className="form-input flex-1"
                placeholder={`Option ${opt.toUpperCase()}`}
                value={(form as any)[`option_${opt}`]}
                onChange={e => setForm({ ...form, [`option_${opt}`]: e.target.value })}
              />
              <button
                type="button"
                onClick={() => setForm({ ...form, correct_option: i })}
                className={`px-3 rounded-lg border text-xs font-semibold transition-all ${
                  form.correct_option === i
                    ? 'bg-emerald-500/20 border-emerald-500 text-emerald-400'
                    : 'border-slate-700 text-slate-500 hover:border-slate-500'
                }`}
                title="Mark as correct"
              >
                ✓
              </button>
            </div>
          </div>
        ))}
      </div>

      <div className="flex items-center gap-2 text-xs text-slate-500 p-3 rounded-lg bg-blue-950/20 border border-blue-900/20">
        <Lock className="w-3.5 h-3.5 text-blue-400" />
        <span>
          This question will be stored as DRAFT. After moderation approval,
          it will be <strong className="text-blue-400">immediately encrypted with AES-256-GCM</strong> and
          the plaintext will be cleared from the database.
        </span>
      </div>

      <div className="flex gap-3">
        <button
          className="btn btn-primary"
          onClick={() => mutation.mutate()}
          disabled={!form.question_text || !form.option_a || mutation.isPending}
        >
          <BookOpen className="w-4 h-4" />
          {mutation.isPending ? 'Saving...' : 'Save Question'}
        </button>
        <button className="btn btn-ghost" onClick={onDone}>Cancel</button>
      </div>

      {mutation.isSuccess && (
        <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs">
          ✅ Question saved in DRAFT status. Submit for review to proceed with encryption.
        </div>
      )}
    </div>
  );
}

export default function AuthoringPage() {
  const qc = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [selectedExamId, setSelectedExamId] = useState('');

  const { data: exams = [] } = useQuery({
    queryKey: ['exams'],
    queryFn: () => examsApi.list().then(r => r.data),
  });

  const { data: questions = [], refetch } = useQuery({
    queryKey: ['questions', selectedExamId],
    queryFn: () => questionsApi.list(selectedExamId).then(r => r.data),
    enabled: !!selectedExamId,
  });

  const submitMutation = useMutation({
    mutationFn: (id: string) => questionsApi.submit(id),
    onSuccess: () => refetch(),
  });

  const approveMutation = useMutation({
    mutationFn: (id: string) => questionsApi.approve(id, 'Approved after review'),
    onSuccess: () => refetch(),
  });

  return (
    <div className="p-8">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold text-white">Question Authoring</h1>
          <p className="text-slate-400 text-sm mt-1">Create and manage examination questions</p>
        </div>
        <div className="flex gap-3">
          <select
            className="form-input w-64"
            value={selectedExamId}
            onChange={e => setSelectedExamId(e.target.value)}
          >
            <option value="">Select exam...</option>
            {exams.map((e: any) => <option key={e.id} value={e.id}>{e.title}</option>)}
          </select>
          {selectedExamId && (
            <button className="btn btn-primary" onClick={() => setShowCreate(true)}>
              <Plus className="w-4 h-4" /> New Question
            </button>
          )}
        </div>
      </div>

      {showCreate && selectedExamId && (
        <div className="mb-6">
          <QuestionForm examId={selectedExamId} onDone={() => { setShowCreate(false); refetch(); }} />
        </div>
      )}

      {selectedExamId ? (
        <div className="space-y-3">
          {questions.map((q: any) => (
            <div key={q.id} className="card flex items-center justify-between">
              <div className="flex items-center gap-4">
                <div className="w-10 h-10 rounded-xl bg-blue-500/10 flex items-center justify-center shrink-0">
                  {q.has_encrypted_content ? (
                    <Lock className="w-5 h-5 text-emerald-400" />
                  ) : (
                    <BookOpen className="w-5 h-5 text-blue-400" />
                  )}
                </div>
                <div>
                  <div className="text-sm font-semibold text-white">{q.subject} — {q.topic || 'General'}</div>
                  <div className="flex items-center gap-2 mt-1">
                    <span className="text-xs text-slate-500">{q.difficulty}</span>
                    {q.has_encrypted_content && (
                      <span className="text-xs text-emerald-400 font-mono">
                        🔒 SHA3: {(q.integrity_hash || '').slice(0, 16)}...
                      </span>
                    )}
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <span className={`badge-${q.status === 'ENCRYPTED' ? 'secure' : q.status === 'DRAFT' ? 'info' : q.status === 'REJECTED' ? 'critical' : 'warning'}`}>
                  {q.status}
                </span>
                {q.status === 'DRAFT' && (
                  <button
                    className="btn btn-ghost text-xs py-1"
                    onClick={() => submitMutation.mutate(q.id)}
                    disabled={submitMutation.isPending}
                  >
                    <Send className="w-3 h-3" /> Submit
                  </button>
                )}
                {q.status === 'SUBMITTED' && (
                  <button
                    className="btn btn-success text-xs py-1"
                    onClick={() => approveMutation.mutate(q.id)}
                    disabled={approveMutation.isPending}
                  >
                    <CheckCircle className="w-3 h-3" /> Approve & Encrypt
                  </button>
                )}
              </div>
            </div>
          ))}
          {questions.length === 0 && (
            <div className="card text-center py-12">
              <BookOpen className="w-10 h-10 text-slate-600 mx-auto mb-3" />
              <div className="text-slate-400 text-sm">No questions yet. Create the first one.</div>
            </div>
          )}
        </div>
      ) : (
        <div className="card text-center py-16">
          <FileText className="w-12 h-12 text-slate-600 mx-auto mb-4" />
          <div className="text-slate-400">Select an exam to view and manage questions</div>
        </div>
      )}
    </div>
  );
}

// Missing import fix
import { FileText } from 'lucide-react';
