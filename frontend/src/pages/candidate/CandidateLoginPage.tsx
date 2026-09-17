import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Shield, BookOpen, AlertCircle, CheckCircle2, UserCheck, ArrowRight, Clock } from 'lucide-react';
import { candidateApi, examsApi } from '../../services/api';
import { useExamSessionStore } from '../../stores/examStore';
import PortalHeader from '../../components/ui/PortalHeader';
import PortalFooter from '../../components/ui/PortalFooter';

export default function CandidateLoginPage() {
  const navigate = useNavigate();
  const setSession = useExamSessionStore((state) => state.setSession);

  const [regNumber, setRegNumber] = useState('NEET-2026-000001');
  const [password, setPassword] = useState('Candidate@123');
  const [selectedExamId, setSelectedExamId] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  // Fetch real active exams from backend API
  const { data: exams = [], isLoading: examsLoading } = useQuery({
    queryKey: ['candidate-exams'],
    queryFn: async () => {
      const res = await examsApi.list();
      return res.data || [];
    },
  });

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    const targetExamId = selectedExamId || (exams.length > 0 ? exams[0].id : '');
    if (!targetExamId) {
      setError('Please select an active examination.');
      return;
    }

    setLoading(true);
    try {
      const res = await candidateApi.login(regNumber, password, targetExamId);
      const data = res.data;

      // Persist candidate session store
      setSession({
        sessionToken: data.session_token,
        examId: targetExamId,
        candidateName: data.candidate_name,
        watermarkId: data.watermark_id,
        totalQuestions: data.total_questions || 0,
        durationMinutes: data.duration_minutes || 180,
        expiresAt: data.expires_at,
      });

      navigate('/candidate/exam');
    } catch (err: any) {
      setError(
        err?.response?.data?.detail || err.message || 'Authentication failed. Please verify Roll Number & Password.'
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col bg-[var(--gov-canvas)]">
      <PortalHeader subtitle="Candidate Computer-Based Test (CBT) Portal" />

      <main className="flex-1 max-w-4xl mx-auto px-4 py-8 sm:py-12 w-full">
        <div className="grid grid-cols-1 md:grid-cols-12 gap-8 items-start">
          {/* Instructions Column */}
          <div className="md:col-span-5 space-y-4">
            <div className="gov-card">
              <h2 className="text-sm font-bold text-[var(--gov-navy-dark)] uppercase tracking-wider mb-3 flex items-center gap-2">
                <BookOpen className="w-4 h-4 text-amber-600" />
                Examination Instructions
              </h2>
              <ul className="space-y-2.5 text-xs text-slate-600 leading-relaxed">
                <li className="flex items-start gap-2">
                  <span className="w-4 h-4 rounded-full bg-amber-500/20 text-amber-900 font-bold text-[10px] flex items-center justify-center shrink-0 mt-0.5">1</span>
                  <span>Ensure your Roll Number matches the entry on your official Admit Card.</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="w-4 h-4 rounded-full bg-amber-500/20 text-amber-900 font-bold text-[10px] flex items-center justify-center shrink-0 mt-0.5">2</span>
                  <span>Do not refresh, close, or switch browser tabs during active testing.</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="w-4 h-4 rounded-full bg-amber-500/20 text-amber-900 font-bold text-[10px] flex items-center justify-center shrink-0 mt-0.5">3</span>
                  <span>Responses are securely saved in real time to the examination server.</span>
                </li>
              </ul>
            </div>

            <div className="gov-card bg-emerald-50/50 border-emerald-200">
              <div className="flex items-center gap-2 font-bold text-xs text-emerald-900 mb-1">
                <CheckCircle2 className="w-4 h-4 text-emerald-700" />
                <span>System Readiness Check</span>
              </div>
              <p className="text-[11px] text-emerald-800 leading-relaxed">
                Browser verified: Modern standards compliant. Cryptographic session isolation active.
              </p>
            </div>
          </div>

          {/* Login Form Column */}
          <div className="md:col-span-7">
            <div className="gov-card-elevated">
              <div className="mb-6">
                <h1 className="text-xl font-bold text-[var(--gov-navy-dark)]">
                  Candidate Verification
                </h1>
                <p className="text-xs text-slate-500 mt-1">
                  Enter your assigned registration credentials to enter the CBT session
                </p>
              </div>

              {error && (
                <div className="p-3 mb-5 bg-red-50 border border-red-200 rounded-lg text-red-700 text-xs flex items-center gap-2">
                  <AlertCircle className="w-4 h-4 shrink-0" />
                  <span>{error}</span>
                </div>
              )}

              <form onSubmit={handleLogin} className="space-y-4">
                <div>
                  <label className="form-label">Examination</label>
                  <select
                    className="form-input text-xs"
                    value={selectedExamId}
                    onChange={(e) => setSelectedExamId(e.target.value)}
                    disabled={examsLoading || exams.length === 0}
                  >
                    {exams.length === 0 ? (
                      <option value="">No released examinations currently active</option>
                    ) : (
                      exams.map((ex: any) => (
                        <option key={ex.id} value={ex.id}>
                          {ex.title} ({ex.exam_type || 'CBT'})
                        </option>
                      ))
                    )}
                  </select>
                </div>

                <div>
                  <label className="form-label">Roll Number / Registration ID</label>
                  <input
                    type="text"
                    className="form-input text-xs font-mono"
                    placeholder="e.g. NEET-2026-000001"
                    value={regNumber}
                    onChange={(e) => setRegNumber(e.target.value)}
                    required
                  />
                </div>

                <div>
                  <label className="form-label">Password / Date of Birth</label>
                  <input
                    type="password"
                    className="form-input text-xs"
                    placeholder="Enter examination password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                  />
                </div>

                <div className="pt-2">
                  <button
                    type="submit"
                    className="btn btn-amber w-full justify-center text-xs py-2.5"
                    disabled={loading || !regNumber || !password}
                  >
                    {loading ? 'Verifying Session...' : 'Start Examination'}
                    <ArrowRight className="w-4 h-4" />
                  </button>
                </div>
              </form>

              <div className="mt-5 text-center text-xs text-slate-500">
                Facing an issue? Notify your centre invigilator immediately.
              </div>
            </div>
          </div>
        </div>
      </main>

      <PortalFooter />
    </div>
  );
}
