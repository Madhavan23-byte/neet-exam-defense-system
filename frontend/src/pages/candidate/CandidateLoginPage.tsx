import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, FileText, Fingerprint, AlertCircle } from 'lucide-react';
import { candidateApi, examsApi } from '../../services/api';
import { useExamSessionStore } from '../../stores/examStore';
import { useQuery } from '@tanstack/react-query';

export default function CandidateLoginPage() {
  const navigate = useNavigate();
  const { setSession } = useExamSessionStore();

  const [registrationNo, setRegistrationNo] = useState('BSEA-2026-DEMO-001');
  const [password, setPassword] = useState('BSeaDemo@2026');
  const [selectedExam, setSelectedExam] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [agreed, setAgreed] = useState(false);

  // We fetch publicly listed active exams (simplified for demo)
  // In reality, this would just be the candidate entering an exam code or logging into a portal first.
  const { data: exams = [] } = useQuery({
    queryKey: ['available-exams'],
    queryFn: () => examsApi.list().then(r => r.data),
  });

  const activeExams = exams.filter((e: any) => e.status === 'RELEASED');

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!agreed) {
      setError('You must agree to the examination rules');
      return;
    }
    setError('');
    setLoading(true);

    try {
      const examToUse = selectedExam || (activeExams.length > 0 ? activeExams[0].id : '');
      if (!examToUse) {
        setError('No active exams available');
        setLoading(false);
        return;
      }

      const res = await candidateApi.login(registrationNo, password, examToUse);
      setSession(res.data);
      navigate('/candidate/exam');
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Authentication failed. Ensure the exam is released.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen security-grid flex items-center justify-center p-6">
      <div className="fixed inset-0 bg-gradient-to-br from-blue-950/20 via-transparent to-purple-950/20 pointer-events-none" />

      <div className="w-full max-w-5xl flex flex-col lg:flex-row gap-8 relative z-10">
        {/* Left Rules Panel */}
        <div className="lg:w-1/2 card-elevated flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-3 mb-6 pb-6 border-b border-blue-900/20">
              <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-blue-600 to-purple-600 flex items-center justify-center">
                <Shield className="w-6 h-6 text-white" />
              </div>
              <div>
                <div className="font-bold text-white text-lg">B-SEA Secure CBT</div>
                <div className="text-xs text-blue-400">Candidate Examination Portal</div>
              </div>
            </div>

            <h2 className="text-lg font-bold text-white mb-4">Examination Rules & Instructions</h2>
            <div className="space-y-4 text-sm text-slate-400">
              <p>
                <strong className="text-slate-300">1. Security Monitoring:</strong> This examination environment is continuously monitored.
                Any attempt to switch tabs, exit fullscreen, or use developer tools will be logged as a security violation.
              </p>
              <p>
                <strong className="text-slate-300">2. Watermarking:</strong> All question content is cryptographically watermarked with your identity.
                Unauthorized photography or screenshots can be forensically traced back to your session.
              </p>
              <p>
                <strong className="text-slate-300">3. Integrity:</strong> Questions are decrypted in real-time. Do not attempt to reverse-engineer
                or capture the network traffic. The answer key is not transmitted to this client.
              </p>
            </div>
          </div>
          <div className="mt-8 pt-6 border-t border-blue-900/20 text-xs text-slate-500">
            Powered by Bharat Secure Examination Architecture
          </div>
        </div>

        {/* Right Login Panel */}
        <div className="lg:w-1/2 card-elevated">
          <div className="flex items-center gap-2 mb-6">
            <Fingerprint className="w-5 h-5 text-blue-400" />
            <h2 className="text-xl font-bold text-white">Candidate Authentication</h2>
          </div>

          {error && (
            <div className="flex items-center gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-sm mb-6">
              <AlertCircle className="w-4 h-4 shrink-0" />
              {error}
            </div>
          )}

          <form onSubmit={handleLogin} className="space-y-5">
            <div>
              <label className="form-label">Select Examination</label>
              <select
                className="form-input"
                value={selectedExam}
                onChange={e => setSelectedExam(e.target.value)}
                required
              >
                {activeExams.length === 0 && <option value="">No released exams</option>}
                {activeExams.map((e: any) => (
                  <option key={e.id} value={e.id}>{e.title}</option>
                ))}
              </select>
            </div>

            <div>
              <label className="form-label">Registration Number</label>
              <input
                className="form-input font-mono"
                placeholder="Registration Number"
                value={registrationNo}
                onChange={e => setRegistrationNo(e.target.value)}
                required
              />
            </div>

            <div>
              <label className="form-label">Password</label>
              <input
                type="password"
                className="form-input"
                placeholder="Password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                required
              />
            </div>

            <label className="flex items-start gap-3 p-3 rounded-lg bg-blue-950/20 border border-blue-900/30 cursor-pointer hover:bg-blue-950/40 transition-colors">
              <input
                type="checkbox"
                className="mt-1"
                checked={agreed}
                onChange={e => setAgreed(e.target.checked)}
              />
              <span className="text-xs text-slate-300">
                I have read and agree to all examination rules. I understand that security violations
                may result in immediate termination of my examination session.
              </span>
            </label>

            <button
              type="submit"
              className="btn btn-primary w-full justify-center text-lg py-3 mt-4"
              disabled={loading}
            >
              <FileText className="w-5 h-5" />
              {loading ? 'Authenticating & Initializing Secure Session...' : 'Start Secure Examination'}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
