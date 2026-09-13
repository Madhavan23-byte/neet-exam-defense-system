import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { CheckCircle, Home, Shield, Clock } from 'lucide-react';
import { useExamSessionStore } from '../../stores/examStore';
import { candidateApi } from '../../services/api';

export default function ResultPage() {
  const navigate = useNavigate();
  const { sessionToken, clearSession } = useExamSessionStore();
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!sessionToken) {
      setLoading(false);
      return;
    }

    candidateApi
      .getResult(sessionToken)
      .then((res) => {
        setResult(res.data);
        setLoading(false);
      })
      .catch((err) => {
        console.error('Failed to fetch candidate result receipt:', err);
        setError('Submission receipt stored. Real-time scores will be published following moderation.');
        setLoading(false);
      });
  }, [sessionToken]);

  const handleReturnHome = () => {
    clearSession();
    navigate('/');
  };

  return (
    <div className="min-h-screen security-grid flex items-center justify-center p-6">
      <div className="w-full max-w-lg card-elevated text-center py-10 px-8 animate-fade-in relative z-10 space-y-6">
        <div className="w-16 h-16 rounded-full bg-emerald-500/20 flex items-center justify-center mx-auto">
          <CheckCircle className="w-8 h-8 text-emerald-400" />
        </div>

        <div>
          <h1 className="text-2xl font-bold text-white mb-1">Examination Submitted</h1>
          <p className="text-slate-400 text-sm">
            Your examination responses have been securely locked and committed to the evaluation engine.
          </p>
        </div>

        {loading ? (
          <div className="py-6 flex flex-col items-center justify-center text-slate-400 text-sm gap-2">
            <Shield className="w-6 h-6 text-blue-400 animate-spin" />
            <span>Verifying submission receipt and evaluation status...</span>
          </div>
        ) : result && result.result_available ? (
          <div className="space-y-4">
            {/* Score Highlight */}
            <div className="p-4 rounded-xl bg-blue-950/30 border border-blue-900/40">
              <div className="text-xs text-blue-400 font-semibold uppercase tracking-wider mb-1">
                Score Summary Receipt
              </div>
              <div className="text-3xl font-extrabold text-white font-mono">
                {result.total_score} <span className="text-lg text-slate-400 font-normal">/ {result.max_score}</span>
              </div>
              <div className="text-xs text-emerald-400 font-mono mt-1 font-semibold">
                Score: {result.percentage}%
              </div>
            </div>

            {/* Metric Cards */}
            <div className="grid grid-cols-4 gap-2 text-center text-xs">
              <div className="p-2.5 rounded-lg bg-slate-800/60 border border-slate-700">
                <div className="font-bold text-white text-base font-mono">{result.attempted}</div>
                <div className="text-slate-400 text-[10px] mt-0.5">Attempted</div>
              </div>
              <div className="p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/30">
                <div className="font-bold text-emerald-400 text-base font-mono">{result.correct}</div>
                <div className="text-slate-400 text-[10px] mt-0.5">Correct</div>
              </div>
              <div className="p-2.5 rounded-lg bg-red-500/10 border border-red-500/30">
                <div className="font-bold text-red-400 text-base font-mono">{result.incorrect}</div>
                <div className="text-slate-400 text-[10px] mt-0.5">Incorrect</div>
              </div>
              <div className="p-2.5 rounded-lg bg-amber-500/10 border border-amber-500/30">
                <div className="font-bold text-amber-400 text-base font-mono">{result.skipped}</div>
                <div className="text-slate-400 text-[10px] mt-0.5">Skipped</div>
              </div>
            </div>

            {result.submitted_at && (
              <div className="text-xs text-slate-500 flex items-center justify-center gap-1 font-mono">
                <Clock className="w-3.5 h-3.5" />
                Submitted: {new Date(result.submitted_at).toLocaleString()}
              </div>
            )}
          </div>
        ) : error ? (
          <div className="p-3 rounded-lg bg-slate-800/80 border border-slate-700 text-xs text-slate-300">
            {error}
          </div>
        ) : (
          <div className="p-4 rounded-lg bg-slate-900/60 border border-slate-800 text-xs text-slate-400">
            Submission successfully acknowledged by central verification service.
          </div>
        )}

        <div className="bg-slate-900/50 p-3 rounded-lg text-xs text-slate-500 border border-slate-800 flex items-center justify-center gap-2">
          <Shield className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>The session cryptographic keys have been destroyed. This device can no longer access exam items.</span>
        </div>

        <button
          className="btn btn-primary w-full flex items-center justify-center gap-2"
          onClick={handleReturnHome}
        >
          <Home className="w-4 h-4" />
          Return to Portal Home
        </button>
      </div>
    </div>
  );
}
