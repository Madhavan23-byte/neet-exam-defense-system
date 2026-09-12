import { useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { CheckCircle, Home } from 'lucide-react';
import { useExamSessionStore } from '../../stores/examStore';

export default function ResultPage() {
  const navigate = useNavigate();
  const { clearSession } = useExamSessionStore();

  useEffect(() => {
    // We clear the active session from state after a brief delay
    // In a real app we might fetch the actual result from an evaluation endpoint
    // if the exam policies allow immediate result viewing.
    const timer = setTimeout(() => {
      clearSession();
    }, 5000);
    return () => clearTimeout(timer);
  }, [clearSession]);

  return (
    <div className="min-h-screen security-grid flex items-center justify-center p-6">
      <div className="w-full max-w-md card-elevated text-center py-12 animate-fade-in relative z-10">
        <div className="w-16 h-16 rounded-full bg-emerald-500/20 flex items-center justify-center mx-auto mb-6">
          <CheckCircle className="w-8 h-8 text-emerald-400" />
        </div>
        <h1 className="text-2xl font-bold text-white mb-2">Examination Submitted</h1>
        <p className="text-slate-400 mb-8 px-4">
          Your examination responses have been securely encrypted and submitted to the central evaluation engine.
        </p>

        <div className="bg-slate-900/50 p-4 rounded-lg mx-6 mb-8 text-sm text-slate-500 border border-slate-800">
          The session cryptographic keys have been destroyed. This device can no longer access the exam paper.
        </div>

        <button
          className="btn btn-ghost"
          onClick={() => {
            clearSession();
            navigate('/');
          }}
        >
          <Home className="w-4 h-4" />
          Return to Home
        </button>
      </div>
    </div>
  );
}
