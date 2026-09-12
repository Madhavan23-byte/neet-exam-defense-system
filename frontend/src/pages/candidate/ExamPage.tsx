import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Clock, AlertTriangle, CheckSquare, Flag, Send } from 'lucide-react';
import { candidateApi } from '../../services/api';
import { useExamSessionStore } from '../../stores/examStore';

export default function ExamPage() {
  const navigate = useNavigate();
  const { sessionToken, totalQuestions, candidateName, watermarkId, expiresAt, clearSession } = useExamSessionStore();

  const [currentIndex, setCurrentIndex] = useState(0);
  const [question, setQuestion] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  // Status maps for UI palette
  const [statusMap, setStatusMap] = useState<Record<number, 'answered' | 'marked' | 'unanswered'>>({});

  // Security tracking
  const [violations, setViolations] = useState(0);
  const [tabSwitches, setTabSwitches] = useState(0);
  const [timeRemaining, setTimeRemaining] = useState('');

  // Load question
  const loadQuestion = useCallback(async (index: number) => {
    if (!sessionToken) return;
    setLoading(true);
    try {
      const res = await candidateApi.getQuestion(index, sessionToken);
      setQuestion(res.data);
      setCurrentIndex(index);
      setError('');
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to load secure question');
    } finally {
      setLoading(false);
    }
  }, [sessionToken]);

  // Initial load & setup
  useEffect(() => {
    if (!sessionToken) {
      navigate('/candidate/login');
      return;
    }

    loadQuestion(0);

    // Initial dummy array for map
    const initialMap: Record<number, 'unanswered'> = {};
    for (let i = 0; i < totalQuestions; i++) initialMap[i] = 'unanswered';
    setStatusMap(initialMap);

    // Enter fullscreen if possible (browser security might block it without user gesture,
    // in real CBT this is handled by a dedicated lockdown browser)
    const enterFullscreen = async () => {
      try {
        if (document.documentElement.requestFullscreen) {
          await document.documentElement.requestFullscreen();
        }
      } catch (e) { /* ignore */ }
    };
    enterFullscreen();

    // Prevent default actions
    const preventDefault = (e: any) => e.preventDefault();
    document.addEventListener('contextmenu', preventDefault);
    document.addEventListener('copy', preventDefault);
    document.addEventListener('paste', preventDefault);

    return () => {
      document.removeEventListener('contextmenu', preventDefault);
      document.removeEventListener('copy', preventDefault);
      document.removeEventListener('paste', preventDefault);
      if (document.fullscreenElement) {
        document.exitFullscreen().catch(() => {});
      }
    };
  }, [sessionToken, navigate, loadQuestion, totalQuestions]);

  // Security: Tab switch detection
  useEffect(() => {
    const handleVisibilityChange = () => {
      if (document.hidden && sessionToken) {
        setTabSwitches(prev => {
          const nw = prev + 1;
          setViolations(v => v + 1);
          candidateApi.reportEvent(sessionToken, 'TAB_SWITCH', { tabSwitches: nw });
          return nw;
        });
      }
    };
    document.addEventListener('visibilitychange', handleVisibilityChange);
    return () => document.removeEventListener('visibilitychange', handleVisibilityChange);
  }, [sessionToken]);

  // Heartbeat & Timer
  useEffect(() => {
    if (!sessionToken || !expiresAt) return;
    const interval = setInterval(() => {
      // Timer update
      const now = new Date().getTime();
      const expiry = new Date(expiresAt).getTime();
      const distance = expiry - now;

      if (distance <= 0) {
        setTimeRemaining('EXPIRED');
        handleSubmitExam();
        clearInterval(interval);
        return;
      }

      const h = Math.floor((distance % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
      const m = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
      const s = Math.floor((distance % (1000 * 60)) / 1000);
      setTimeRemaining(`${h.toString().padStart(2, '0')}:${m.toString().padStart(2, '0')}:${s.toString().padStart(2, '0')}`);

      // Heartbeat send
      candidateApi.heartbeat(sessionToken, currentIndex, violations, tabSwitches).catch(() => {});
    }, 1000);

    return () => clearInterval(interval);
  }, [sessionToken, expiresAt, currentIndex, violations, tabSwitches]);

  const handleOptionSelect = async (optIndex: number) => {
    if (!sessionToken || !question) return;

    // Optimistic update
    setQuestion({ ...question, selected_option: optIndex });
    setStatusMap(prev => ({ ...prev, [currentIndex]: 'answered' }));

    try {
      await candidateApi.saveResponse(sessionToken, question.question_id, optIndex, question.is_marked_review);
    } catch (e) {
      console.error('Failed to save response');
    }
  };

  const handleClearResponse = async () => {
    if (!sessionToken || !question) return;
    setQuestion({ ...question, selected_option: null });
    setStatusMap(prev => ({ ...prev, [currentIndex]: question.is_marked_review ? 'marked' : 'unanswered' }));
    try {
      await candidateApi.saveResponse(sessionToken, question.question_id, null, question.is_marked_review);
    } catch (e) { }
  };

  const handleMarkReview = async () => {
    if (!sessionToken || !question) return;
    const newVal = !question.is_marked_review;
    setQuestion({ ...question, is_marked_review: newVal });

    if (newVal) {
      setStatusMap(prev => ({ ...prev, [currentIndex]: 'marked' }));
    } else {
      setStatusMap(prev => ({ ...prev, [currentIndex]: question.selected_option !== null ? 'answered' : 'unanswered' }));
    }

    try {
      await candidateApi.saveResponse(sessionToken, question.question_id, question.selected_option, newVal);
    } catch (e) { }
  };

  const handleSubmitExam = async () => {
    if (!sessionToken) return;
    if (confirm('Are you sure you want to submit the examination? This cannot be undone.')) {
      try {
        await candidateApi.submit(sessionToken);
        navigate('/candidate/result');
      } catch (e) {
        alert('Failed to submit exam. Please try again or contact invigilator.');
      }
    }
  };

  if (!sessionToken) return null;

  return (
    <div className="exam-fullscreen flex flex-col">
      {/* Background forensic watermark layer */}
      <div className="exam-watermark">
        {watermarkId} • {candidateName?.toUpperCase()} • B-SEA SECURE • {watermarkId}
      </div>

      {/* Header */}
      <header className="relative z-10 bg-slate-900 border-b border-blue-900/30 px-6 py-3 flex items-center justify-between shrink-0">
        <div className="flex items-center gap-4">
          <div className="w-8 h-8 rounded bg-gradient-to-br from-blue-600 to-purple-600 flex items-center justify-center">
            <Shield className="w-4 h-4 text-white" />
          </div>
          <div>
            <div className="text-white font-bold text-sm">B-SEA CBT Terminal</div>
            <div className="text-xs text-blue-400 font-mono">{candidateName} • {watermarkId}</div>
          </div>
        </div>

        {tabSwitches > 0 && (
          <div className="flex items-center gap-2 px-3 py-1 rounded bg-red-500/20 text-red-400 border border-red-500/30 text-xs font-bold animate-pulse">
            <AlertTriangle className="w-4 h-4" />
            SECURITY WARNING: TAB SWITCH DETECTED ({tabSwitches})
          </div>
        )}

        <div className="flex items-center gap-6">
          <div className="text-right">
            <div className="text-xs text-slate-500 uppercase tracking-wider font-semibold">Time Remaining</div>
            <div className={`text-xl font-bold font-mono ${timeRemaining === 'EXPIRED' ? 'text-red-500 animate-pulse' : 'text-emerald-400'}`}>
              {timeRemaining || '--:--:--'}
            </div>
          </div>
          <button className="btn btn-danger text-sm" onClick={handleSubmitExam}>
            Submit Exam
          </button>
        </div>
      </header>

      {/* Main Content */}
      <div className="flex-1 flex overflow-hidden relative z-10">
        {/* Left: Question Area */}
        <div className="flex-1 flex flex-col p-6 overflow-y-auto">
          {error ? (
            <div className="card-elevated border-red-500/30 bg-red-500/10 text-center py-12">
              <AlertTriangle className="w-12 h-12 text-red-400 mx-auto mb-4" />
              <div className="text-red-400 font-bold mb-2">Secure Decryption Failed</div>
              <div className="text-slate-400 text-sm">{error}</div>
              <button className="btn btn-primary mt-6" onClick={() => loadQuestion(currentIndex)}>Retry</button>
            </div>
          ) : loading || !question ? (
            <div className="flex-1 flex flex-col items-center justify-center text-slate-500">
              <Shield className="w-12 h-12 text-blue-500/30 animate-pulse-secure mb-4" />
              <div>Decrypting secure question object...</div>
              <div className="text-xs font-mono mt-2 text-slate-600">AES-256-GCM</div>
            </div>
          ) : (
            <div className="flex-1 flex flex-col max-w-4xl mx-auto w-full">
              {/* Question Header */}
              <div className="flex items-center justify-between border-b border-slate-800 pb-4 mb-6">
                <div className="flex items-center gap-4">
                  <div className="w-10 h-10 rounded-lg bg-blue-900/30 text-blue-400 flex items-center justify-center font-bold text-lg">
                    Q{currentIndex + 1}
                  </div>
                  <div>
                    <div className="badge-info text-xs">{question.subject}</div>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <span className="text-xs text-slate-500 font-mono">ID: {question.question_id.slice(0, 8)}</span>
                </div>
              </div>

              {/* Question Content */}
              <div className="text-lg text-white mb-8 leading-relaxed font-medium">
                {question.content?.text}
              </div>

              {/* Options */}
              <div className="space-y-3 mb-8 flex-1">
                {(question.content?.options || []).map((optText: string, i: number) => {
                  const isSelected = question.selected_option === i;
                  return (
                    <div
                      key={i}
                      className={`question-option ${isSelected ? 'selected' : ''}`}
                      onClick={() => handleOptionSelect(i)}
                    >
                      <div className={`w-6 h-6 rounded-full border flex items-center justify-center shrink-0 mt-0.5 text-xs font-bold transition-colors ${
                        isSelected ? 'bg-blue-600 border-blue-600 text-white' : 'border-slate-600 text-slate-400'
                      }`}>
                        {String.fromCharCode(65 + i)}
                      </div>
                      <div className={isSelected ? 'text-blue-100 font-medium' : 'text-slate-300'}>
                        {optText}
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Bottom Actions */}
              <div className="flex items-center justify-between border-t border-slate-800 pt-6">
                <div className="flex gap-3">
                  <button className="btn btn-ghost text-sm" onClick={handleClearResponse} disabled={question.selected_option === null}>
                    Clear Response
                  </button>
                  <button
                    className={`btn text-sm ${question.is_marked_review ? 'btn-ghost border-amber-500/50 text-amber-400' : 'btn-ghost'}`}
                    onClick={handleMarkReview}
                  >
                    <Flag className="w-4 h-4" />
                    {question.is_marked_review ? 'Unmark for Review' : 'Mark for Review'}
                  </button>
                </div>
                <div className="flex gap-3">
                  <button
                    className="btn btn-primary"
                    onClick={() => {
                      if (currentIndex < totalQuestions - 1) loadQuestion(currentIndex + 1);
                    }}
                    disabled={currentIndex === totalQuestions - 1}
                  >
                    Save & Next →
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Right: Navigation Palette */}
        <div className="w-80 bg-slate-900 border-l border-blue-900/30 flex flex-col shrink-0">
          <div className="p-4 border-b border-blue-900/20">
            <h3 className="font-bold text-white text-sm mb-3">Question Palette</h3>
            <div className="grid grid-cols-2 gap-2 text-xs">
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded bg-emerald-500/20 border border-emerald-500" /> Answered
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded bg-amber-500/20 border border-amber-500" /> Marked
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded bg-slate-800 border border-slate-600" /> Unanswered
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded bg-blue-500/20 border border-blue-500" /> Current
              </div>
            </div>
          </div>
          <div className="p-4 flex-1 overflow-y-auto">
            <div className="flex flex-wrap gap-2">
              {Array.from({ length: totalQuestions }).map((_, i) => {
                const status = statusMap[i];
                let className = 'question-nav-btn ';
                if (i === currentIndex) className += 'current';
                else if (status === 'answered') className += 'answered';
                else if (status === 'marked') className += 'marked';

                return (
                  <button
                    key={i}
                    className={className}
                    onClick={() => loadQuestion(i)}
                  >
                    {i + 1}
                  </button>
                );
              })}
            </div>
          </div>
          <div className="p-4 border-t border-blue-900/20 bg-slate-950">
            <div className="text-xs text-slate-500 flex items-center justify-center gap-2">
              <Shield className="w-3.5 h-3.5" />
              Connection Secure
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
