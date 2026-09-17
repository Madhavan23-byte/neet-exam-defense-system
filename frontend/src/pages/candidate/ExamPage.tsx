import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Shield, Clock, AlertTriangle, CheckSquare, Flag, Send,
  ChevronLeft, ChevronRight, CheckCircle2, RotateCcw, HelpCircle
} from 'lucide-react';
import { candidateApi } from '../../services/api';
import { useExamSessionStore } from '../../stores/examStore';
import CbtPalette, { type QuestionStatus } from '../../components/exam/CbtPalette';
import ActionModal from '../../components/ui/ActionModal';

export default function ExamPage() {
  const navigate = useNavigate();
  const {
    sessionToken,
    totalQuestions: initialTotal,
    candidateName,
    watermarkId,
    expiresAt,
    clearSession,
  } = useExamSessionStore();

  const [currentIndex, setCurrentIndex] = useState(0);
  const [totalQuestions, setTotalQuestions] = useState(initialTotal || 1);
  const [question, setQuestion] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);

  // Status map for palette
  const [statusMap, setStatusMap] = useState<Record<number, QuestionStatus>>({});
  // Dynamic subjects cache (Constraint 2: derived dynamically from actual questions)
  const [subjectsMap, setSubjectsMap] = useState<Record<number, string>>({});
  const [activeSubject, setActiveSubject] = useState<string>('');

  // Security violations & tab switches
  const [violations, setViolations] = useState(0);
  const [tabSwitches, setTabSwitches] = useState(0);

  // Timer
  const [timeLeftSec, setTimeLeftSec] = useState<number>(() => {
    if (expiresAt) {
      const ms = new Date(expiresAt).getTime() - Date.now();
      return Math.max(0, Math.floor(ms / 1000));
    }
    return 180 * 60; // 3 hours fallback
  });

  // Submission modal state
  const [showSubmitModal, setShowSubmitModal] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  // Redirect if no session token
  useEffect(() => {
    if (!sessionToken) {
      navigate('/candidate/login');
    }
  }, [sessionToken, navigate]);

  // Load question by index
  const loadQuestion = useCallback(async (index: number) => {
    if (!sessionToken) return;
    setLoading(true);
    setError('');

    try {
      const res = await candidateApi.getQuestion(index, sessionToken);
      const data = res.data;
      setQuestion(data);
      if (data.total_questions) {
        setTotalQuestions(data.total_questions);
      }

      // Record dynamic subject
      const subj = data.subject || 'General Section';
      setSubjectsMap((prev) => ({ ...prev, [index]: subj }));
      if (!activeSubject) {
        setActiveSubject(subj);
      }

      // Update palette status
      setStatusMap((prev) => {
        const current = prev[index];
        if (!current || current === 'not-visited') {
          return {
            ...prev,
            [index]: data.selected_option !== null && data.selected_option !== undefined
              ? (data.is_marked_review ? 'marked-answered' : 'answered')
              : 'not-answered',
          };
        }
        return prev;
      });
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || 'Error retrieving question');
    } finally {
      setLoading(false);
    }
  }, [sessionToken, activeSubject]);

  useEffect(() => {
    loadQuestion(currentIndex);
  }, [currentIndex, loadQuestion]);

  // Security monitoring: visibilitychange
  useEffect(() => {
    const handleVisibilityChange = () => {
      if (document.hidden && sessionToken) {
        setTabSwitches((prev) => {
          const nw = prev + 1;
          candidateApi.reportEvent(sessionToken, 'TAB_SWITCH', { tabSwitches: nw }).catch(() => {});
          return nw;
        });
      }
    };
    document.addEventListener('visibilitychange', handleVisibilityChange);
    return () => document.removeEventListener('visibilitychange', handleVisibilityChange);
  }, [sessionToken]);

  // Heartbeat every 20 seconds
  useEffect(() => {
    if (!sessionToken) return;
    const interval = setInterval(() => {
      candidateApi.heartbeat(sessionToken, currentIndex, violations, tabSwitches).catch(() => {});
    }, 20000);
    return () => clearInterval(interval);
  }, [sessionToken, currentIndex, violations, tabSwitches]);

  // Timer countdown
  useEffect(() => {
    if (timeLeftSec <= 0) return;
    const timer = setInterval(() => {
      setTimeLeftSec((prev) => {
        if (prev <= 1) {
          clearInterval(timer);
          return 0;
        }
        return prev - 1;
      });
    }, 1000);
    return () => clearInterval(timer);
  }, [timeLeftSec]);

  const formatTimer = (totalSec: number) => {
    const h = Math.floor(totalSec / 3600);
    const m = Math.floor((totalSec % 3600) / 60);
    const s = totalSec % 60;
    return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
  };

  // Actions
  const handleSelectOption = async (optIndex: number) => {
    if (!question || !sessionToken) return;
    setSaving(true);
    try {
      await candidateApi.saveResponse(sessionToken, question.question_id, optIndex, question.is_marked_review || false);
      setQuestion((prev: any) => ({ ...prev, selected_option: optIndex }));
      setStatusMap((prev) => ({
        ...prev,
        [currentIndex]: prev[currentIndex] === 'marked' || prev[currentIndex] === 'marked-answered'
          ? 'marked-answered'
          : 'answered',
      }));
    } catch (err: any) {
      console.error('Failed to save response:', err);
    } finally {
      setSaving(false);
    }
  };

  const handleClearResponse = async () => {
    if (!question || !sessionToken) return;
    setSaving(true);
    try {
      await candidateApi.saveResponse(sessionToken, question.question_id, null, question.is_marked_review || false);
      setQuestion((prev: any) => ({ ...prev, selected_option: null }));
      setStatusMap((prev) => ({
        ...prev,
        [currentIndex]: prev[currentIndex] === 'marked-answered' || prev[currentIndex] === 'marked'
          ? 'marked'
          : 'not-answered',
      }));
    } catch (err: any) {
      console.error('Failed to clear response:', err);
    } finally {
      setSaving(false);
    }
  };

  const handleToggleMarkReview = async () => {
    if (!question || !sessionToken) return;
    const newVal = !question.is_marked_review;
    setSaving(true);
    try {
      await candidateApi.saveResponse(sessionToken, question.question_id, question.selected_option, newVal);
      setQuestion((prev: any) => ({ ...prev, is_marked_review: newVal }));
      setStatusMap((prev) => {
        const hasAnswer = question.selected_option !== null && question.selected_option !== undefined;
        if (newVal) {
          return { ...prev, [currentIndex]: hasAnswer ? 'marked-answered' : 'marked' };
        } else {
          return { ...prev, [currentIndex]: hasAnswer ? 'answered' : 'not-answered' };
        }
      });
    } catch (err: any) {
      console.error('Failed to toggle review flag:', err);
    } finally {
      setSaving(false);
    }
  };

  const handleNext = () => {
    if (currentIndex < totalQuestions - 1) {
      setCurrentIndex(currentIndex + 1);
    }
  };

  const handlePrev = () => {
    if (currentIndex > 0) {
      setCurrentIndex(currentIndex - 1);
    }
  };

  const handleSubmitExam = async () => {
    if (!sessionToken) return;
    setSubmitting(true);
    try {
      await candidateApi.submit(sessionToken);
      navigate('/candidate/result');
    } catch (err: any) {
      alert(err?.response?.data?.detail || 'Failed to submit exam');
      setSubmitting(false);
    }
  };

  // Extract unique dynamic subjects
  const availableSubjects = Array.from(new Set(Object.values(subjectsMap)));

  return (
    <div className="min-h-screen flex flex-col bg-[var(--gov-canvas)] relative select-none">
      {/* Subtle Forensic Watermark Overlay */}
      {watermarkId && (
        <div className="pointer-events-none fixed inset-0 z-0 opacity-4 overflow-hidden flex flex-wrap gap-24 p-12 text-slate-900 font-mono text-xs">
          {Array.from({ length: 16 }).map((_, i) => (
            <div key={i} className="transform -rotate-12">
              {watermarkId} • {candidateName || 'Candidate'}
            </div>
          ))}
        </div>
      )}

      {/* CBT Header */}
      <header className="border-b border-[var(--gov-border)] bg-[var(--gov-surface)] px-4 py-3 sticky top-0 z-30 shadow-xs">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-[var(--gov-navy)] text-amber-400 flex items-center justify-center font-bold text-sm">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <div className="text-sm font-bold text-[var(--gov-navy-dark)]">
                B-SEA Computer-Based Test
              </div>
              <div className="text-xs text-slate-500 font-medium">
                Candidate: <span className="text-slate-800 font-semibold">{candidateName || 'Authorized Candidate'}</span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-4">
            {/* Countdown Timer with Empathetic Calm Styling */}
            <div className={`px-3.5 py-1.5 rounded-lg border font-mono font-bold text-sm flex items-center gap-2 ${
              timeLeftSec < 900
                ? 'bg-amber-500/15 text-amber-900 border-amber-500/40 animate-pulse'
                : 'bg-[var(--gov-surface-warm)] text-[var(--gov-navy-dark)] border-[var(--gov-border)]'
            }`}>
              <Clock className="w-4 h-4 text-amber-600" />
              <span>Time Left: {formatTimer(timeLeftSec)}</span>
            </div>

            <button
              onClick={() => setShowSubmitModal(true)}
              className="btn btn-primary text-xs py-2 px-4 shadow-xs"
            >
              <Send className="w-3.5 h-3.5" /> Submit Examination
            </button>
          </div>
        </div>
      </header>

      {/* CBT Main Layout */}
      <main className="flex-1 max-w-7xl mx-auto w-full px-4 py-4 grid grid-cols-1 lg:grid-cols-12 gap-5 relative z-10">
        {/* Question Area (8 cols) */}
        <div className="lg:col-span-8 flex flex-col gap-4">
          {/* Dynamic Subject Bar (Constraint 2) */}
          {availableSubjects.length > 0 && (
            <div className="flex items-center gap-2 border-b border-[var(--gov-border)] pb-2 overflow-x-auto">
              <span className="text-xs font-bold text-slate-500 uppercase tracking-wider mr-1">Section:</span>
              {availableSubjects.map((subj) => (
                <button
                  key={subj}
                  type="button"
                  onClick={() => setActiveSubject(subj)}
                  className={`px-3 py-1 rounded-md text-xs font-semibold transition-colors cursor-pointer ${
                    activeSubject === subj
                      ? 'bg-[var(--gov-navy)] text-white'
                      : 'bg-white text-slate-600 border border-[var(--gov-border)] hover:bg-slate-50'
                  }`}
                >
                  {subj}
                </button>
              ))}
            </div>
          )}

          {/* Question Card */}
          <div className="gov-card flex-1 flex flex-col justify-between min-h-[460px]">
            <div>
              {/* Question Header */}
              <div className="flex items-center justify-between pb-3 border-b border-[var(--gov-border)] mb-4">
                <div className="text-xs font-bold text-[var(--gov-navy)] uppercase tracking-wider">
                  Question {currentIndex + 1} of {totalQuestions}
                </div>
                <div className="flex items-center gap-2 text-xs">
                  {saving && <span className="text-slate-400 italic">Saving response...</span>}
                  <span className="badge-info">{question?.subject || 'Standard'}</span>
                </div>
              </div>

              {loading ? (
                <div className="py-20 text-center text-slate-400 text-xs">
                  Decrypting question securely from KMS...
                </div>
              ) : error ? (
                <div className="p-4 bg-red-50 border border-red-200 rounded-lg text-red-700 text-xs">
                  {error}
                </div>
              ) : question ? (
                <div>
                  <div className="text-sm sm:text-base font-semibold text-[var(--gov-navy-dark)] leading-relaxed mb-6 whitespace-pre-wrap">
                    {question.content?.question_text || question.content?.text || 'Question text not available.'}
                  </div>

                  {/* Options List */}
                  <div className="space-y-3">
                    {question.content?.options &&
                      question.content.options.map((optionText: string, optIdx: number) => {
                        const isSelected = question.selected_option === optIdx;
                        return (
                          <label
                            key={optIdx}
                            onClick={() => handleSelectOption(optIdx)}
                            className={`flex items-start gap-3.5 p-3.5 rounded-lg border text-xs sm:text-sm cursor-pointer transition-all ${
                              isSelected
                                ? 'bg-amber-500/10 border-amber-600/60 shadow-xs font-semibold text-[var(--gov-navy-dark)]'
                                : 'bg-[var(--gov-surface)] border-[var(--gov-border)] hover:bg-slate-50 text-slate-700'
                            }`}
                          >
                            <input
                              type="radio"
                              name="question-option"
                              checked={isSelected}
                              onChange={() => {}}
                              className="mt-0.5 accent-amber-600"
                            />
                            <span className="w-5 font-bold text-slate-500">{String.fromCharCode(65 + optIdx)}.</span>
                            <span className="flex-1">{optionText}</span>
                          </label>
                        );
                      })}
                  </div>
                </div>
              ) : null}
            </div>

            {/* Question Bottom Action Toolbar */}
            <div className="pt-5 mt-6 border-t border-[var(--gov-border)] flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={handleToggleMarkReview}
                  className={`btn text-xs py-1.5 px-3 ${
                    question?.is_marked_review ? 'btn-amber' : 'btn-outline text-slate-600'
                  }`}
                  disabled={loading}
                >
                  <Flag className="w-3.5 h-3.5" />
                  {question?.is_marked_review ? 'Marked for Review' : 'Mark for Review'}
                </button>
                <button
                  type="button"
                  onClick={handleClearResponse}
                  className="btn btn-ghost text-xs py-1.5 px-2.5 text-slate-500"
                  disabled={loading || question?.selected_option === null || question?.selected_option === undefined}
                >
                  <RotateCcw className="w-3.5 h-3.5" /> Clear Response
                </button>
              </div>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={handlePrev}
                  className="btn btn-outline text-xs py-1.5 px-3"
                  disabled={currentIndex === 0 || loading}
                >
                  <ChevronLeft className="w-3.5 h-3.5" /> Previous
                </button>
                <button
                  type="button"
                  onClick={handleNext}
                  className="btn btn-navy text-xs py-1.5 px-4"
                  disabled={currentIndex >= totalQuestions - 1 || loading}
                >
                  Next <ChevronRight className="w-3.5 h-3.5" />
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Question Palette Sidebar (4 cols) */}
        <div className="lg:col-span-4 flex flex-col">
          <CbtPalette
            totalQuestions={totalQuestions}
            currentIndex={currentIndex}
            statusMap={statusMap}
            onSelectIndex={(idx) => setCurrentIndex(idx)}
          />
        </div>
      </main>

      {/* Submission Confirmation Modal */}
      <ActionModal
        isOpen={showSubmitModal}
        onClose={() => setShowSubmitModal(false)}
        title="Confirm Examination Submission"
        subtitle="Please review your attempt status before concluding the exam."
        maxWidth="max-w-md"
      >
        <div className="space-y-4 text-xs">
          <div className="p-3 bg-[var(--gov-surface-warm)] rounded-lg border border-[var(--gov-border)] space-y-2">
            <div className="flex justify-between">
              <span className="text-slate-500 font-semibold">Total Questions:</span>
              <span className="font-bold text-slate-800">{totalQuestions}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500 font-semibold">Answered:</span>
              <span className="font-bold text-emerald-700">
                {Object.values(statusMap).filter((s) => s === 'answered' || s === 'marked-answered').length}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500 font-semibold">Marked for Review:</span>
              <span className="font-bold text-purple-700">
                {Object.values(statusMap).filter((s) => s === 'marked' || s === 'marked-answered').length}
              </span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500 font-semibold">Not Answered:</span>
              <span className="font-bold text-amber-700">
                {totalQuestions - Object.values(statusMap).filter((s) => s === 'answered' || s === 'marked-answered').length}
              </span>
            </div>
          </div>

          <p className="text-slate-600 leading-relaxed">
            Once submitted, your responses will be cryptographically locked and evaluated. You cannot re-enter this examination session.
          </p>

          <div className="pt-2 flex justify-end gap-3">
            <button
              type="button"
              className="btn btn-outline text-xs"
              onClick={() => setShowSubmitModal(false)}
              disabled={submitting}
            >
              Return to Test
            </button>
            <button
              type="button"
              className="btn btn-primary text-xs"
              onClick={handleSubmitExam}
              disabled={submitting}
            >
              {submitting ? 'Submitting Responses...' : 'Confirm Final Submission'}
            </button>
          </div>
        </div>
      </ActionModal>
    </div>
  );
}
