import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { questionsApi } from '../../services/api';
import { useAuthStore } from '../../stores/authStore';
import {
  Shield,
  FileCheck,
  CheckCircle2,
  XCircle,
  AlertCircle,
  Clock,
  ArrowLeft,
  BookOpen,
  LogOut,
  ChevronRight,
} from 'lucide-react';

export default function ReviewerPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { user, logout } = useAuthStore();
  const [selectedAssignment, setSelectedAssignment] = useState<any>(null);
  const [reviewVerdict, setReviewVerdict] = useState<'APPROVED' | 'REJECTED' | 'NEEDS_REVISION'>('APPROVED');
  const [reviewComments, setReviewComments] = useState('');
  const [actionError, setActionError] = useState<string | null>(null);

  // Fetch reviewer's active and historical assignments
  const {
    data: assignments = [],
    isLoading,
    error,
  } = useQuery({
    queryKey: ['myAssignments'],
    queryFn: () => questionsApi.getMyAssignments().then((r) => r.data),
  });

  // Fetch question detail when an assignment is selected
  const {
    data: questionDetail,
    isLoading: isQuestionLoading,
  } = useQuery({
    queryKey: ['questionDetail', selectedAssignment?.question_id],
    queryFn: () => questionsApi.getDetail(selectedAssignment.question_id).then((r) => r.data),
    enabled: !!selectedAssignment,
  });

  // Mutation to start review (ACTIVE -> IN_REVIEW)
  const startReviewMutation = useMutation({
    mutationFn: (assignmentId: string) => questionsApi.startReview(assignmentId),
    onSuccess: (res) => {
      setActionError(null);
      queryClient.invalidateQueries({ queryKey: ['myAssignments'] });
      if (selectedAssignment) {
        setSelectedAssignment({ ...selectedAssignment, assignment_status: res.data.status });
      }
    },
    onError: (err: any) => {
      setActionError(err?.response?.data?.detail || 'Failed to start review session.');
    },
  });

  // Mutation to submit review verdict (IN_REVIEW -> COMPLETED)
  const submitReviewMutation = useMutation({
    mutationFn: () => {
      if (!selectedAssignment) throw new Error('No assignment selected');
      return questionsApi.submitReview(
        selectedAssignment.question_id,
        selectedAssignment.assignment_id,
        reviewVerdict,
        reviewComments
      );
    },
    onSuccess: () => {
      setActionError(null);
      setReviewComments('');
      queryClient.invalidateQueries({ queryKey: ['myAssignments'] });
      setSelectedAssignment(null);
    },
    onError: (err: any) => {
      setActionError(err?.response?.data?.detail || 'Failed to submit review.');
    },
  });

  const completedCount = assignments.filter((a: any) => a.assignment_status === 'COMPLETED').length;
  const inReviewCount = assignments.filter((a: any) => a.assignment_status === 'IN_REVIEW').length;
  const activeCount = assignments.filter((a: any) => a.assignment_status === 'ACTIVE').length;
  const progressPercent = assignments.length > 0 ? Math.round((completedCount / assignments.length) * 100) : 0;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col">
      {/* Top Header */}
      <header className="border-b border-slate-800 bg-slate-900/60 backdrop-blur-sm sticky top-0 z-20 px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-blue-500/20 text-blue-400 flex items-center justify-center font-bold">
            <FileCheck className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-base font-bold text-white flex items-center gap-2">
              B-SEA Reviewer Portal
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-medium bg-blue-500/20 text-blue-300 border border-blue-500/30">
                COMPARTMENTALIZED SHARD
              </span>
            </h1>
            <p className="text-xs text-slate-400">
              Logged in as <span className="text-slate-200 font-semibold">{user?.full_name || user?.username}</span> ({user?.role})
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => navigate('/admin')}
            className="btn btn-ghost text-xs flex items-center gap-1.5"
            title="Return to administrative dashboard if authorized"
          >
            <ArrowLeft className="w-3.5 h-3.5" /> Dashboard
          </button>
          <button
            onClick={() => {
              logout();
              navigate('/login');
            }}
            className="btn btn-ghost text-xs text-red-400 hover:text-red-300 flex items-center gap-1.5"
          >
            <LogOut className="w-3.5 h-3.5" /> Logout
          </button>
        </div>
      </header>

      {/* Main Reviewer Content */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-6 grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Shard Assignments List & Progress (5 cols) */}
        <div className="lg:col-span-5 space-y-6">
          {/* Progress Card */}
          <div className="card-elevated p-5 space-y-3">
            <div className="flex items-center justify-between text-xs">
              <span className="font-semibold text-slate-300">Review Shard Progress</span>
              <span className="font-mono text-blue-400 font-bold">{progressPercent}%</span>
            </div>
            <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden">
              <div
                className="bg-blue-500 h-full transition-all duration-300 ease-out"
                style={{ width: `${progressPercent}%` }}
              />
            </div>
            <div className="grid grid-cols-3 gap-2 pt-1 text-center text-[11px]">
              <div className="p-2 rounded bg-slate-900/60 border border-slate-800">
                <div className="font-mono font-bold text-slate-300 text-sm">{activeCount}</div>
                <div className="text-slate-500">Pending</div>
              </div>
              <div className="p-2 rounded bg-amber-500/10 border border-amber-500/30">
                <div className="font-mono font-bold text-amber-400 text-sm">{inReviewCount}</div>
                <div className="text-amber-500/80">In Review</div>
              </div>
              <div className="p-2 rounded bg-emerald-500/10 border border-emerald-500/30">
                <div className="font-mono font-bold text-emerald-400 text-sm">{completedCount}</div>
                <div className="text-emerald-500/80">Completed</div>
              </div>
            </div>
          </div>

          {/* Assignments List */}
          <div className="card-elevated p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <h2 className="font-bold text-sm text-white flex items-center gap-2">
                <BookOpen className="w-4 h-4 text-blue-400" />
                My Assigned Questions ({assignments.length})
              </h2>
              <span className="text-[11px] text-slate-400">Scoped to your active shard</span>
            </div>

            {isLoading ? (
              <div className="py-8 text-center text-slate-400 text-xs flex flex-col items-center gap-2">
                <Shield className="w-5 h-5 animate-spin text-blue-400" />
                <span>Loading assigned questions...</span>
              </div>
            ) : error ? (
              <div className="p-3 rounded bg-red-950/30 border border-red-900/40 text-xs text-red-300">
                Failed to load assignments.
              </div>
            ) : assignments.length === 0 ? (
              <div className="py-8 text-center text-slate-500 text-xs">
                No questions currently assigned to your review shard.
              </div>
            ) : (
              <div className="space-y-2 max-h-[500px] overflow-y-auto pr-1">
                {assignments.map((item: any) => {
                  const isSelected = selectedAssignment?.assignment_id === item.assignment_id;
                  return (
                    <button
                      key={item.assignment_id}
                      onClick={() => {
                        setSelectedAssignment(item);
                        setActionError(null);
                      }}
                      className={`w-full text-left p-3.5 rounded-lg border transition-all duration-150 flex items-center justify-between ${
                        isSelected
                          ? 'bg-blue-950/40 border-blue-500/50 shadow-md'
                          : 'bg-slate-900/40 border-slate-800 hover:border-slate-700 hover:bg-slate-900/80'
                      }`}
                    >
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <span className="font-semibold text-xs text-white">
                            {item.question.subject}
                          </span>
                          <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300 uppercase">
                            {item.question.difficulty}
                          </span>
                          <span className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-purple-500/10 text-purple-300 border border-purple-500/30">
                            {item.purpose.replace('_', ' ')}
                          </span>
                        </div>
                        <div className="text-xs text-slate-400 line-clamp-1">
                          {item.question.topic || 'General item'}
                        </div>
                      </div>

                      <div className="flex items-center gap-2">
                        {item.assignment_status === 'COMPLETED' ? (
                          <span className="flex items-center gap-1 text-[11px] text-emerald-400 font-medium">
                            <CheckCircle2 className="w-3.5 h-3.5" /> Reviewed
                          </span>
                        ) : item.assignment_status === 'IN_REVIEW' ? (
                          <span className="flex items-center gap-1 text-[11px] text-amber-400 font-medium">
                            <Clock className="w-3.5 h-3.5" /> In Review
                          </span>
                        ) : (
                          <span className="text-[11px] text-slate-400">Assigned</span>
                        )}
                        <ChevronRight className="w-4 h-4 text-slate-600" />
                      </div>
                    </button>
                  );
                })}
              </div>
            )}
          </div>
        </div>

        {/* Right Column: Question Review Action Area (7 cols) */}
        <div className="lg:col-span-7">
          {selectedAssignment ? (
            <div className="card-elevated p-6 space-y-6">
              {/* Question Header */}
              <div className="flex items-center justify-between border-b border-slate-800 pb-4">
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="font-bold text-base text-white">
                      {selectedAssignment.question.subject}
                    </h3>
                    <span className="px-2 py-0.5 rounded text-xs font-mono bg-blue-500/10 text-blue-400 border border-blue-500/30 uppercase">
                      {selectedAssignment.purpose.replace('_', ' ')}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Topic: {selectedAssignment.question.topic || 'N/A'} • Marks: +{selectedAssignment.question.marks_positive} / -{selectedAssignment.question.marks_negative}
                  </p>
                </div>

                <div className="text-right text-xs">
                  <span className="text-slate-400">Status: </span>
                  <span className="font-mono font-bold text-white uppercase">
                    {selectedAssignment.assignment_status}
                  </span>
                </div>
              </div>

              {/* Question Content Display */}
              {isQuestionLoading ? (
                <div className="py-12 text-center text-slate-400 text-xs flex flex-col items-center gap-2">
                  <Shield className="w-6 h-6 animate-spin text-blue-400" />
                  <span>Loading question content securely...</span>
                </div>
              ) : questionDetail ? (
                <div className="space-y-4">
                  <div className="p-4 rounded-lg bg-slate-900/80 border border-slate-800">
                    <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                      Question Text
                    </div>
                    <div className="text-sm text-slate-200 leading-relaxed font-serif whitespace-pre-wrap">
                      {questionDetail.content?.text || 'No question text provided.'}
                    </div>
                  </div>

                  {/* MCQ Options if available */}
                  {Array.isArray(questionDetail.content?.options) && questionDetail.content.options.length > 0 && (
                    <div className="space-y-2">
                      <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                        Response Options
                      </div>
                      <div className="grid grid-cols-1 gap-2">
                        {questionDetail.content.options.map((opt: string, idx: number) => (
                          <div
                            key={idx}
                            className="p-3 rounded bg-slate-900/50 border border-slate-800 text-xs text-slate-300 flex items-center gap-3"
                          >
                            <span className="w-5 h-5 rounded-full bg-slate-800 text-slate-300 flex items-center justify-center font-mono font-bold text-[11px] shrink-0">
                              {String.fromCharCode(65 + idx)}
                            </span>
                            <span>{opt}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Answer Key Non-Disclosure Reminder */}
                  <div className="p-3 rounded bg-slate-900/40 border border-slate-800 text-[11px] text-slate-500 flex items-center gap-2">
                    <Shield className="w-4 h-4 text-emerald-400 shrink-0" />
                    <span>
                      Answer keys are strictly isolated in a protected store and are never exposed to review interfaces.
                    </span>
                  </div>
                </div>
              ) : (
                <div className="text-xs text-red-400">Failed to load question detail.</div>
              )}

              {/* Action Area based on Assignment Status */}
              {selectedAssignment.assignment_status === 'ACTIVE' ? (
                <div className="p-4 rounded-lg bg-blue-950/20 border border-blue-900/30 flex items-center justify-between">
                  <div className="text-xs text-slate-300">
                    Ready to evaluate this question. Starting review will transition status to{' '}
                    <span className="font-mono text-amber-400 font-semibold">IN_REVIEW</span>.
                  </div>
                  <button
                    onClick={() => startReviewMutation.mutate(selectedAssignment.assignment_id)}
                    disabled={startReviewMutation.isPending}
                    className="btn btn-primary text-xs font-semibold px-4 py-2 flex items-center gap-1.5"
                  >
                    {startReviewMutation.isPending ? 'Starting...' : 'Start Review'}
                  </button>
                </div>
              ) : selectedAssignment.assignment_status === 'IN_REVIEW' ? (
                <div className="space-y-4 pt-2 border-t border-slate-800">
                  <h4 className="text-xs font-bold text-white uppercase tracking-wider">
                    Submit Review Verdict
                  </h4>

                  <div className="grid grid-cols-3 gap-2">
                    <button
                      type="button"
                      onClick={() => setReviewVerdict('APPROVED')}
                      className={`p-2.5 rounded-lg border text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors ${
                        reviewVerdict === 'APPROVED'
                          ? 'bg-emerald-500/20 border-emerald-500 text-emerald-300'
                          : 'bg-slate-900/60 border-slate-800 text-slate-400 hover:border-slate-700'
                      }`}
                    >
                      <CheckCircle2 className="w-4 h-4" /> Approve
                    </button>
                    <button
                      type="button"
                      onClick={() => setReviewVerdict('NEEDS_REVISION')}
                      className={`p-2.5 rounded-lg border text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors ${
                        reviewVerdict === 'NEEDS_REVISION'
                          ? 'bg-amber-500/20 border-amber-500 text-amber-300'
                          : 'bg-slate-900/60 border-slate-800 text-slate-400 hover:border-slate-700'
                      }`}
                    >
                      <AlertCircle className="w-4 h-4" /> Revise
                    </button>
                    <button
                      type="button"
                      onClick={() => setReviewVerdict('REJECTED')}
                      className={`p-2.5 rounded-lg border text-xs font-semibold flex items-center justify-center gap-1.5 transition-colors ${
                        reviewVerdict === 'REJECTED'
                          ? 'bg-red-500/20 border-red-500 text-red-300'
                          : 'bg-slate-900/60 border-slate-800 text-slate-400 hover:border-slate-700'
                      }`}
                    >
                      <XCircle className="w-4 h-4" /> Reject
                    </button>
                  </div>

                  <div>
                    <label className="form-label text-xs">Review Comments / Justification</label>
                    <textarea
                      rows={3}
                      className="form-input text-xs"
                      placeholder="Specify rationale for verdict, syllabus alignment notes, or required revisions..."
                      value={reviewComments}
                      onChange={(e) => setReviewComments(e.target.value)}
                    />
                  </div>

                  {actionError && (
                    <div className="p-2.5 rounded bg-red-950/40 border border-red-900/50 text-xs text-red-300">
                      {actionError}
                    </div>
                  )}

                  <button
                    onClick={() => submitReviewMutation.mutate()}
                    disabled={submitReviewMutation.isPending}
                    className="btn btn-primary w-full text-xs font-semibold py-2.5 flex items-center justify-center gap-1.5"
                  >
                    {submitReviewMutation.isPending ? 'Submitting Review...' : 'Finalize & Submit Verdict'}
                  </button>
                </div>
              ) : (
                <div className="p-4 rounded-lg bg-emerald-950/20 border border-emerald-900/40 text-xs text-emerald-300 flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 shrink-0" />
                  <span>This assignment has been completed. Your review has been recorded in the central audit ledger.</span>
                </div>
              )}
            </div>
          ) : (
            <div className="card-elevated h-full min-h-[400px] flex flex-col items-center justify-center text-center p-8 text-slate-500">
              <FileCheck className="w-12 h-12 mb-3 text-slate-700" />
              <h3 className="text-sm font-semibold text-slate-400 mb-1">No Question Selected</h3>
              <p className="text-xs max-w-sm">
                Select a question from your assigned shard on the left to inspect its content and submit your evaluation.
              </p>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
