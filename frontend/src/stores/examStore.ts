import { create } from 'zustand';

interface ExamSessionState {
  sessionToken: string | null;
  sessionId: string | null;
  examId: string | null;
  watermarkId: string | null;
  candidateName: string | null;
  expiresAt: string | null;
  totalQuestions: number;
  durationMinutes: number;
  setSession: (data: any) => void;
  clearSession: () => void;
}

export const useExamSessionStore = create<ExamSessionState>((set) => ({
  sessionToken: null,
  sessionId: null,
  examId: null,
  watermarkId: null,
  candidateName: null,
  expiresAt: null,
  totalQuestions: 0,
  durationMinutes: 180,
  setSession: (data) => set({
    sessionToken: data.session_token,
    sessionId: data.session_id,
    examId: data.exam_id,
    watermarkId: data.watermark_id,
    candidateName: data.candidate_name,
    expiresAt: data.expires_at,
    totalQuestions: data.total_questions,
    durationMinutes: data.duration_minutes,
  }),
  clearSession: () => set({
    sessionToken: null,
    sessionId: null,
    examId: null,
    watermarkId: null,
    candidateName: null,
    expiresAt: null,
    totalQuestions: 0,
  }),
}));
