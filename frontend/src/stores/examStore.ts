import { create } from 'zustand';
import { persist } from 'zustand/middleware';

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

export const useExamSessionStore = create<ExamSessionState>()(
  persist(
    (set) => ({
      sessionToken: null,
      sessionId: null,
      examId: null,
      watermarkId: null,
      candidateName: null,
      expiresAt: null,
      totalQuestions: 0,
      durationMinutes: 180,
      setSession: (data: any) =>
        set({
          sessionToken: data.session_token || data.sessionToken || null,
          sessionId: data.session_id || data.sessionId || null,
          examId: data.exam_id || data.examId || null,
          watermarkId: data.watermark_id || data.watermarkId || null,
          candidateName: data.candidate_name || data.candidateName || null,
          expiresAt: data.expires_at || data.expiresAt || null,
          totalQuestions: data.total_questions ?? data.totalQuestions ?? 0,
          durationMinutes: data.duration_minutes ?? data.durationMinutes ?? 180,
        }),
      clearSession: () =>
        set({
          sessionToken: null,
          sessionId: null,
          examId: null,
          watermarkId: null,
          candidateName: null,
          expiresAt: null,
          totalQuestions: 0,
        }),
    }),
    {
      name: 'bsea_candidate_session',
      partialize: (state) => ({
        sessionToken: state.sessionToken,
        sessionId: state.sessionId,
        examId: state.examId,
        watermarkId: state.watermarkId,
        candidateName: state.candidateName,
        expiresAt: state.expiresAt,
        totalQuestions: state.totalQuestions,
        durationMinutes: state.durationMinutes,
      }),
    }
  )
);
