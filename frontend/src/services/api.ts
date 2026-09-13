import axios from 'axios';

const api = axios.create({
  baseURL: '/api/v1',
  headers: { 'Content-Type': 'application/json' },
  timeout: 30000,
});

// Attach auth token to every request
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('bsea_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Handle 401 globally
api.interceptors.response.use(
  (res) => res,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('bsea_token');
      localStorage.removeItem('bsea_user');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

export default api;

// ── Auth ──────────────────────────────────────────────────────────────────────
export const authApi = {
  login: (username: string, password: string) =>
    api.post('/auth/login', { username, password }),
  verifyMfa: (user_id: string, totp_code: string) =>
    api.post('/auth/mfa/verify', { user_id, totp_code }),
  getMe: () => api.get('/auth/me'),
  setupMfa: () => api.post('/auth/mfa/setup'),
  enableMfa: (totp_code: string) => api.post('/auth/mfa/enable', { totp_code }),
};

// ── Exams ─────────────────────────────────────────────────────────────────────
export const examsApi = {
  list: () => api.get('/exams/'),
  get: (id: string) => api.get(`/exams/${id}`),
  create: (data: any) => api.post('/exams/', data),
  createBlueprint: (examId: string, data: any) =>
    api.post(`/exams/${examId}/blueprint`, data),
  approveBlueprint: (examId: string) =>
    api.post(`/exams/${examId}/blueprint/approve`),
  generateForms: (examId: string) =>
    api.post(`/exams/${examId}/forms/generate`),
};

// ── Questions ─────────────────────────────────────────────────────────────────
export const questionsApi = {
  list: (examId: string) => api.get(`/questions/exam/${examId}`),
  getDetail: (id: string) => api.get(`/questions/${id}`),
  getMyAssignments: (examId?: string) =>
    api.get('/questions/assignments/me' + (examId ? `?exam_id=${encodeURIComponent(examId)}` : '')),
  create: (data: any) => api.post('/questions/', data),
  submit: (id: string) => api.post(`/questions/${id}/submit`),
  startReview: (assignmentId: string) => api.post(`/questions/assignments/${assignmentId}/start`),
  submitReview: (questionId: string, assignmentId: string, verdict: string, comments?: string) =>
    api.post(`/questions/${questionId}/review`, { assignment_id: assignmentId, verdict, comments }),
  approve: (id: string, comments: string) =>
    api.post(`/questions/${id}/approve`, { verdict: 'APPROVED', comments }),
  reject: (id: string, comments: string) =>
    api.post(`/questions/${id}/reject`, { verdict: 'REJECTED', comments }),
  shard: (examId: string, data: any) => api.post(`/questions/exam/${examId}/shard`, data),
  assign: (questionId: string, data: any) => api.post(`/questions/${questionId}/assign`, data),
  reassign: (assignmentId: string, data: any) =>
    api.post(`/questions/assignments/${assignmentId}/reassign`, data),
};

// ── Release ───────────────────────────────────────────────────────────────────
export const releaseApi = {
  getStatus: (examId: string) => api.get(`/release/${examId}/status`),
  approve: (examId: string) => api.post(`/release/${examId}/approve`),
  check: (examId: string) => api.post(`/release/${examId}/check`),
  freeze: (examId: string, reason: string) =>
    api.post(`/release/${examId}/freeze`, { reason }),
};

// ── Candidate CBT ─────────────────────────────────────────────────────────────
export const candidateApi = {
  login: (registration_number: string, password: string, exam_id: string) =>
    api.post('/candidate/auth/login', { registration_number, password, exam_id }),
  getQuestion: (index: number, token: string) =>
    api.get(`/candidate/session/question/${index}?session_token=${token}`),
  saveResponse: (token: string, question_id: string, selected_option: number | null, is_marked_review: boolean) =>
    api.post('/candidate/session/response', { session_token: token, question_id, selected_option, is_marked_review }),
  heartbeat: (token: string, index: number, violations: number, tabSwitches: number) =>
    api.post('/candidate/session/heartbeat', {
      session_token: token,
      current_question_index: index,
      security_violations: violations,
      tab_switch_count: tabSwitches,
    }),
  submit: (token: string) =>
    api.post('/candidate/session/submit', { session_token: token, current_question_index: 0 }),
  getResult: (token: string) =>
    api.get(`/candidate/session/result?session_token=${encodeURIComponent(token)}`),
  reportEvent: (token: string, event_type: string, details?: any) =>
    api.post('/candidate/session/event', { session_token: token, event_type, details }),
};

// ── Security ──────────────────────────────────────────────────────────────────
export const securityApi = {
  getStats: () => api.get('/security/events'),
  getEvents: () => api.get('/security/events/list'),
};

// ── Audit ─────────────────────────────────────────────────────────────────────
export const auditApi = {
  getLogs: (limit = 100) => api.get(`/audit/logs?limit=${limit}`),
  verifyChain: () => api.get('/audit/verify'),
};

// ── Incidents ─────────────────────────────────────────────────────────────────
export const incidentsApi = {
  list: () => api.get('/incidents/'),
  create: (data: any) => api.post('/incidents/', data),
  executeAction: (id: string, action: string, target_id: string, reason: string) =>
    api.post(`/incidents/${id}/action`, { action, target_id, reason }),
};

// ── Dashboard ─────────────────────────────────────────────────────────────────
export const dashboardApi = {
  overview: () => api.get('/dashboard/overview'),
};

// ── Users ─────────────────────────────────────────────────────────────────────
export const usersApi = {
  list: () => api.get('/users/'),
  create: (data: any) => api.post('/users/', data),
  lock: (id: string) => api.post(`/users/${id}/lock`),
  unlock: (id: string) => api.post(`/users/${id}/unlock`),
};
