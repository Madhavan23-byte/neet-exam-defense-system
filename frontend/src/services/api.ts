import axios from 'axios';

// B-SEA Backend API endpoint configuration (Vercel Production & Local Parity)
// Verified active Cloudflare edge tunnel for the live demonstrator
export const DEFAULT_BACKEND_URL = 'https://rehabilitation-wins-convergence-addresses.trycloudflare.com';

/**
 * Returns the authoritative backend base URL.
 * Precedence:
 * 1. Runtime override stored in localStorage (`bsea_backend_url`) - allows instant demo reconnection
 * 2. Vite environment variable (`VITE_API_URL`)
 * 3. Default verified active Cloudflare tunnel URL
 */
export const getActiveBackendUrl = (): string => {
  if (typeof window !== 'undefined') {
    const custom = localStorage.getItem('bsea_backend_url');
    if (custom && custom.trim() !== '') {
      return custom.trim().replace(/\/+$/, '');
    }
  }
  const configuredUrl = import.meta.env.VITE_API_URL;
  if (configuredUrl !== undefined && configuredUrl.trim() !== '') {
    return configuredUrl.trim().replace(/\/+$/, '');
  }
  return DEFAULT_BACKEND_URL.trim().replace(/\/+$/, '');
};

export const setCustomBackendUrl = (url: string): void => {
  if (typeof window !== 'undefined') {
    const clean = url.trim().replace(/\/+$/, '');
    localStorage.setItem('bsea_backend_url', clean);
  }
};

export const resetBackendUrl = (): void => {
  if (typeof window !== 'undefined') {
    localStorage.removeItem('bsea_backend_url');
  }
};

const initialBaseUrl = getActiveBackendUrl();

const api = axios.create({
  baseURL: initialBaseUrl ? `${initialBaseUrl}/api/v1` : '/api/v1',
  headers: { 'Content-Type': 'application/json' },
  timeout: 30000,
});

// Attach auth token and dynamically ensure authoritative base URL
api.interceptors.request.use((config) => {
  const activeBase = getActiveBackendUrl();
  if (activeBase && !config.url?.startsWith('http://') && !config.url?.startsWith('https://')) {
    config.baseURL = `${activeBase}/api/v1`;
  }
  const token = typeof window !== 'undefined' ? localStorage.getItem('bsea_token') : null;
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Response interceptor: Global error classification and SPA catch-all HTML detection
api.interceptors.response.use(
  (res) => {
    // If an API request receives an HTML document instead of JSON (typical when backend is offline on SPA hosts)
    if (
      typeof res.data === 'string' &&
      (res.data.trim().toLowerCase().startsWith('<!doctype') ||
       res.data.trim().toLowerCase().startsWith('<html'))
    ) {
      const offlineError: any = new Error('Examination backend services are currently unreachable (received SPA HTML).');
      offlineError.isBackendOffline = true;
      offlineError.userMessage = 'Examination backend service is unreachable. The demonstration tunnel may be offline.';
      offlineError.response = {
        status: 503,
        statusText: 'Service Unavailable',
        data: { detail: 'Examination services are currently unavailable. Please verify that the backend daemon and tunnel are active.' },
      };
      return Promise.reject(offlineError);
    }
    return res;
  },
  (error) => {
    // Network / connectivity errors (DNS resolution failure, tunnel terminated, CORS, timeout)
    if (!error.response) {
      error.isNetworkError = true;
      error.isBackendOffline = true;
      if (error.code === 'ECONNABORTED' || error.message?.toLowerCase().includes('timeout')) {
        error.userMessage = 'Request timed out. The demonstration backend is under heavy load or offline.';
      } else {
        error.userMessage = 'Demonstration backend service unreachable. Please ensure the B-SEA backend tunnel is active.';
      }
    } else {
      const status = error.response.status;
      if (status === 401) {
        if (typeof window !== 'undefined') {
          localStorage.removeItem('bsea_token');
          localStorage.removeItem('bsea_user');
          if (!window.location.pathname.includes('/login')) {
            window.location.href = '/login';
          }
        }
        error.userMessage = error.response.data?.detail || 'Authentication required. Please sign in again.';
      } else if (status === 403) {
        error.userMessage = error.response.data?.detail || 'Access denied. You do not possess the required RBAC role permissions.';
      } else if (status === 404) {
        error.userMessage = error.response.data?.detail || 'The requested API route was not found on the server.';
      } else if (status === 405) {
        error.userMessage = 'API method not allowed (HTTP 405).';
      } else if (status === 409) {
        error.userMessage = error.response.data?.detail || 'Active session conflict: Another terminal is already active for this candidate.';
      } else if (status >= 500) {
        error.userMessage = error.response.data?.detail || `Demonstration gateway error (HTTP ${status}). The backend service is unreachable.`;
      } else {
        error.userMessage = error.response.data?.detail || error.message || 'An error occurred during API communication.';
      }
    }
    return Promise.reject(error);
  }
);

export default api;

export const healthApi = {
  checkReady: async (baseUrl?: string) => {
    const base = baseUrl ? baseUrl.replace(/\/+$/, '') : getActiveBackendUrl();
    const res = await axios.get(`${base}/health/ready`, { timeout: 8000 });
    return res.data;
  },
  checkLive: async (baseUrl?: string) => {
    const base = baseUrl ? baseUrl.replace(/\/+$/, '') : getActiveBackendUrl();
    const res = await axios.get(`${base}/health`, { timeout: 8000 });
    return res.data;
  },
};

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
  getDetail: (id: string, grantId?: string) =>
    api.get(
      `/questions/${id}${grantId ? `?grant_id=${encodeURIComponent(grantId)}` : ''}`,
      { headers: grantId ? { 'X-Access-Grant-ID': grantId } : {} }
    ),
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
  getExams: () => api.get('/candidate/exams'),
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

// ── Containment (Phase 3C-5E) ─────────────────────────────────────────────────
export interface ContainmentRequestPayload {
  action_type: string;
  incident_id: string;
  target_dict: Record<string, any>;
  justification: string;
  policy_version?: string;
  target_scope_hash?: string;
}

export interface ContainmentAuthorizePayload {
  auth_nonce: string;
  decision?: string;
}

export interface ContainmentExecutePayload {
  target_dict: Record<string, any>;
  execution_nonce?: string;
}

export interface BreakGlassIssuePayload {
  action_type: string;
  incident_id: string;
  target_dict: Record<string, any>;
  fido2_assertion_payload: string;
  justification?: string;
}

export const containmentApi = {
  createRequest: (data: ContainmentRequestPayload) =>
    api.post('/containment/requests', data),
  authorizeRequest: (requestId: string, data: ContainmentAuthorizePayload) =>
    api.post(`/containment/requests/${requestId}/authorize`, data),
  executeRequest: (requestId: string, data: ContainmentExecutePayload) =>
    api.post(`/containment/requests/${requestId}/execute`, data),
  getRequest: (requestId: string) =>
    api.get(`/containment/requests/${requestId}`),
  issueBreakGlass: (data: BreakGlassIssuePayload) =>
    api.post('/containment/break-glass/issue', data),
  executeBreakGlass: (data: { token_id: string; action_type: string; incident_id: string; target_dict: Record<string, any> }) =>
    api.post('/containment/break-glass/execute', data),
  reconcile: () =>
    api.post('/containment/reconcile'),
  attest: (data: { target_urn: string; attestation_note: string }) =>
    api.post('/containment/attest', data),
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

// ── Break-Glass & Complete-Paper Exception ────────────────────────────────────
export type BreakGlassScope = 'COMPLETE_EXAM_PAPER' | 'EXAM_FORM_PREVIEW';
export type BreakGlassRequestStatus =
  | 'PENDING'
  | 'APPROVED'
  | 'ACTIVATED'
  | 'EXPIRED'
  | 'REVOKED'
  | 'REJECTED';
export type BreakGlassApprovalDecision = 'APPROVE' | 'REJECT';

export interface BreakGlassApproval {
  id: string;
  request_id: string;
  approver_id: string;
  approver_role: string;
  decision: BreakGlassApprovalDecision;
  comments?: string;
  nonce: string;
  request_fingerprint: string;
  digital_signature: string;
  is_valid: boolean;
  created_at: string;
}

export interface BreakGlassRequest {
  id: string;
  exam_id: string;
  blueprint_id?: string;
  exam_version: number;
  blueprint_hash: string;
  requester_id: string;
  scope: BreakGlassScope;
  form_label?: string;
  justification: string;
  incident_id?: string;
  required_quorum: number;
  min_distinct_roles: number;
  status: BreakGlassRequestStatus;
  requested_duration_minutes: number;
  activation_session_id?: string;
  content_fingerprint: string;
  policy_version: string;
  created_at: string;
  approved_at?: string;
  activated_at?: string;
  expires_at?: string;
  revoked_at?: string;
  revoked_by?: string;
  revocation_reason?: string;
  correlation_id: string;
  approvals_count: number;
  distinct_roles_count: number;
  approvals: BreakGlassApproval[];
}

export interface AssembledQuestion {
  id: string;
  subject: string;
  section?: string;
  difficulty: string;
  content: string;
  options: string[];
  marks: number;
}

export interface AttributionWatermark {
  requester_username: string;
  requester_user_id: string;
  request_id: string;
  activation_session_id: string;
  assembled_at_utc: string;
  expires_at_utc: string;
  audit_ip_hash?: string;
  security_notice: string;
}

export interface AssembledPaperResponse {
  exam_id: string;
  exam_title: string;
  scope: string;
  form_label?: string;
  question_count: number;
  questions: AssembledQuestion[];
  attribution_watermark: AttributionWatermark;
  security_invariant: string;
}

export const breakGlassApi = {
  createRequest: (data: {
    exam_id: string;
    scope: BreakGlassScope;
    justification: string;
    form_label?: string;
    incident_id?: string;
    requested_duration_minutes?: number;
  }) => api.post<BreakGlassRequest>('/break-glass/requests', data),

  listRequests: (examId?: string, statusFilter?: BreakGlassRequestStatus) => {
    const params = new URLSearchParams();
    if (examId) params.append('exam_id', examId);
    if (statusFilter) params.append('status_filter', statusFilter);
    const qs = params.toString();
    return api.get<BreakGlassRequest[]>(`/break-glass/requests${qs ? `?${qs}` : ''}`);
  },

  getRequest: (id: string) =>
    api.get<BreakGlassRequest>(`/break-glass/requests/${id}`),

  approveRequest: (id: string, comments?: string) =>
    api.post<BreakGlassApproval>(`/break-glass/requests/${id}/approve`, { comments }),

  rejectRequest: (id: string, comments?: string) =>
    api.post<BreakGlassApproval>(`/break-glass/requests/${id}/reject`, { comments }),

  activateRequest: (id: string) =>
    api.post<BreakGlassRequest>(`/break-glass/requests/${id}/activate`),

  getAssembledPaper: (id: string) =>
    api.get<AssembledPaperResponse>(`/break-glass/requests/${id}/assembled-paper`),

  revokeRequest: (id: string, reason: string) =>
    api.post<BreakGlassRequest>(`/break-glass/requests/${id}/revoke`, { reason }),
};
