import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import {
  BookOpen, AlertCircle, AlertTriangle, CheckCircle2,
  ArrowRight, RefreshCw, WifiOff, ServerCrash, ShieldAlert
} from 'lucide-react';
import { candidateApi, examsApi } from '../../services/api';
import { useExamSessionStore } from '../../stores/examStore';
import PortalHeader from '../../components/ui/PortalHeader';
import PortalFooter from '../../components/ui/PortalFooter';

export type RegistryStatus =
  | 'loading'          // Connecting to examination registry
  | 'available'        // Verified active exams retrieved
  | 'empty'            // Valid array from server, but 0 exams scheduled
  | 'offline'          // Backend unreachable, connection refused, 405, or non-JSON
  | 'server_error'     // HTTP 5xx from backend
  | 'unauthorized'     // HTTP 401 / 403
  | 'invalid_response';// Received non-array payload format

export default function CandidateLoginPage() {
  const navigate = useNavigate();
  const setSession = useExamSessionStore((state) => state.setSession);

  const [regNumber, setRegNumber] = useState('NEET-2026-000001');
  const [password, setPassword] = useState('Candidate@123');
  const [selectedExamId, setSelectedExamId] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  // Fetch real active exams from backend API with strict validation
  const {
    data: rawExams,
    isLoading: examsLoading,
    isError,
    error: queryError,
    refetch,
    isFetching,
  } = useQuery({
    queryKey: ['candidate-exams'],
    queryFn: async () => {
      const res = await examsApi.list();
      // Check for non-JSON or HTML string response
      if (typeof res.data === 'string') {
        throw new Error('NON_JSON_RESPONSE: Server returned non-JSON content');
      }
      if (Array.isArray(res.data)) {
        return res.data;
      }
      if (res.data && Array.isArray((res.data as any).exams)) {
        return (res.data as any).exams;
      }
      throw new Error('INVALID_PAYLOAD_SHAPE: Expected examination list array');
    },
    retry: 1,
    staleTime: 30000,
  });

  // Defensive array conversion: safeExams is GUARANTEED to be an Array
  const safeExams: any[] = Array.isArray(rawExams) ? rawExams : [];

  // Determine truthful, differentiated registry status
  const getRegistryStatus = (): RegistryStatus => {
    if (examsLoading) return 'loading';
    if (isError) {
      const err = queryError as any;
      const status = err?.response?.status;
      if (status === 401 || status === 403) return 'unauthorized';
      if (status && status >= 500) return 'server_error';
      if (err?.message?.includes('INVALID_PAYLOAD_SHAPE')) return 'invalid_response';
      // Default network failure, offline, 405, or NON_JSON_RESPONSE
      return 'offline';
    }
    if (Array.isArray(rawExams)) {
      return rawExams.length > 0 ? 'available' : 'empty';
    }
    return 'invalid_response';
  };

  const registryStatus = getRegistryStatus();

  // Automatically select the first exam when active exams become available
  useEffect(() => {
    if (registryStatus === 'available' && safeExams.length > 0 && !selectedExamId) {
      setSelectedExamId(safeExams[0].id);
    }
  }, [registryStatus, safeExams, selectedExamId]);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (registryStatus !== 'available' || !selectedExamId) {
      if (registryStatus === 'offline') {
        setError('Examination services are currently unavailable. Please verify network connectivity.');
      } else if (registryStatus === 'server_error') {
        setError('Central examination service error. Please retry shortly.');
      } else if (registryStatus === 'empty') {
        setError('No active examinations are currently open for candidate login.');
      } else {
        setError('Please select an active examination.');
      }
      return;
    }

    setLoading(true);
    try {
      const res = await candidateApi.login(regNumber, password, selectedExamId);
      const data = res.data;

      // Persist candidate session store
      setSession({
        sessionToken: data.session_token,
        examId: selectedExamId,
        candidateName: data.candidate_name,
        watermarkId: data.watermark_id,
        totalQuestions: data.total_questions || 0,
        durationMinutes: data.duration_minutes || 180,
        expiresAt: data.expires_at,
      });

      navigate('/candidate/exam');
    } catch (err: any) {
      if (err?.isBackendOffline || !err?.response || err?.response?.status === 405) {
        setError('Examination services are currently unavailable. Please try again shortly.');
      } else if (err?.response?.status === 409) {
        setError('Active session conflict: Another terminal is already active for this registration ID.');
      } else {
        setError(
          err?.response?.data?.detail || err.message || 'Authentication failed. Please verify Roll Number & Password.'
        );
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col bg-[var(--gov-canvas)]">
      <PortalHeader subtitle="Candidate Computer-Based Test (CBT) Portal" />

      <main className="flex-1 max-w-4xl mx-auto px-4 py-8 sm:py-12 w-full">
        <div className="grid grid-cols-1 md:grid-cols-12 gap-8 items-start">
          {/* Instructions Column */}
          <div className="md:col-span-5 space-y-4">
            <div className="gov-card">
              <h2 className="text-sm font-bold text-[var(--gov-navy-dark)] uppercase tracking-wider mb-3 flex items-center gap-2">
                <BookOpen className="w-4 h-4 text-amber-600" />
                Examination Instructions
              </h2>
              <ul className="space-y-2.5 text-xs text-slate-600 leading-relaxed">
                <li className="flex items-start gap-2">
                  <span className="w-4 h-4 rounded-full bg-amber-500/20 text-amber-900 font-bold text-[10px] flex items-center justify-center shrink-0 mt-0.5">1</span>
                  <span>Ensure your Roll Number matches the entry on your official Admit Card.</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="w-4 h-4 rounded-full bg-amber-500/20 text-amber-900 font-bold text-[10px] flex items-center justify-center shrink-0 mt-0.5">2</span>
                  <span>Do not refresh, close, or switch browser tabs during active testing.</span>
                </li>
                <li className="flex items-start gap-2">
                  <span className="w-4 h-4 rounded-full bg-amber-500/20 text-amber-900 font-bold text-[10px] flex items-center justify-center shrink-0 mt-0.5">3</span>
                  <span>Responses are securely saved in real time to the examination server.</span>
                </li>
              </ul>
            </div>

            {/* Truthful Readiness Check */}
            <div className={`gov-card ${
              registryStatus === 'available'
                ? 'bg-emerald-50/50 border-emerald-200'
                : registryStatus === 'offline'
                ? 'bg-amber-50/50 border-amber-200'
                : 'bg-slate-50 border-slate-200'
            }`}>
              <div className="flex items-center gap-2 font-bold text-xs mb-1">
                {registryStatus === 'available' ? (
                  <>
                    <CheckCircle2 className="w-4 h-4 text-emerald-700" />
                    <span className="text-emerald-900">System Readiness: Online</span>
                  </>
                ) : registryStatus === 'offline' ? (
                  <>
                    <WifiOff className="w-4 h-4 text-amber-700" />
                    <span className="text-amber-900">System Readiness: Gateway Offline</span>
                  </>
                ) : (
                  <>
                    <AlertCircle className="w-4 h-4 text-slate-600" />
                    <span className="text-slate-800">System Readiness: Verifying...</span>
                  </>
                )}
              </div>
              <p className="text-[11px] leading-relaxed text-slate-600">
                {registryStatus === 'available'
                  ? 'Browser verified: Modern standards compliant. Cryptographic session isolation active.'
                  : registryStatus === 'offline'
                  ? 'Examination backend services are currently unreachable. Verification will resume once services reconnect.'
                  : 'Checking communication with central examination gateway...'}
              </p>
            </div>
          </div>

          {/* Login Form Column */}
          <div className="md:col-span-7">
            <div className="gov-card-elevated">
              <div className="mb-6">
                <h1 className="text-xl font-bold text-[var(--gov-navy-dark)]">
                  Candidate Verification
                </h1>
                <p className="text-xs text-slate-500 mt-1">
                  Enter your assigned registration credentials to enter the CBT session
                </p>
              </div>

              {/* Service Status Banners */}
              {registryStatus === 'offline' && (
                <div className="p-3.5 mb-5 bg-amber-50 border border-amber-200 rounded-lg text-amber-900 text-xs flex items-start justify-between gap-3">
                  <div className="flex items-start gap-2.5">
                    <WifiOff className="w-4 h-4 text-amber-700 shrink-0 mt-0.5" />
                    <div>
                      <div className="font-semibold text-amber-950">Examination Services Unavailable</div>
                      <p className="mt-0.5 text-amber-800 leading-relaxed">
                        The examination registry is currently offline or unreachable. Please try again shortly or contact your centre invigilator.
                      </p>
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => refetch()}
                    disabled={isFetching}
                    className="btn btn-outline text-[11px] py-1 px-2.5 border-amber-300 hover:bg-amber-100/60 shrink-0 flex items-center gap-1.5 cursor-pointer"
                  >
                    <RefreshCw className={`w-3 h-3 ${isFetching ? 'animate-spin' : ''}`} />
                    <span>{isFetching ? 'Checking...' : 'Retry'}</span>
                  </button>
                </div>
              )}

              {registryStatus === 'server_error' && (
                <div className="p-3.5 mb-5 bg-red-50 border border-red-200 rounded-lg text-red-900 text-xs flex items-start justify-between gap-3">
                  <div className="flex items-start gap-2.5">
                    <ServerCrash className="w-4 h-4 text-red-700 shrink-0 mt-0.5" />
                    <div>
                      <div className="font-semibold text-red-950">Examination Server Error (HTTP 5xx)</div>
                      <p className="mt-0.5 text-red-800 leading-relaxed">
                        The central examination service encountered a temporary error. Centre technical staff have been alerted.
                      </p>
                    </div>
                  </div>
                  <button
                    type="button"
                    onClick={() => refetch()}
                    disabled={isFetching}
                    className="btn btn-outline text-[11px] py-1 px-2.5 border-red-300 hover:bg-red-100/60 shrink-0 flex items-center gap-1.5 cursor-pointer"
                  >
                    <RefreshCw className={`w-3 h-3 ${isFetching ? 'animate-spin' : ''}`} />
                    <span>{isFetching ? 'Checking...' : 'Retry'}</span>
                  </button>
                </div>
              )}

              {registryStatus === 'unauthorized' && (
                <div className="p-3.5 mb-5 bg-red-50 border border-red-200 rounded-lg text-red-900 text-xs flex items-start gap-2.5">
                  <ShieldAlert className="w-4 h-4 text-red-700 shrink-0 mt-0.5" />
                  <div>
                    <div className="font-semibold text-red-950">Access Restricted</div>
                    <p className="mt-0.5 text-red-800 leading-relaxed">
                      This workstation or network terminal is not authorized to query the examination registry.
                    </p>
                  </div>
                </div>
              )}

              {registryStatus === 'invalid_response' && (
                <div className="p-3.5 mb-5 bg-amber-50 border border-amber-200 rounded-lg text-amber-900 text-xs flex items-start gap-2.5">
                  <AlertTriangle className="w-4 h-4 text-amber-700 shrink-0 mt-0.5" />
                  <div>
                    <div className="font-semibold text-amber-950">Service Communication Anomaly</div>
                    <p className="mt-0.5 text-amber-800 leading-relaxed">
                      Received unexpected payload format from examination gateway. Please notify your centre invigilator.
                    </p>
                  </div>
                </div>
              )}

              {registryStatus === 'empty' && (
                <div className="p-3 mb-5 bg-slate-50 border border-slate-200 rounded-lg text-slate-700 text-xs flex items-center gap-2">
                  <AlertCircle className="w-4 h-4 text-slate-500 shrink-0" />
                  <span>No active examinations are currently scheduled for this session window.</span>
                </div>
              )}

              {/* Form Validation Error Banner */}
              {error && (
                <div className="p-3 mb-5 bg-red-50 border border-red-200 rounded-lg text-red-700 text-xs flex items-center gap-2">
                  <AlertCircle className="w-4 h-4 shrink-0" />
                  <span>{error}</span>
                </div>
              )}

              <form onSubmit={handleLogin} className="space-y-4">
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <label className="form-label mb-0">Examination</label>
                    {isFetching && (
                      <span className="text-[10px] text-amber-700 flex items-center gap-1">
                        <RefreshCw className="w-2.5 h-2.5 animate-spin" />
                        Syncing...
                      </span>
                    )}
                  </div>
                  <select
                    className="form-input text-xs"
                    value={selectedExamId}
                    onChange={(e) => setSelectedExamId(e.target.value)}
                    disabled={registryStatus !== 'available'}
                  >
                    {registryStatus === 'loading' && (
                      <option value="">Connecting to examination registry...</option>
                    )}
                    {registryStatus === 'offline' && (
                      <option value="">Examination gateway unreachable</option>
                    )}
                    {registryStatus === 'server_error' && (
                      <option value="">Examination service error — retry required</option>
                    )}
                    {registryStatus === 'unauthorized' && (
                      <option value="">Access unauthorized</option>
                    )}
                    {registryStatus === 'invalid_response' && (
                      <option value="">Invalid registry response format</option>
                    )}
                    {registryStatus === 'empty' && (
                      <option value="">No released examinations currently active</option>
                    )}
                    {registryStatus === 'available' &&
                      safeExams.map((ex: any) => (
                        <option key={ex.id} value={ex.id}>
                          {ex.title} ({ex.exam_type || 'CBT'})
                        </option>
                      ))}
                  </select>
                </div>

                <div>
                  <label className="form-label">Roll Number / Registration ID</label>
                  <input
                    type="text"
                    className="form-input text-xs font-mono"
                    placeholder="e.g. NEET-2026-000001"
                    value={regNumber}
                    onChange={(e) => setRegNumber(e.target.value)}
                    required
                  />
                </div>

                <div>
                  <label className="form-label">Password / Date of Birth</label>
                  <input
                    type="password"
                    className="form-input text-xs"
                    placeholder="Enter examination password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                  />
                </div>

                <div className="pt-2">
                  <button
                    type="submit"
                    className="btn btn-amber w-full justify-center text-xs py-2.5 cursor-pointer"
                    disabled={loading || !regNumber || !password || registryStatus !== 'available' || !selectedExamId}
                  >
                    {loading
                      ? 'Verifying Session...'
                      : registryStatus === 'offline'
                      ? 'Examination Service Offline'
                      : registryStatus === 'loading'
                      ? 'Connecting to Registry...'
                      : registryStatus === 'empty'
                      ? 'No Examinations Active'
                      : 'Start Examination'}
                    <ArrowRight className="w-4 h-4" />
                  </button>
                </div>
              </form>

              <div className="mt-5 text-center text-xs text-slate-500">
                Facing an issue? Notify your centre invigilator immediately.
              </div>
            </div>
          </div>
        </div>
      </main>

      <PortalFooter />
    </div>
  );
}
