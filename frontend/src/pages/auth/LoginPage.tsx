import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Shield, Lock, User, Key, AlertCircle, ChevronDown, ChevronUp, Sparkles, CheckCircle2 } from 'lucide-react';
import { authApi } from '../../services/api';
import { useAuthStore } from '../../stores/authStore';
import PortalHeader from '../../components/ui/PortalHeader';
import PortalFooter from '../../components/ui/PortalFooter';

// Demo evaluation profiles for local evaluation only (Constraint 1)
const DEMO_EVALUATION_ACCOUNTS = [
  { label: 'Super Administrator', username: 'admin', role: 'SUPER_ADMIN', desc: 'Full emergency and executive authority' },
  { label: 'Security Officer', username: 'security_officer', role: 'SECURITY_OFFICER', desc: '5C detection, 5D incidents, 5E containment' },
  { label: 'Exam Authority', username: 'exam_authority', role: 'EXAM_AUTHORITY', desc: 'Examination management and blueprints' },
  { label: 'Release Authority', username: 'release_auth_1', role: 'RELEASE_AUTHORITY', desc: 'Cryptographic quorum release ceremonies' },
  { label: 'Question Setter', username: 'q_setter_1', role: 'QUESTION_SETTER', desc: 'Question authoring and encryption' },
  { label: 'Reviewer', username: 'reviewer_1', role: 'REVIEWER', desc: 'Peer question review and approval' },
  { label: 'Centre Admin', username: 'centre_admin', role: 'CENTRE_ADMIN', desc: 'Exam centre operational monitoring' },
  { label: 'Auditor', username: 'auditor_1', role: 'AUDITOR', desc: 'Mode B audit trail verification' },
];

export default function LoginPage() {
  const navigate = useNavigate();
  const { setAuth } = useAuthStore();

  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  // MFA step state
  const [mfaRequired, setMfaRequired] = useState(false);
  const [mfaUserId, setMfaUserId] = useState('');
  const [totpCode, setTotpCode] = useState('');

  // Demo helper panel state
  const [showDemoHelper, setShowDemoHelper] = useState(false);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const res = await authApi.login(username, password);
      const data = res.data;

      if (data.mfa_required) {
        setMfaRequired(true);
        setMfaUserId(data.user_id);
        setLoading(false);
        return;
      }

      setAuth(data.user, data.access_token);

      // Role-based routing
      if (data.user.role === 'REVIEWER') {
        navigate('/reviewer');
      } else {
        navigate('/admin');
      }
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || 'Invalid username or password');
    } finally {
      setLoading(false);
    }
  };

  const handleMfaSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const res = await authApi.verifyMfa(mfaUserId, totpCode);
      const data = res.data;
      setAuth(data.user, data.access_token);
      navigate('/admin');
    } catch (err: any) {
      setError(err?.response?.data?.detail || err.message || 'Invalid authentication code');
    } finally {
      setLoading(false);
    }
  };

  const fillDemoAccount = (u: string) => {
    setUsername(u);
    setPassword('Admin@123456');
    setError('');
  };

  return (
    <div className="min-h-screen flex flex-col bg-[var(--gov-canvas)]">
      <PortalHeader subtitle="Official Staff & Administration Access" />

      <main className="flex-1 flex items-center justify-center p-4 sm:p-6 lg:p-8">
        <div className="w-full max-w-md">
          {/* Main Auth Card */}
          <div className="gov-card-elevated border-[var(--gov-border)]">
            <div className="text-center mb-6">
              <div className="w-12 h-12 rounded-xl bg-[var(--gov-navy)] text-amber-400 flex items-center justify-center mx-auto mb-3 shadow-sm">
                <Lock className="w-6 h-6" />
              </div>
              <h1 className="text-xl font-bold text-[var(--gov-navy-dark)]">
                {mfaRequired ? 'Two-Factor Verification' : 'Staff Portal Authentication'}
              </h1>
              <p className="text-xs text-slate-500 mt-1">
                {mfaRequired
                  ? 'Enter the 6-digit TOTP code from your registered authenticator'
                  : 'Enter your credentials to access the examination security console'}
              </p>
            </div>

            {error && (
              <div className="p-3 mb-5 bg-red-50 border border-red-200 rounded-lg text-red-700 text-xs flex items-center gap-2">
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>{error}</span>
              </div>
            )}

            {!mfaRequired ? (
              <form onSubmit={handleLogin} className="space-y-4">
                <div>
                  <label className="form-label">Username</label>
                  <div className="relative">
                    <input
                      type="text"
                      className="form-input pl-9 text-xs"
                      placeholder="Enter assigned username"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      required
                      autoComplete="username"
                    />
                    <User className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
                  </div>
                </div>

                <div>
                  <label className="form-label">Password</label>
                  <div className="relative">
                    <input
                      type="password"
                      className="form-input pl-9 text-xs"
                      placeholder="Enter secure password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      required
                      autoComplete="current-password"
                    />
                    <Key className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
                  </div>
                </div>

                <button
                  type="submit"
                  className="btn btn-primary w-full justify-center text-xs py-2.5 mt-2"
                  disabled={loading || !username || !password}
                >
                  {loading ? 'Authenticating...' : 'Sign In'}
                </button>
              </form>
            ) : (
              <form onSubmit={handleMfaSubmit} className="space-y-4">
                <div>
                  <label className="form-label">Authentication Code (TOTP)</label>
                  <input
                    type="text"
                    maxLength={6}
                    className="form-input text-center font-mono tracking-widest text-base font-bold"
                    placeholder="000000"
                    value={totpCode}
                    onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ''))}
                    required
                    autoFocus
                  />
                </div>

                <div className="flex gap-2">
                  <button
                    type="button"
                    className="btn btn-outline flex-1 text-xs"
                    onClick={() => { setMfaRequired(false); setTotpCode(''); }}
                  >
                    Back
                  </button>
                  <button
                    type="submit"
                    className="btn btn-primary flex-1 text-xs"
                    disabled={loading || totpCode.length !== 6}
                  >
                    {loading ? 'Verifying...' : 'Verify Code'}
                  </button>
                </div>
              </form>
            )}

            <div className="mt-6 pt-4 border-t border-[var(--gov-border)] flex items-center justify-between text-xs text-slate-500">
              <Link to="/candidate/login" className="text-amber-700 hover:underline font-medium">
                Candidate CBT Portal →
              </Link>
              <Link to="/" className="hover:underline">
                Return Home
              </Link>
            </div>
          </div>

          {/* Explicitly Labelled Demo Credentials Helper (Constraint 1) */}
          <div className="mt-4 gov-card border-amber-500/30 bg-amber-500/5">
            <button
              type="button"
              onClick={() => setShowDemoHelper(!showDemoHelper)}
              className="w-full flex items-center justify-between text-xs font-bold text-amber-900 cursor-pointer"
            >
              <div className="flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-amber-600" />
                <span>Local Demonstration & Evaluation Helper</span>
              </div>
              {showDemoHelper ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
            </button>

            {showDemoHelper && (
              <div className="mt-3 pt-3 border-t border-amber-500/20 text-xs">
                <p className="text-[11px] text-amber-800 mb-2">
                  Click any role below to prefill standard test account credentials for evaluation:
                </p>
                <div className="grid grid-cols-2 gap-1.5">
                  {DEMO_EVALUATION_ACCOUNTS.map((acc) => (
                    <button
                      key={acc.username}
                      type="button"
                      onClick={() => fillDemoAccount(acc.username)}
                      className="p-2 text-left bg-white/80 border border-amber-500/20 rounded-md hover:bg-amber-100/50 hover:border-amber-500/50 transition-colors cursor-pointer"
                    >
                      <div className="font-bold text-[11px] text-[var(--gov-navy-dark)]">{acc.label}</div>
                      <div className="text-[10px] text-slate-500 font-mono">@{acc.username}</div>
                    </button>
                  ))}
                </div>
                <div className="mt-2 text-[10px] text-slate-500 italic">
                  Note: Evaluation helper applies to local demonstrator environment only.
                </div>
              </div>
            )}
          </div>
        </div>
      </main>

      <PortalFooter />
    </div>
  );
}
