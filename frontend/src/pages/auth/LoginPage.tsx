import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Shield, Eye, EyeOff, Lock, AlertCircle, Fingerprint } from 'lucide-react';
import { useAuthStore } from '../../stores/authStore';
import { authApi } from '../../services/api';

export default function LoginPage() {
  const navigate = useNavigate();
  const { setAuth } = useAuthStore();

  const [step, setStep] = useState<'credentials' | 'mfa'>('credentials');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [mfaCode, setMfaCode] = useState('');
  const [preAuthUserId, setPreAuthUserId] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const res = await authApi.login(username, password);
      const data = res.data;

      if (!data.success) {
        setError(data.error || 'Login failed');
        return;
      }

      if (data.mfa_required) {
        setPreAuthUserId(data.user_id);
        setStep('mfa');
      } else {
        setAuth(data.user, data.access_token);
        navigate('/admin');
      }
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Login failed. Check your credentials.');
    } finally {
      setLoading(false);
    }
  };

  const handleMfa = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const res = await authApi.verifyMfa(preAuthUserId, mfaCode);
      const data = res.data;
      if (data.success) {
        setAuth(data.user, data.access_token);
        navigate('/admin');
      } else {
        setError(data.error || 'Invalid MFA code');
      }
    } catch (err: any) {
      setError(err.response?.data?.detail || 'MFA verification failed');
    } finally {
      setLoading(false);
    }
  };

  const DEMO_LOGINS = [
    { label: 'Super Admin', username: 'admin' },
    { label: 'Security Officer', username: 'security_officer' },
    { label: 'Moderator', username: 'moderator_1' },
    { label: 'Question Setter', username: 'q_setter_1' },
    { label: 'Release Authority', username: 'release_auth_1' },
    { label: 'Auditor', username: 'auditor_1' },
  ];

  return (
    <div className="min-h-screen security-grid flex">
      {/* Background */}
      <div className="fixed inset-0 bg-gradient-to-br from-blue-950/30 via-transparent to-purple-950/20 pointer-events-none" />

      {/* Left panel — branding */}
      <div className="hidden lg:flex flex-col justify-between w-1/2 p-12 relative z-10 border-r border-blue-900/20">
        <Link to="/" className="flex items-center gap-3 group">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-blue-600 to-purple-600 flex items-center justify-center">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <div>
            <div className="font-bold text-white text-xl">B-SEA</div>
            <div className="text-xs text-blue-400/80">Bharat Secure Examination Architecture</div>
          </div>
        </Link>

        <div>
          <div className="badge-info mb-6">Admin Portal</div>
          <h2 className="text-3xl font-bold text-white mb-4">
            Secure Examination<br />Management Console
          </h2>
          <p className="text-slate-400 mb-8">
            Access the examination administration, question authoring, release management, security console, and audit systems.
          </p>

          <div className="space-y-3">
            {[
              'Question encryption & lifecycle management',
              'Threshold authorization (multi-party approval)',
              'Time-locked cryptographic exam release',
              'Real-time security anomaly detection',
              'Hash-chained tamper-evident audit trail',
            ].map((item, i) => (
              <div key={i} className="flex items-center gap-2 text-sm text-slate-400">
                <div className="w-1.5 h-1.5 rounded-full bg-blue-500" />
                {item}
              </div>
            ))}
          </div>
        </div>

        <div className="text-xs text-slate-600">
          Prototype Reference Implementation • Not for production use
        </div>
      </div>

      {/* Right panel — login form */}
      <div className="flex-1 flex items-center justify-center px-6 relative z-10">
        <div className="w-full max-w-md">
          <div className="lg:hidden flex items-center gap-3 mb-8 justify-center">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-blue-600 to-purple-600 flex items-center justify-center">
              <Shield className="w-6 h-6 text-white" />
            </div>
            <div className="text-xl font-bold text-white">B-SEA</div>
          </div>

          {step === 'credentials' ? (
            <div className="card-elevated animate-fade-in">
              <div className="flex items-center gap-2 mb-6">
                <Lock className="w-5 h-5 text-blue-400" />
                <h1 className="text-xl font-bold text-white">Secure Login</h1>
              </div>

              {error && (
                <div className="flex items-center gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-sm mb-4">
                  <AlertCircle className="w-4 h-4 shrink-0" />
                  {error}
                </div>
              )}

              <form onSubmit={handleLogin} className="space-y-4">
                <div>
                  <label className="form-label">Username</label>
                  <input
                    id="username"
                    type="text"
                    className="form-input"
                    placeholder="Enter username"
                    value={username}
                    onChange={e => setUsername(e.target.value)}
                    required
                    autoComplete="username"
                  />
                </div>

                <div>
                  <label className="form-label">Password</label>
                  <div className="relative">
                    <input
                      id="password"
                      type={showPassword ? 'text' : 'password'}
                      className="form-input pr-10"
                      placeholder="Enter password"
                      value={password}
                      onChange={e => setPassword(e.target.value)}
                      required
                      autoComplete="current-password"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
                    >
                      {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                </div>

                <button
                  id="login-submit"
                  type="submit"
                  className="btn btn-primary w-full justify-center"
                  disabled={loading}
                >
                  {loading ? 'Authenticating...' : 'Login Securely'}
                </button>
              </form>

              {/* Demo quick-login */}
              <div className="mt-6 pt-5 border-t border-slate-800">
                <div className="text-xs text-slate-500 font-semibold uppercase tracking-wider mb-3">
                  Demo Quick Login (password: BSeaDemo@2026)
                </div>
                <div className="grid grid-cols-2 gap-2">
                  {DEMO_LOGINS.map((u) => (
                    <button
                      key={u.username}
                      onClick={() => { setUsername(u.username); setPassword('BSeaDemo@2026'); }}
                      className="text-left p-2 rounded-lg border border-slate-800 hover:border-blue-800 hover:bg-blue-950/20 transition-all text-xs"
                    >
                      <div className="text-blue-400 font-medium">{u.label}</div>
                      <div className="text-slate-500 font-mono">{u.username}</div>
                    </button>
                  ))}
                </div>
              </div>

              <div className="mt-4 text-center">
                <Link to="/candidate/login" className="text-xs text-slate-500 hover:text-blue-400 transition-colors">
                  Candidate? → Take the demo exam
                </Link>
              </div>
            </div>
          ) : (
            <div className="card-elevated animate-fade-in">
              <div className="flex items-center gap-2 mb-6">
                <Fingerprint className="w-5 h-5 text-purple-400" />
                <h1 className="text-xl font-bold text-white">MFA Verification</h1>
              </div>
              <p className="text-slate-400 text-sm mb-6">
                Enter the 6-digit code from your authenticator app.
              </p>

              {error && (
                <div className="flex items-center gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-sm mb-4">
                  <AlertCircle className="w-4 h-4 shrink-0" />
                  {error}
                </div>
              )}

              <form onSubmit={handleMfa} className="space-y-4">
                <input
                  id="mfa-code"
                  type="text"
                  className="form-input text-center text-2xl tracking-widest font-mono"
                  placeholder="000000"
                  maxLength={6}
                  value={mfaCode}
                  onChange={e => setMfaCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  required
                />
                <button type="submit" className="btn btn-primary w-full justify-center" disabled={loading}>
                  {loading ? 'Verifying...' : 'Verify MFA Code'}
                </button>
              </form>
              <button onClick={() => setStep('credentials')} className="mt-4 w-full text-center text-sm text-slate-500 hover:text-white transition-colors">
                ← Back to login
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
