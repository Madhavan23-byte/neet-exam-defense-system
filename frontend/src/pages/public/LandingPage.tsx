import { Link } from 'react-router-dom';
import { Shield, Lock, Eye, Zap, Globe, Server, Key, AlertTriangle, ChevronRight, Fingerprint, Network } from 'lucide-react';

const SECURITY_FEATURES = [
  {
    icon: <Key className="w-6 h-6" />,
    title: "AES-256-GCM Encryption",
    desc: "Every question is independently encrypted. No master exam paper exists in plaintext.",
    color: "blue",
  },
  {
    icon: <Fingerprint className="w-6 h-6" />,
    title: "Threshold Authorization",
    desc: "Exam release requires cryptographic approval from multiple independent authorities simultaneously.",
    color: "purple",
  },
  {
    icon: <Lock className="w-6 h-6" />,
    title: "Time-Locked Release",
    desc: "Questions cannot be decrypted before the authorized exam window, even by administrators.",
    color: "green",
  },
  {
    icon: <Eye className="w-6 h-6" />,
    title: "Zero-Trust Architecture",
    desc: "No single account, server, or administrator has sufficient access to compromise the exam.",
    color: "amber",
  },
  {
    icon: <Network className="w-6 h-6" />,
    title: "Hash-Chained Audit Logs",
    desc: "Tamper-evident audit trail — any historical modification breaks the cryptographic chain.",
    color: "blue",
  },
  {
    icon: <Shield className="w-6 h-6" />,
    title: "Ed25519 Digital Signatures",
    desc: "Every question object carries a cryptographic signature. Tampering is mathematically detectable.",
    color: "purple",
  },
];

const EXAM_TYPES = [
  "NEET · JEE · UPSC · GMAT · SAT · GRE",
  "National Competitive Examinations",
  "Government Recruitment Tests",
  "Professional Certification",
  "University Entrance Examinations",
];

const THREAT_MODEL = [
  { threat: "Insider Threat", control: "Zero Trust + RBAC + threshold authorization" },
  { threat: "Database Compromise", control: "AES-256-GCM at rest — ciphertext only" },
  { threat: "Bulk Question Leak", control: "Rate limiting + anomaly detection + scoped access" },
  { threat: "Early Release Attempt", control: "Time-lock + multi-party authorization" },
  { threat: "Question Tampering", control: "Ed25519 signature + SHA-3 integrity hash" },
  { threat: "Audit Log Deletion", control: "Hash chain — any modification detectable" },
];

export default function LandingPage() {
  return (
    <div className="min-h-screen security-grid">
      {/* Background gradient */}
      <div className="fixed inset-0 bg-gradient-to-br from-blue-950/20 via-transparent to-purple-950/20 pointer-events-none" />

      {/* Header */}
      <header className="relative z-10 border-b border-blue-900/20">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-blue-600 to-purple-600 flex items-center justify-center">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div>
              <div className="font-bold text-white text-lg leading-none">B-SEA</div>
              <div className="text-xs text-blue-400/80 leading-none mt-0.5">Bharat Secure Examination Architecture</div>
            </div>
          </div>
          <nav className="hidden md:flex items-center gap-6">
            <a href="#architecture" className="text-sm text-slate-400 hover:text-white transition-colors">Architecture</a>
            <a href="#security" className="text-sm text-slate-400 hover:text-white transition-colors">Security Model</a>
            <a href="#threats" className="text-sm text-slate-400 hover:text-white transition-colors">Threat Model</a>
            <Link to="/candidate/login" className="text-sm text-slate-400 hover:text-white transition-colors">Candidate Portal</Link>
            <Link to="/login" className="btn btn-primary text-sm px-4 py-2">
              Admin Portal →
            </Link>
          </nav>
        </div>
      </header>

      {/* Hero */}
      <section className="relative z-10 pt-20 pb-16 px-6">
        <div className="max-w-6xl mx-auto text-center">
          {/* Badge */}
          <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full border border-blue-500/30 bg-blue-500/10 text-blue-400 text-sm font-medium mb-8">
            <div className="w-2 h-2 rounded-full bg-blue-400 animate-pulse" />
            Prototype Reference Implementation — Security Research Platform
          </div>

          <h1 className="text-5xl md:text-7xl font-black tracking-tight mb-6 leading-tight">
            <span className="text-white">Examination Security</span>
            <br />
            <span className="gradient-text">Re-Engineered from Zero</span>
          </h1>

          <p className="text-xl text-slate-400 max-w-3xl mx-auto mb-4">
            B-SEA is a cryptographic examination security platform that eliminates single points of compromise.
            No master exam paper. No trusted administrator. No single key.
          </p>
          <p className="text-sm text-slate-500 max-w-2xl mx-auto mb-10">
            Built as a technically credible reference implementation for national-scale secure examination delivery.
            Designed around real-world threat models, not theoretical security.
          </p>

          <div className="flex flex-wrap items-center justify-center gap-4">
            <Link to="/login" className="btn btn-primary text-base px-6 py-3">
              <Shield className="w-4 h-4" />
              Admin Portal
              <ChevronRight className="w-4 h-4" />
            </Link>
            <Link to="/candidate/login" className="btn btn-ghost text-base px-6 py-3">
              Take Demo Exam
            </Link>
          </div>

          {/* Demo credentials */}
          <div className="mt-8 inline-block px-6 py-3 rounded-xl border border-blue-900/30 bg-blue-950/20 text-left">
            <div className="text-xs text-blue-400 font-semibold uppercase tracking-widest mb-2">Demo Credentials</div>
            <div className="flex flex-wrap gap-6 text-sm font-mono">
              <span className="text-slate-400">admin <span className="text-slate-300">/ BSeaDemo@2026</span></span>
              <span className="text-slate-400">security_officer <span className="text-slate-300">/ BSeaDemo@2026</span></span>
              <span className="text-slate-400">moderator_1 <span className="text-slate-300">/ BSeaDemo@2026</span></span>
            </div>
          </div>
        </div>
      </section>

      {/* Exam type ticker */}
      <div className="relative z-10 border-y border-blue-900/20 py-3 bg-blue-950/10 overflow-hidden">
        <div className="text-center text-sm text-slate-500">
          Designed for → {EXAM_TYPES.join(" · ")}
        </div>
      </div>

      {/* Security Features */}
      <section id="security" className="relative z-10 py-20 px-6">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-12">
            <div className="badge-info mb-4 inline-block">Security Architecture</div>
            <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">
              Every Layer Designed for Breach Resistance
            </h2>
            <p className="text-slate-400 max-w-2xl mx-auto">
              Security is not a feature — it's the foundation. Every component is designed assuming the worst-case scenario.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {SECURITY_FEATURES.map((feature, i) => (
              <div key={i} className="card card-elevated hover:border-blue-500/30 transition-all group animate-fade-in" style={{ animationDelay: `${i * 0.1}s` }}>
                <div className={`w-12 h-12 rounded-xl flex items-center justify-center mb-4 ${
                  feature.color === 'blue' ? 'bg-blue-500/10 text-blue-400' :
                  feature.color === 'purple' ? 'bg-purple-500/10 text-purple-400' :
                  feature.color === 'green' ? 'bg-emerald-500/10 text-emerald-400' :
                  'bg-amber-500/10 text-amber-400'
                }`}>
                  {feature.icon}
                </div>
                <h3 className="font-bold text-white mb-2 font-mono text-sm">{feature.title}</h3>
                <p className="text-slate-400 text-sm leading-relaxed">{feature.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Architecture Diagram */}
      <section id="architecture" className="relative z-10 py-20 px-6 bg-blue-950/10 border-y border-blue-900/20">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-12">
            <div className="badge-purple mb-4 inline-block">System Architecture</div>
            <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">
              Cryptographically Isolated Examination Pipeline
            </h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-0 relative">
            {/* Pipeline steps */}
            {[
              { step: "01", title: "Question Authoring", detail: "QUESTION_SETTER creates question. Stored as plaintext in DRAFT only.", icon: "✍️" },
              { step: "02", title: "Review & Approval", detail: "MODERATOR reviews. Approval triggers immediate AES-256-GCM encryption. Plaintext cleared.", icon: "🔍" },
              { step: "03", title: "Blueprint Signing", detail: "EXAM_AUTHORITY creates blueprint. Ed25519 signed. Defines which encrypted questions form the exam.", icon: "📋" },
              { step: "04", title: "Threshold Authorization", detail: "3-of-N RELEASE_AUTHORITY submit signed approvals. No single authority can release alone.", icon: "🔑" },
              { step: "05", title: "Time-Locked Release", detail: "Automated engine verifies: time + threshold + blueprint + centres + no incidents. All must pass.", icon: "⏱️" },
              { step: "06", title: "Secure CBT Delivery", detail: "Questions decrypted per-session, watermarked, integrity-verified. Answer key isolated.", icon: "🖥️" },
            ].map((step, i) => (
              <div key={i} className="relative p-6 border border-blue-900/20">
                {i < 5 && (
                  <div className="absolute top-1/2 -right-3 z-10 text-blue-600 hidden md:block">▶</div>
                )}
                <div className="text-xs font-mono text-blue-600 mb-1">STEP {step.step}</div>
                <div className="text-2xl mb-2">{step.icon}</div>
                <div className="font-bold text-white text-sm mb-2">{step.title}</div>
                <div className="text-xs text-slate-400 leading-relaxed">{step.detail}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Threat Model */}
      <section id="threats" className="relative z-10 py-20 px-6">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-12">
            <div className="badge-warning mb-4 inline-block">STRIDE Threat Model</div>
            <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">
              Real Threats. Engineered Controls.
            </h2>
            <p className="text-slate-400 max-w-2xl mx-auto">
              B-SEA does not claim to be 100% leak-proof. It claims to maximize prevention,
              detection, attribution, and containment — against a realistic adversary model.
            </p>
          </div>

          <div className="overflow-hidden rounded-xl border border-blue-900/30">
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-blue-950/40 border-b border-blue-900/30">
                  <th className="text-left px-6 py-3 text-blue-400 font-semibold uppercase tracking-wider text-xs">Threat Scenario</th>
                  <th className="text-left px-6 py-3 text-blue-400 font-semibold uppercase tracking-wider text-xs">Control Mechanism</th>
                </tr>
              </thead>
              <tbody>
                {THREAT_MODEL.map((row, i) => (
                  <tr key={i} className={`border-b border-blue-900/10 hover:bg-blue-950/20 transition-colors ${i % 2 === 0 ? 'bg-transparent' : 'bg-blue-950/10'}`}>
                    <td className="px-6 py-4 text-amber-400 font-medium">{row.threat}</td>
                    <td className="px-6 py-4 text-slate-300">{row.control}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      {/* Security Disclaimer */}
      <section className="relative z-10 py-12 px-6">
        <div className="max-w-4xl mx-auto">
          <div className="rounded-xl border border-amber-500/20 bg-amber-500/5 p-6">
            <div className="flex gap-3">
              <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
              <div>
                <div className="text-amber-400 font-semibold mb-2">Prototype Reference Implementation</div>
                <p className="text-slate-400 text-sm leading-relaxed">
                  B-SEA is a <strong className="text-slate-300">security research prototype</strong>, not production-certified software.
                  The MockKMS uses software-derived keys — production requires certified HSM hardware (FIPS 140-2 Level 3+).
                  CBT browser controls cannot prevent OS-level screenshots or physical photography.
                  National-scale deployment requires security audit, penetration testing, HSM integration, and government approval.
                </p>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="relative z-10 border-t border-blue-900/20 py-8 px-6">
        <div className="max-w-6xl mx-auto flex items-center justify-between">
          <div className="text-slate-500 text-sm">
            B-SEA v1.0.0 — Bharat Secure Examination Architecture Prototype
          </div>
          <div className="flex gap-6 text-sm text-slate-500">
            <Link to="/login" className="hover:text-white transition-colors">Admin Portal</Link>
            <Link to="/candidate/login" className="hover:text-white transition-colors">Candidate Portal</Link>
          </div>
        </div>
      </footer>
    </div>
  );
}
