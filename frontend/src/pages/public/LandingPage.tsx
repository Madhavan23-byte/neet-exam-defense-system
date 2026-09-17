import React from 'react';
import { Link } from 'react-router-dom';
import {
  Shield, Lock, KeyRound, FileCheck2, UserCheck,
  ChevronRight, Sparkles, BookOpen, AlertTriangle, Building2, CheckCircle2
} from 'lucide-react';
import PortalHeader from '../../components/ui/PortalHeader';
import PortalFooter from '../../components/ui/PortalFooter';

export default function LandingPage() {
  return (
    <div className="min-h-screen flex flex-col bg-[var(--gov-canvas)]">
      <PortalHeader />

      {/* Hero Banner with Warm Sunlight & Dignified Authority */}
      <section className="relative overflow-hidden bg-gradient-to-b from-[var(--gov-navy-dark)] to-[var(--gov-navy)] text-white py-16 px-4 sm:px-6 lg:px-8 border-b border-amber-500/20">
        <div className="max-w-5xl mx-auto text-center relative z-10">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-amber-500/20 border border-amber-400/40 text-amber-300 text-xs font-semibold mb-6 tracking-wide">
            <Sparkles className="w-3.5 h-3.5 text-amber-300" />
            <span>High-Assurance National Examination Defense</span>
          </div>

          <h1 className="text-3xl sm:text-5xl font-extrabold tracking-tight mb-4 leading-tight">
            Protecting the Sanctity of National Examinations
          </h1>
          <p className="text-base sm:text-lg text-slate-300 max-w-3xl mx-auto mb-8 font-normal leading-relaxed">
            Bharat Secure Examination Architecture (B-SEA) unites cryptographic envelope encryption, multi-authority quorum releases, and policy-governed containment to guarantee absolute merit, equity, and trust for millions of candidates.
          </p>

          <div className="flex flex-wrap justify-center gap-4">
            <Link
              to="/candidate/login"
              className="btn btn-amber text-sm py-2.5 px-6 shadow-md"
            >
              Candidate CBT Portal <ChevronRight className="w-4 h-4" />
            </Link>
            <Link
              to="/login"
              className="btn btn-outline text-sm py-2.5 px-6 text-white border-slate-500 hover:bg-slate-800"
            >
              Administrative & Security Console
            </Link>
          </div>
        </div>

        {/* Subtle Decorative Sunlight Warmth Effect */}
        <div className="absolute top-0 right-1/4 w-96 h-96 bg-amber-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="absolute bottom-0 left-1/4 w-96 h-96 bg-blue-500/10 rounded-full blur-3xl pointer-events-none" />
      </section>

      {/* Main Pillars of Trust */}
      <section className="py-14 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto flex-1">
        <div className="text-center max-w-2xl mx-auto mb-10">
          <h2 className="text-2xl font-bold text-[var(--gov-navy-dark)] tracking-tight">
            Four Pillars of Cryptographic Defense
          </h2>
          <p className="text-xs sm:text-sm text-slate-500 mt-2">
            Every layer is engineered to eliminate single points of failure, collusion, and unauthorized disclosure.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <div className="gov-card flex flex-col justify-between hover:border-amber-500/40 transition-colors">
            <div>
              <div className="w-10 h-10 rounded-lg bg-amber-500/10 text-amber-700 flex items-center justify-center mb-4">
                <Lock className="w-5 h-5" />
              </div>
              <h3 className="text-base font-bold text-[var(--gov-navy-dark)] mb-2">
                Envelope Encryption
              </h3>
              <p className="text-xs text-slate-600 leading-relaxed">
                Questions are independently encrypted at rest with AES-256-GCM. Plaintext question papers never exist prior to authorized examination windows.
              </p>
            </div>
            <div className="mt-4 pt-3 border-t border-[var(--gov-border)] text-[11px] font-semibold text-amber-800 flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5" /> KMS Key Hierarchy
            </div>
          </div>

          <div className="gov-card flex flex-col justify-between hover:border-blue-500/40 transition-colors">
            <div>
              <div className="w-10 h-10 rounded-lg bg-blue-500/10 text-blue-700 flex items-center justify-center mb-4">
                <KeyRound className="w-5 h-5" />
              </div>
              <h3 className="text-base font-bold text-[var(--gov-navy-dark)] mb-2">
                Quorum Release
              </h3>
              <p className="text-xs text-slate-600 leading-relaxed">
                Decryption keys cannot be assembled by any single administrator. Multiple designated authorities must provide cryptographic authorizations simultaneously.
              </p>
            </div>
            <div className="mt-4 pt-3 border-t border-[var(--gov-border)] text-[11px] font-semibold text-blue-800 flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5" /> M-of-N Threshold Keys
            </div>
          </div>

          <div className="gov-card flex flex-col justify-between hover:border-emerald-500/40 transition-colors">
            <div>
              <div className="w-10 h-10 rounded-lg bg-emerald-500/10 text-emerald-700 flex items-center justify-center mb-4">
                <Shield className="w-5 h-5" />
              </div>
              <h3 className="text-base font-bold text-[var(--gov-navy-dark)] mb-2">
                Policy Containment
              </h3>
              <p className="text-xs text-slate-600 leading-relaxed">
                Phase 3C-5E security containment safely isolates compromised candidate sessions or centres without disrupting innocent examinees.
              </p>
            </div>
            <div className="mt-4 pt-3 border-t border-[var(--gov-border)] text-[11px] font-semibold text-emerald-800 flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5" /> Out-of-Band Verification
            </div>
          </div>

          <div className="gov-card flex flex-col justify-between hover:border-slate-500/40 transition-colors">
            <div>
              <div className="w-10 h-10 rounded-lg bg-slate-500/10 text-slate-700 flex items-center justify-center mb-4">
                <FileCheck2 className="w-5 h-5" />
              </div>
              <h3 className="text-base font-bold text-[var(--gov-navy-dark)] mb-2">
                Immutable Audit Trail
              </h3>
              <p className="text-xs text-slate-600 leading-relaxed">
                All lifecycle events are recorded in append-only PostgreSQL ledgers sealed with SHA-256 hash chains, providing verifiable forensic proof.
              </p>
            </div>
            <div className="mt-4 pt-3 border-t border-[var(--gov-border)] text-[11px] font-semibold text-slate-800 flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5" /> Mode B Audit Isolation
            </div>
          </div>
        </div>

        {/* Portal Directory Section */}
        <div className="mt-14 gov-card-elevated border-amber-500/20 bg-gradient-to-r from-white to-[#FAF8F3]">
          <div className="flex flex-col md:flex-row items-center justify-between gap-6 p-2">
            <div>
              <h3 className="text-lg font-bold text-[var(--gov-navy-dark)]">
                Evaluation & Technical Demonstration Notice
              </h3>
              <p className="text-xs text-slate-600 mt-1 max-w-2xl leading-relaxed">
                B-SEA is configured with comprehensive test blueprints, role-based access controls for 11 distinct operational roles, and full incident lifecycle tracking.
              </p>
            </div>
            <div className="flex items-center gap-3 shrink-0">
              <Link to="/candidate/login" className="btn btn-outline text-xs">
                Candidate CBT
              </Link>
              <Link to="/login" className="btn btn-navy text-xs">
                Enter Staff Console <ChevronRight className="w-3.5 h-3.5" />
              </Link>
            </div>
          </div>
        </div>
      </section>

      <PortalFooter />
    </div>
  );
}
