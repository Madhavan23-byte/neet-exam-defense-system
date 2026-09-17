import React from 'react';
import { Shield, Lock, FileCheck } from 'lucide-react';

export default function PortalFooter() {
  return (
    <footer className="mt-auto border-t border-[var(--gov-border)] bg-[var(--gov-surface-warm)] text-slate-600 text-xs py-8">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 pb-6 border-b border-[var(--gov-border)]">
          <div>
            <div className="font-bold text-[var(--gov-navy-dark)] text-sm mb-2 flex items-center gap-1.5">
              <Shield className="w-4 h-4 text-amber-600" />
              <span>B-SEA Platform</span>
            </div>
            <p className="text-slate-600 text-xs leading-relaxed">
              Bharat Secure Examination Architecture. An open, high-assurance technology demonstrator designed to protect national-scale examinations through cryptographic immutability, quorum release, and policy-governed containment.
            </p>
          </div>
          <div>
            <div className="font-bold text-[var(--gov-navy-dark)] text-sm mb-2">Notice & Attribution</div>
            <p className="text-slate-600 text-xs leading-relaxed">
              This demonstrator illustrates state-of-the-art examination defense protocols. All demonstrations utilize synthetic test blueprints, mock candidate records, and non-sensitive question banks.
            </p>
          </div>
          <div>
            <div className="font-bold text-[var(--gov-navy-dark)] text-sm mb-2">Security Architecture</div>
            <ul className="space-y-1.5 text-slate-600 text-xs">
              <li className="flex items-center gap-1.5">
                <Lock className="w-3.5 h-3.5 text-emerald-600" />
                <span>AES-256-GCM Envelope Encryption</span>
              </li>
              <li className="flex items-center gap-1.5">
                <FileCheck className="w-3.5 h-3.5 text-amber-600" />
                <span>Append-Only Cryptographic Audit Seals</span>
              </li>
              <li className="flex items-center gap-1.5">
                <Shield className="w-3.5 h-3.5 text-blue-600" />
                <span>Phase 3C-5E Policy-Governed Containment</span>
              </li>
            </ul>
          </div>
        </div>
        <div className="pt-4 flex flex-col sm:flex-row justify-between items-center text-slate-500 text-[11px] gap-2">
          <div>
            © 2026 Bharat Secure Examination Architecture (B-SEA). Evaluation & Demonstrator Build.
          </div>
          <div>
            System Version: Rev-04.1 | Mode B Canonical Audit Isolated
          </div>
        </div>
      </div>
    </footer>
  );
}
