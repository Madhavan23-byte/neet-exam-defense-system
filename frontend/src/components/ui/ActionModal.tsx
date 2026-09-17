import React, { useEffect } from 'react';
import { X } from 'lucide-react';

interface ActionModalProps {
  isOpen: boolean;
  onClose: () => void;
  title: string;
  subtitle?: string;
  children: React.ReactNode;
  maxWidth?: string;
}

export default function ActionModal({ isOpen, onClose, title, subtitle, children, maxWidth = 'max-w-lg' }: ActionModalProps) {
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    if (isOpen) {
      document.addEventListener('keydown', handleKeyDown);
      document.body.style.overflow = 'hidden';
    }
    return () => {
      document.removeEventListener('keydown', handleKeyDown);
      document.body.style.overflow = 'unset';
    };
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/50 backdrop-blur-xs animate-fade-in">
      <div
        className={`w-full ${maxWidth} bg-[var(--gov-surface)] rounded-xl border border-[var(--gov-border)] shadow-xl overflow-hidden`}
        role="dialog"
        aria-modal="true"
      >
        <div className="px-6 py-4 border-b border-[var(--gov-border)] flex items-center justify-between bg-[var(--gov-surface-warm)]">
          <div>
            <h2 className="text-base font-bold text-[var(--gov-navy-dark)]">{title}</h2>
            {subtitle && <p className="text-xs text-slate-500 mt-0.5">{subtitle}</p>}
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-slate-400 hover:text-slate-700 hover:bg-slate-200 transition-colors cursor-pointer"
            aria-label="Close dialog"
          >
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="p-6">{children}</div>
      </div>
    </div>
  );
}
