import React from 'react';
import { Inbox } from 'lucide-react';

interface EmptyStateProps {
  title: string;
  description: string;
  actionText?: string;
  onAction?: () => void;
  icon?: React.ReactNode;
}

export default function EmptyState({ title, description, actionText, onAction, icon }: EmptyStateProps) {
  return (
    <div className="text-center py-12 px-4 border border-dashed border-[var(--gov-border-strong)] rounded-xl bg-[var(--gov-surface-warm)]">
      <div className="w-12 h-12 rounded-full bg-[var(--gov-surface)] text-slate-400 mx-auto flex items-center justify-center mb-3 shadow-xs">
        {icon || <Inbox className="w-6 h-6" />}
      </div>
      <h3 className="text-sm font-semibold text-[var(--gov-navy-dark)] mb-1">{title}</h3>
      <p className="text-xs text-slate-500 max-w-sm mx-auto mb-4">{description}</p>
      {actionText && onAction && (
        <button onClick={onAction} className="btn btn-outline text-xs">
          {actionText}
        </button>
      )}
    </div>
  );
}
