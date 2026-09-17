import React from 'react';

interface DataTileProps {
  label: string;
  value: string | number | null | undefined;
  subtitle?: string;
  icon?: React.ReactNode;
  badge?: React.ReactNode;
  variant?: 'navy' | 'amber' | 'emerald' | 'neutral';
}

export default function DataTile({ label, value, subtitle, icon, badge, variant = 'neutral' }: DataTileProps) {
  const displayVal = value !== null && value !== undefined ? value : '—';

  return (
    <div className="gov-card flex flex-col justify-between">
      <div className="flex items-start justify-between">
        <div className="text-xs font-semibold uppercase tracking-wider text-slate-500">
          {label}
        </div>
        {icon && (
          <div className="p-2 rounded-lg bg-[var(--gov-surface-warm)] text-[var(--gov-navy)]">
            {icon}
          </div>
        )}
      </div>
      <div className="mt-3">
        <div className="text-2xl font-bold text-[var(--gov-navy-dark)] tracking-tight flex items-baseline gap-2">
          <span>{displayVal}</span>
          {badge}
        </div>
        {subtitle && (
          <div className="text-xs text-slate-500 mt-1 font-medium">
            {subtitle}
          </div>
        )}
      </div>
    </div>
  );
}
