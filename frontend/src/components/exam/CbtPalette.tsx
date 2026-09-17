import React from 'react';

export type QuestionStatus = 'answered' | 'not-answered' | 'marked' | 'marked-answered' | 'not-visited';

interface CbtPaletteProps {
  totalQuestions: number;
  currentIndex: number;
  statusMap: Record<number, QuestionStatus>;
  onSelectIndex: (index: number) => void;
}

export default function CbtPalette({
  totalQuestions,
  currentIndex,
  statusMap,
  onSelectIndex,
}: CbtPaletteProps) {
  const getButtonClass = (index: number) => {
    const status = statusMap[index] || 'not-visited';
    const isCurrent = index === currentIndex;
    const base = 'w-9 h-9 text-xs font-semibold rounded-md flex items-center justify-center transition-all cursor-pointer relative ';
    const borderStyle = isCurrent ? 'ring-2 ring-[var(--gov-navy)] ring-offset-2 scale-105 z-10 ' : 'border ';

    if (status === 'answered') {
      return base + borderStyle + 'bg-emerald-600 text-white border-emerald-700 shadow-xs';
    }
    if (status === 'not-answered') {
      return base + borderStyle + 'bg-amber-500 text-white border-amber-600 shadow-xs';
    }
    if (status === 'marked') {
      return base + borderStyle + 'bg-purple-600 text-white border-purple-700 shadow-xs';
    }
    if (status === 'marked-answered') {
      return base + borderStyle + 'bg-purple-600 text-white border-purple-700 shadow-xs';
    }
    // not-visited
    return base + borderStyle + 'bg-stone-100 text-stone-700 border-stone-300 hover:bg-stone-200';
  };

  // Compute counts
  let answeredCount = 0;
  let notAnsweredCount = 0;
  let markedCount = 0;
  let notVisitedCount = 0;

  for (let i = 0; i < totalQuestions; i++) {
    const s = statusMap[i] || 'not-visited';
    if (s === 'answered') answeredCount++;
    else if (s === 'not-answered') notAnsweredCount++;
    else if (s === 'marked' || s === 'marked-answered') markedCount++;
    else notVisitedCount++;
  }

  return (
    <div className="gov-card flex flex-col h-full">
      <div className="text-xs font-bold uppercase tracking-wider text-[var(--gov-navy-dark)] pb-3 border-b border-[var(--gov-border)] mb-3">
        Question Palette
      </div>

      {/* Summary Legend */}
      <div className="grid grid-cols-2 gap-2 text-xs mb-4 p-2 bg-[var(--gov-surface-warm)] rounded-lg border border-[var(--gov-border)]">
        <div className="flex items-center gap-2">
          <span className="w-5 h-5 rounded bg-emerald-600 text-white font-bold text-[10px] flex items-center justify-center">
            {answeredCount}
          </span>
          <span className="text-slate-600">Answered</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-5 h-5 rounded bg-amber-500 text-white font-bold text-[10px] flex items-center justify-center">
            {notAnsweredCount}
          </span>
          <span className="text-slate-600">Not Answered</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-5 h-5 rounded bg-purple-600 text-white font-bold text-[10px] flex items-center justify-center">
            {markedCount}
          </span>
          <span className="text-slate-600">Marked Review</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-5 h-5 rounded bg-stone-200 text-stone-700 font-bold text-[10px] flex items-center justify-center border border-stone-300">
            {notVisitedCount}
          </span>
          <span className="text-slate-600">Not Visited</span>
        </div>
      </div>

      {/* Palette Buttons Grid */}
      <div className="flex-1 overflow-y-auto pr-1">
        <div className="grid grid-cols-5 gap-2">
          {Array.from({ length: totalQuestions }, (_, i) => (
            <button
              key={i}
              type="button"
              onClick={() => onSelectIndex(i)}
              className={getButtonClass(i)}
              aria-label={`Go to question ${i + 1}`}
            >
              {i + 1}
              {statusMap[i] === 'marked-answered' && (
                <span className="absolute -top-1 -right-1 w-2.5 h-2.5 bg-emerald-400 rounded-full border border-white" />
              )}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
