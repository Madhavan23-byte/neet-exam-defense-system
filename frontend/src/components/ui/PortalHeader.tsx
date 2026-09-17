import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Shield, Clock, LogOut, User, Sparkles, ChevronDown } from 'lucide-react';
import { useAuthStore } from '../../stores/authStore';

export default function PortalHeader({ title, subtitle }: { title?: string; subtitle?: string }) {
  const { user, logout, isAuthenticated } = useAuthStore();
  const navigate = useNavigate();
  const [timeStr, setTimeStr] = useState('');
  const [fontSize, setFontSize] = useState<'normal' | 'large' | 'xlarge'>('normal');

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      // Format as IST time
      const formatted = now.toLocaleTimeString('en-IN', {
        timeZone: 'Asia/Kolkata',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: true,
      });
      setTimeStr(formatted);
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  const handleFontChange = (size: 'normal' | 'large' | 'xlarge') => {
    setFontSize(size);
    const root = document.documentElement;
    if (size === 'large') {
      root.style.fontSize = '17px';
    } else if (size === 'xlarge') {
      root.style.fontSize = '18px';
    } else {
      root.style.fontSize = '16px';
    }
  };

  return (
    <header className="border-b border-[var(--gov-border)] bg-[var(--gov-surface)] sticky top-0 z-40 shadow-xs">
      {/* Top Utility Bar */}
      <div className="bg-[var(--gov-navy-dark)] text-slate-200 px-4 py-1 text-xs flex justify-between items-center">
        <div className="flex items-center gap-2">
          <span className="font-semibold text-amber-400">B-SEA</span>
          <span className="text-slate-400">|</span>
          <span className="text-slate-300">Bharat Secure Examination Architecture</span>
          <span className="hidden sm:inline-block bg-amber-500/20 text-amber-300 border border-amber-500/30 px-2 py-0.2 rounded text-[10px] font-medium tracking-wide">
            TECHNOLOGY DEMONSTRATOR
          </span>
        </div>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1.5 text-slate-300">
            <Clock className="w-3.5 h-3.5 text-amber-400" />
            <span className="font-mono">IST {timeStr || '--:--:--'}</span>
          </div>
          <div className="hidden md:flex items-center gap-1 text-[11px] border-l border-slate-700 pl-3">
            <span className="text-slate-400 mr-1">Font:</span>
            <button
              onClick={() => handleFontChange('normal')}
              className={`px-1.5 py-0.5 rounded cursor-pointer ${fontSize === 'normal' ? 'bg-amber-500 text-slate-900 font-bold' : 'hover:text-white'}`}
              title="Standard Font Size"
            >
              A
            </button>
            <button
              onClick={() => handleFontChange('large')}
              className={`px-1.5 py-0.5 rounded cursor-pointer ${fontSize === 'large' ? 'bg-amber-500 text-slate-900 font-bold' : 'hover:text-white'}`}
              title="Large Font Size"
            >
              A+
            </button>
          </div>
        </div>
      </div>

      {/* Main Header Bar */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-3.5 flex justify-between items-center">
        <Link to="/" className="flex items-center gap-3 no-underline group">
          <div className="w-10 h-10 rounded-lg bg-[var(--gov-navy)] flex items-center justify-center text-amber-400 shadow-sm border border-amber-500/20 group-hover:border-amber-500/50 transition-colors">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <div className="text-base font-bold text-[var(--gov-navy-dark)] tracking-tight flex items-center gap-1.5">
              <span>B-SEA</span>
              <span className="text-xs font-normal text-slate-500 hidden sm:inline">— Examination Security Architecture</span>
            </div>
            <div className="text-xs text-slate-500 font-medium">
              {subtitle || 'High-Assurance Examination Protection System'}
            </div>
          </div>
        </Link>

        {/* Right Session / Nav Controls */}
        <div className="flex items-center gap-3">
          {isAuthenticated && user ? (
            <div className="flex items-center gap-3">
              <div className="text-right hidden sm:block">
                <div className="text-xs font-semibold text-[var(--gov-navy-dark)]">{user.full_name || user.username}</div>
                <div className="text-[11px] text-amber-700 font-medium">{user.role}</div>
              </div>
              <Link
                to="/admin"
                className="btn btn-outline text-xs py-1.5 px-3"
              >
                Console
              </Link>
              <button
                onClick={() => { logout(); navigate('/login'); }}
                className="btn btn-ghost text-xs py-1.5 px-2.5 text-slate-500 hover:text-red-700"
                title="Sign Out"
              >
                <LogOut className="w-4 h-4" />
              </button>
            </div>
          ) : (
            <div className="flex items-center gap-2">
              <Link to="/candidate/login" className="btn btn-outline text-xs py-1.5 px-3.5">
                Candidate CBT
              </Link>
              <Link to="/login" className="btn btn-primary text-xs py-1.5 px-3.5">
                Staff Portal
              </Link>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
