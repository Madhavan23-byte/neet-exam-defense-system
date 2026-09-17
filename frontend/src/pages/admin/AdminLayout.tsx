import React, { useState, useEffect } from 'react';
import { Outlet, NavLink, useNavigate, Link, useLocation } from 'react-router-dom';
import {
  Shield, LayoutDashboard, FileText, Users, Lock,
  AlertTriangle, BookOpen, LogOut, KeyRound, BookCheck, Activity, Flame,
  Clock, ShieldAlert, Sparkles, ChevronRight, Menu, X
} from 'lucide-react';
import { useAuthStore } from '../../stores/authStore';

const NAV_ITEMS = [
  { to: '/admin', icon: <LayoutDashboard className="w-4 h-4" />, label: 'Dashboard', end: true },
  { to: '/admin/exams', icon: <FileText className="w-4 h-4" />, label: 'Examinations' },
  { to: '/admin/authoring', icon: <BookOpen className="w-4 h-4" />, label: 'Question Bank' },
  { to: '/admin/release', icon: <KeyRound className="w-4 h-4" />, label: 'Quorum Release' },
  { to: '/admin/security', icon: <Activity className="w-4 h-4" />, label: 'Threat Observability' },
  { to: '/admin/incidents', icon: <AlertTriangle className="w-4 h-4" />, label: 'Incident Response' },
  { to: '/admin/containment', icon: <ShieldAlert className="w-4 h-4 text-amber-500" />, label: 'Containment Ops' },
  { to: '/admin/break-glass', icon: <Flame className="w-4 h-4 text-orange-500" />, label: 'Emergency Override' },
  { to: '/admin/audit', icon: <BookCheck className="w-4 h-4" />, label: 'Cryptographic Audit' },
  { to: '/admin/users', icon: <Users className="w-4 h-4" />, label: 'Staff & RBAC' },
];

export default function AdminLayout() {
  const { user, logout } = useAuthStore();
  const navigate = useNavigate();
  const location = useLocation();
  const [mobileOpen, setMobileOpen] = useState(false);
  const [timeStr, setTimeStr] = useState('');

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setTimeStr(
        now.toLocaleTimeString('en-IN', {
          timeZone: 'Asia/Kolkata',
          hour: '2-digit',
          minute: '2-digit',
          second: '2-digit',
          hour12: true,
        })
      );
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  // Find active nav title
  const currentNav = NAV_ITEMS.find((item) =>
    item.end ? location.pathname === item.to : location.pathname.startsWith(item.to)
  );

  return (
    <div className="flex h-screen overflow-hidden bg-[var(--gov-canvas)]">
      {/* Sidebar */}
      <aside
        className={`fixed inset-y-0 left-0 z-40 w-64 bg-[var(--gov-navy-dark)] text-slate-300 flex flex-col border-r border-slate-800 transition-transform duration-200 lg:translate-x-0 lg:static lg:inset-auto ${
          mobileOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        {/* Brand Header */}
        <div className="p-4 border-b border-slate-800/80 flex items-center justify-between">
          <Link to="/" className="flex items-center gap-3 no-underline text-white">
            <div className="w-9 h-9 rounded-lg bg-amber-500/20 text-amber-400 border border-amber-500/40 flex items-center justify-center font-bold">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <div className="text-sm font-bold tracking-tight text-white flex items-center gap-1.5">
                <span>B-SEA</span>
                <span className="text-[10px] bg-amber-500/30 text-amber-300 px-1.5 py-0.2 rounded font-mono">
                  DEMO
                </span>
              </div>
              <div className="text-[11px] text-slate-400 font-medium">Security Operations</div>
            </div>
          </Link>
          <button
            onClick={() => setMobileOpen(false)}
            className="lg:hidden p-1 text-slate-400 hover:text-white"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* User Card */}
        <div className="px-4 py-3 border-b border-slate-800/60 bg-slate-900/40">
          <div className="text-xs font-semibold text-white truncate">
            {user?.full_name || user?.username || 'Authorized Official'}
          </div>
          <div className="flex items-center gap-1.5 mt-1">
            <span className="w-2 h-2 rounded-full bg-emerald-400 inline-block" />
            <span className="text-[11px] font-mono text-amber-300 font-medium">{user?.role || 'SUPER_ADMIN'}</span>
          </div>
        </div>

        {/* Nav Links */}
        <nav className="flex-1 overflow-y-auto px-3 py-3 space-y-1">
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              onClick={() => setMobileOpen(false)}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2 rounded-lg text-xs font-semibold transition-all ${
                  isActive
                    ? 'bg-amber-500 text-slate-950 shadow-sm font-bold'
                    : 'text-slate-300 hover:bg-slate-800 hover:text-white'
                }`
              }
            >
              {item.icon}
              <span>{item.label}</span>
            </NavLink>
          ))}
        </nav>

        {/* Bottom Actions */}
        <div className="p-3 border-t border-slate-800/80 space-y-2 text-xs">
          <Link
            to="/"
            className="flex items-center gap-2 px-3 py-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <ChevronRight className="w-3.5 h-3.5" />
            <span>Public Portal</span>
          </Link>
          <button
            onClick={handleLogout}
            className="w-full flex items-center gap-2 px-3 py-2 rounded-lg text-red-400 hover:text-red-300 hover:bg-red-500/10 transition-colors cursor-pointer"
          >
            <LogOut className="w-3.5 h-3.5" />
            <span>Sign Out</span>
          </button>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Top Header Bar */}
        <header className="h-14 border-b border-[var(--gov-border)] bg-[var(--gov-surface)] px-4 sm:px-6 flex items-center justify-between shrink-0 shadow-xs">
          <div className="flex items-center gap-3">
            <button
              onClick={() => setMobileOpen(true)}
              className="lg:hidden p-1.5 rounded-lg text-slate-600 hover:bg-slate-100"
            >
              <Menu className="w-5 h-5" />
            </button>
            <div className="flex items-center gap-2 text-xs">
              <span className="font-semibold text-slate-500">Console</span>
              <span className="text-slate-400">/</span>
              <span className="font-bold text-[var(--gov-navy-dark)]">{currentNav?.label || 'Overview'}</span>
            </div>
          </div>

          <div className="flex items-center gap-4 text-xs">
            <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-[var(--gov-surface-warm)] border border-[var(--gov-border)] text-slate-600 font-mono">
              <Clock className="w-3.5 h-3.5 text-amber-600" />
              <span>IST {timeStr || '--:--:--'}</span>
            </div>
            <div className="px-2 py-0.5 rounded bg-emerald-50 text-emerald-800 border border-emerald-200 text-[11px] font-semibold flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-600" />
              <span>Cryptographic Protection Active</span>
            </div>
          </div>
        </header>

        {/* Scrollable Page Body */}
        <main className="flex-1 overflow-y-auto p-4 sm:p-6 lg:p-8 bg-[var(--gov-canvas)]">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
