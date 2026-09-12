import { Outlet, NavLink, useNavigate } from 'react-router-dom';
import {
  Shield, LayoutDashboard, FileText, Users, Lock,
  AlertTriangle, BookOpen, LogOut, Key, BookCheck, Activity
} from 'lucide-react';
import { useAuthStore } from '../../stores/authStore';

const NAV_ITEMS = [
  { to: '/admin', icon: <LayoutDashboard className="w-4 h-4" />, label: 'Dashboard', end: true },
  { to: '/admin/exams', icon: <FileText className="w-4 h-4" />, label: 'Exams' },
  { to: '/admin/authoring', icon: <BookOpen className="w-4 h-4" />, label: 'Authoring' },
  { to: '/admin/release', icon: <Key className="w-4 h-4" />, label: 'Release Control' },
  { to: '/admin/users', icon: <Users className="w-4 h-4" />, label: 'Users' },
  { to: '/admin/security', icon: <Activity className="w-4 h-4" />, label: 'Security Console' },
  { to: '/admin/audit', icon: <BookCheck className="w-4 h-4" />, label: 'Audit Trail' },
  { to: '/admin/incidents', icon: <AlertTriangle className="w-4 h-4" />, label: 'Incidents' },
];

const ROLE_COLORS: Record<string, string> = {
  SUPER_ADMIN: 'badge-critical',
  EXAM_AUTHORITY: 'badge-info',
  SECURITY_OFFICER: 'badge-warning',
  RELEASE_AUTHORITY: 'badge-purple',
  MODERATOR: 'badge-info',
  QUESTION_SETTER: 'badge-secure',
  AUDITOR: 'badge-purple',
  default: 'badge-info',
};

export default function AdminLayout() {
  const { user, logout } = useAuthStore();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <div className="flex h-screen overflow-hidden">
      {/* Sidebar */}
      <aside className="w-64 flex flex-col border-r border-blue-900/20 bg-slate-950/80 backdrop-blur shrink-0">
        {/* Logo */}
        <div className="p-5 border-b border-blue-900/20">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-blue-600 to-purple-600 flex items-center justify-center shrink-0">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div>
              <div className="font-bold text-white text-sm">B-SEA</div>
              <div className="text-xs text-slate-500">Admin Console</div>
            </div>
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 p-3 space-y-0.5 overflow-y-auto">
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                  isActive
                    ? 'bg-blue-600/20 text-blue-400 border border-blue-600/20'
                    : 'text-slate-400 hover:text-white hover:bg-slate-800/50'
                }`
              }
            >
              {item.icon}
              {item.label}
            </NavLink>
          ))}
        </nav>

        {/* User info */}
        <div className="p-4 border-t border-blue-900/20">
          <div className="flex items-center justify-between">
            <div className="min-w-0">
              <div className="text-sm font-medium text-white truncate">{user?.full_name}</div>
              <div className={`${ROLE_COLORS[user?.role || 'default'] || 'badge-info'} mt-1 inline-block text-xs`}>
                {user?.role}
              </div>
            </div>
            <button
              onClick={handleLogout}
              className="p-2 text-slate-500 hover:text-red-400 transition-colors rounded-lg hover:bg-red-500/10"
              title="Logout"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-y-auto security-grid">
        <Outlet />
      </main>
    </div>
  );
}
