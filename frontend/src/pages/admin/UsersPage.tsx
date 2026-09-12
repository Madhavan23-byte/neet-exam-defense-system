import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { usersApi } from '../../services/api';
import { useState } from 'react';
import { Users, UserPlus, Lock, Unlock, Shield } from 'lucide-react';

const ROLE_COLORS: Record<string, string> = {
  SUPER_ADMIN: 'badge-critical',
  EXAM_AUTHORITY: 'badge-info',
  SECURITY_OFFICER: 'badge-warning',
  RELEASE_AUTHORITY: 'badge-purple',
  MODERATOR: 'badge-info',
  QUESTION_SETTER: 'badge-secure',
  AUDITOR: 'badge-purple',
  CANDIDATE: 'badge-info',
};

function CreateUserModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [form, setForm] = useState({
    username: '', full_name: '', email: '', role: 'QUESTION_SETTER', password: ''
  });

  const mutation = useMutation({
    mutationFn: () => usersApi.create(form),
    onSuccess: () => { onCreated(); onClose(); },
  });

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="w-full max-w-md card-elevated animate-fade-in">
        <h2 className="text-lg font-bold text-white mb-5 flex items-center gap-2">
          <UserPlus className="w-5 h-5 text-blue-400" />
          Provision New User
        </h2>
        <div className="space-y-4">
          <div>
            <label className="form-label">Full Name</label>
            <input className="form-input" placeholder="e.g. Dr. Jane Doe"
              value={form.full_name} onChange={e => setForm({ ...form, full_name: e.target.value })} />
          </div>
          <div>
            <label className="form-label">Username</label>
            <input className="form-input font-mono" placeholder="username"
              value={form.username} onChange={e => setForm({ ...form, username: e.target.value })} />
          </div>
          <div>
            <label className="form-label">Email</label>
            <input type="email" className="form-input" placeholder="email@bsea.demo"
              value={form.email} onChange={e => setForm({ ...form, email: e.target.value })} />
          </div>
          <div>
            <label className="form-label">Role</label>
            <select className="form-input" value={form.role} onChange={e => setForm({ ...form, role: e.target.value })}>
              {Object.keys(ROLE_COLORS).filter(r => r !== 'CANDIDATE').map(r => (
                <option key={r} value={r}>{r}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="form-label">Initial Password</label>
            <input type="password" className="form-input"
              value={form.password} onChange={e => setForm({ ...form, password: e.target.value })} />
          </div>
        </div>
        <div className="flex gap-3 mt-6">
          <button className="btn btn-primary flex-1 justify-center"
            onClick={() => mutation.mutate()} disabled={!form.username || mutation.isPending}>
            {mutation.isPending ? 'Provisioning...' : 'Provision User'}
          </button>
          <button className="btn btn-ghost" onClick={onClose}>Cancel</button>
        </div>
        {mutation.isError && (
          <div className="mt-3 text-xs text-red-400">
            {(mutation.error as any)?.response?.data?.detail || 'Failed to create user'}
          </div>
        )}
      </div>
    </div>
  );
}

export default function UsersPage() {
  const qc = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);

  const { data: users = [], isLoading } = useQuery({
    queryKey: ['users'],
    queryFn: () => usersApi.list().then(r => r.data),
  });

  const lockMutation = useMutation({
    mutationFn: (id: string) => usersApi.lock(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['users'] }),
  });

  const unlockMutation = useMutation({
    mutationFn: (id: string) => usersApi.unlock(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['users'] }),
  });

  return (
    <div className="p-8">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold text-white">Access Management</h1>
          <p className="text-slate-400 text-sm mt-1">Identity, role provisioning, and account security</p>
        </div>
        <button className="btn btn-primary" onClick={() => setShowCreate(true)}>
          <UserPlus className="w-4 h-4" /> Provision User
        </button>
      </div>

      <div className="card">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-900/50">
                <th className="text-left py-3 px-4 text-xs text-slate-500 uppercase tracking-wider">User</th>
                <th className="text-left py-3 px-4 text-xs text-slate-500 uppercase tracking-wider">Role</th>
                <th className="text-left py-3 px-4 text-xs text-slate-500 uppercase tracking-wider">Security</th>
                <th className="text-left py-3 px-4 text-xs text-slate-500 uppercase tracking-wider">Last Login</th>
                <th className="text-right py-3 px-4 text-xs text-slate-500 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr><td colSpan={5} className="text-center py-8 text-slate-500">Loading users...</td></tr>
              ) : users.map((u: any) => (
                <tr key={u.id} className={`border-b border-slate-800/20 hover:bg-slate-800/20 transition-colors ${u.is_locked ? 'opacity-60' : ''}`}>
                  <td className="py-3 px-4">
                    <div className="font-semibold text-white">{u.full_name}</div>
                    <div className="text-xs text-slate-500 font-mono mt-0.5">{u.username}</div>
                  </td>
                  <td className="py-3 px-4">
                    <span className={ROLE_COLORS[u.role] || 'badge-info'}>{u.role}</span>
                  </td>
                  <td className="py-3 px-4">
                    <div className="flex items-center gap-2">
                      <Shield className={`w-3.5 h-3.5 ${u.mfa_enabled ? 'text-emerald-400' : 'text-slate-500'}`} />
                      <span className={`text-xs ${u.mfa_enabled ? 'text-emerald-400' : 'text-slate-500'}`}>
                        {u.mfa_enabled ? 'MFA Enabled' : 'MFA Pending'}
                      </span>
                      {u.is_locked && (
                        <span className="badge-critical ml-2">LOCKED</span>
                      )}
                    </div>
                  </td>
                  <td className="py-3 px-4 text-xs text-slate-500">
                    {u.last_login ? new Date(u.last_login).toLocaleString() : 'Never'}
                  </td>
                  <td className="py-3 px-4 text-right">
                    {u.is_locked ? (
                      <button className="btn btn-ghost text-xs py-1.5" onClick={() => unlockMutation.mutate(u.id)}>
                        <Unlock className="w-3 h-3" /> Unlock
                      </button>
                    ) : (
                      <button className="btn btn-ghost text-xs py-1.5 text-red-400 hover:border-red-500 hover:bg-red-500/10" onClick={() => lockMutation.mutate(u.id)}>
                        <Lock className="w-3 h-3" /> Lock
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {showCreate && (
        <CreateUserModal
          onClose={() => setShowCreate(false)}
          onCreated={() => qc.invalidateQueries({ queryKey: ['users'] })}
        />
      )}
    </div>
  );
}
