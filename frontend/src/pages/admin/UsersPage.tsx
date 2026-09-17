import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Users, UserPlus, Lock, Unlock, Shield, AlertCircle, CheckCircle2 } from 'lucide-react';
import { usersApi } from '../../services/api';
import ActionModal from '../../components/ui/ActionModal';

export default function UsersPage() {
  const queryClient = useQueryClient();
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [username, setUsername] = useState('');
  const [fullName, setFullName] = useState('');
  const [email, setEmail] = useState('');
  const [role, setRole] = useState('QUESTION_SETTER');
  const [password, setPassword] = useState('Password@123');
  const [msg, setMsg] = useState('');

  const { data: users = [], isLoading } = useQuery({
    queryKey: ['users-list'],
    queryFn: () => usersApi.list().then((r) => r.data || []),
  });

  const createMutation = useMutation({
    mutationFn: (data: any) => usersApi.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users-list'] });
      setShowCreateModal(false);
      setMsg('User account provisioned with assigned role.');
      setUsername('');
      setFullName('');
      setEmail('');
    },
    onError: (err: any) => {
      setMsg(err?.response?.data?.detail || 'Failed to provision user');
    },
  });

  const lockMutation = useMutation({
    mutationFn: (id: string) => usersApi.lock(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['users-list'] }),
  });

  const unlockMutation = useMutation({
    mutationFn: (id: string) => usersApi.unlock(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['users-list'] }),
  });

  const handleCreate = (e: React.FormEvent) => {
    e.preventDefault();
    createMutation.mutate({
      username,
      full_name: fullName,
      email,
      role,
      password,
    });
  };

  return (
    <div className="space-y-6">
      <div className="gov-card-warm flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-[var(--gov-navy-dark)]">
            Staff & Role-Based Access Control (RBAC)
          </h1>
          <p className="text-xs text-slate-500 mt-1">
            Manage authenticated officials across all 11 system roles with strict privilege separation
          </p>
        </div>
        <button
          onClick={() => setShowCreateModal(true)}
          className="btn btn-navy text-xs"
        >
          <UserPlus className="w-4 h-4" /> Provision User
        </button>
      </div>

      {msg && (
        <div className="p-3 bg-amber-50 border border-amber-200 text-amber-900 rounded-lg text-xs flex items-center gap-2">
          <Shield className="w-4 h-4 text-amber-600" />
          <span>{msg}</span>
        </div>
      )}

      <div className="gov-card">
        <div className="overflow-x-auto">
          <table className="gov-table">
            <thead>
              <tr>
                <th>Username</th>
                <th>Full Name</th>
                <th>Role</th>
                <th>Status</th>
                <th>MFA Enabled</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr>
                  <td colSpan={6} className="py-8 text-center text-slate-400">Loading user directory...</td>
                </tr>
              ) : (
                users.map((u: any) => (
                  <tr key={u.id}>
                    <td className="font-mono text-xs font-bold text-slate-800">@{u.username}</td>
                    <td className="text-xs text-slate-700">{u.full_name || '—'}</td>
                    <td>
                      <span className="badge-info text-[10px]">{u.role}</span>
                    </td>
                    <td>
                      {u.is_active ? (
                        <span className="badge-secure">Active</span>
                      ) : (
                        <span className="badge-critical">Locked</span>
                      )}
                    </td>
                    <td className="text-xs text-slate-600 font-mono">
                      {u.is_mfa_enabled ? 'Enforced' : 'Pending'}
                    </td>
                    <td>
                      {u.is_active ? (
                        <button
                          onClick={() => lockMutation.mutate(u.id)}
                          className="btn btn-outline text-[11px] py-1 px-2 text-red-600 hover:bg-red-50"
                          title="Lock Account"
                        >
                          <Lock className="w-3 h-3" /> Lock
                        </button>
                      ) : (
                        <button
                          onClick={() => unlockMutation.mutate(u.id)}
                          className="btn btn-outline text-[11px] py-1 px-2 text-emerald-600 hover:bg-emerald-50"
                          title="Unlock Account"
                        >
                          <Unlock className="w-3 h-3" /> Unlock
                        </button>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Provision User Modal */}
      <ActionModal
        isOpen={showCreateModal}
        onClose={() => setShowCreateModal(false)}
        title="Provision Authorized Official"
        subtitle="Assign role and establish system credentials"
      >
        <form onSubmit={handleCreate} className="space-y-4 text-xs">
          <div>
            <label className="form-label">Username</label>
            <input
              type="text"
              className="form-input text-xs"
              placeholder="e.g. j_doe"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
            />
          </div>

          <div>
            <label className="form-label">Full Name</label>
            <input
              type="text"
              className="form-input text-xs"
              placeholder="e.g. Dr. Jane Doe"
              value={fullName}
              onChange={(e) => setFullName(e.target.value)}
              required
            />
          </div>

          <div>
            <label className="form-label">Email Address</label>
            <input
              type="email"
              className="form-input text-xs"
              placeholder="e.g. j.doe@bsea.gov.in"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
          </div>

          <div>
            <label className="form-label">System Role</label>
            <select
              className="form-input text-xs"
              value={role}
              onChange={(e) => setRole(e.target.value)}
            >
              <option value="QUESTION_SETTER">QUESTION_SETTER</option>
              <option value="REVIEWER">REVIEWER</option>
              <option value="EXAM_AUTHORITY">EXAM_AUTHORITY</option>
              <option value="RELEASE_AUTHORITY">RELEASE_AUTHORITY</option>
              <option value="SECURITY_OFFICER">SECURITY_OFFICER</option>
              <option value="CENTRE_ADMIN">CENTRE_ADMIN</option>
              <option value="INVIGILATOR">INVIGILATOR</option>
              <option value="AUDITOR">AUDITOR</option>
              <option value="SUPER_ADMIN">SUPER_ADMIN</option>
            </select>
          </div>

          <div className="pt-2 flex justify-end gap-2">
            <button
              type="button"
              className="btn btn-outline text-xs"
              onClick={() => setShowCreateModal(false)}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="btn btn-primary text-xs"
              disabled={createMutation.isPending}
            >
              {createMutation.isPending ? 'Provisioning...' : 'Provision User'}
            </button>
          </div>
        </form>
      </ActionModal>
    </div>
  );
}
