import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import {
  AlertTriangle, Plus, Shield, CheckCircle2, AlertOctagon,
  Zap, ArrowRight, Clock, ShieldAlert, RefreshCw, Filter
} from 'lucide-react';
import { incidentsApi } from '../../services/api';
import StatusBadge from '../../components/ui/StatusBadge';
import ActionModal from '../../components/ui/ActionModal';
import EmptyState from '../../components/ui/EmptyState';

export default function IncidentsPage() {
  const queryClient = useQueryClient();
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showActionModal, setShowActionModal] = useState(false);
  const [selectedIncident, setSelectedIncident] = useState<any>(null);

  // Form states
  const [title, setTitle] = useState('');
  const [severity, setSeverity] = useState('HIGH');
  const [description, setDescription] = useState('');
  const [affectedResource, setAffectedResource] = useState('');
  const [actionReason, setActionReason] = useState('');
  const [actionType, setActionType] = useState('RESOLVE');
  const [actionTargetId, setActionTargetId] = useState('');
  const [msg, setMsg] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  const { data: incidents = [], isLoading, refetch } = useQuery({
    queryKey: ['incidents-list'],
    queryFn: () => incidentsApi.list().then((r) => r.data || []),
    refetchInterval: 10000,
  });

  const createMutation = useMutation({
    mutationFn: (data: any) => incidentsApi.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['incidents-list'] });
      setShowCreateModal(false);
      setMsg({ type: 'success', text: 'Security incident created and placed in TRIAGE.' });
      setTitle('');
      setDescription('');
      setAffectedResource('');
    },
    onError: (err: any) => {
      setMsg({ type: 'error', text: err?.response?.data?.detail || 'Failed to create incident' });
    },
  });

  const actionMutation = useMutation({
    mutationFn: () =>
      incidentsApi.executeAction(
        selectedIncident.id,
        actionType,
        actionTargetId || selectedIncident.affected_resource || 'target',
        actionReason
      ),
    onSuccess: (res) => {
      queryClient.invalidateQueries({ queryKey: ['incidents-list'] });
      setShowActionModal(false);
      setMsg({ type: 'success', text: res?.data?.message || 'Incident action executed successfully.' });
      setActionReason('');
    },
    onError: (err: any) => {
      setMsg({ type: 'error', text: err?.response?.data?.detail || 'Failed to execute incident action' });
    },
  });

  const handleCreate = (e: React.FormEvent) => {
    e.preventDefault();
    if (!title.trim()) return;
    createMutation.mutate({
      title,
      severity,
      description,
      affected_resource: affectedResource,
    });
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="gov-card-warm flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <h1 className="text-xl font-bold text-[var(--gov-navy-dark)]">
              Security Incident Management & Escalation
            </h1>
            <span className="badge-secure">Phase 3C-5D Engine</span>
          </div>
          <p className="text-xs text-slate-500">
            Authoritative 5-state lifecycle: TRIAGE → INVESTIGATING → CONTAINED → RESOLVED → CLOSED
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Link to="/admin/containment" className="btn btn-outline text-xs">
            <ShieldAlert className="w-3.5 h-3.5 text-amber-700" /> Containment Console
          </Link>
          <button
            onClick={() => setShowCreateModal(true)}
            className="btn btn-navy text-xs"
          >
            <Plus className="w-4 h-4" /> Declare Incident
          </button>
        </div>
      </div>

      {msg && (
        <div className={`p-3 rounded-lg text-xs flex items-center gap-2 ${
          msg.type === 'success' ? 'bg-emerald-50 border border-emerald-200 text-emerald-800' : 'bg-red-50 border border-red-200 text-red-700'
        }`}>
          {msg.type === 'success' ? <CheckCircle2 className="w-4 h-4 shrink-0" /> : <AlertTriangle className="w-4 h-4 shrink-0" />}
          <span>{msg.text}</span>
        </div>
      )}

      {/* Incidents Table */}
      <div className="gov-card">
        <div className="flex items-center justify-between pb-3 border-b border-[var(--gov-border)] mb-4">
          <h2 className="text-sm font-bold text-[var(--gov-navy-dark)] flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-red-600" />
            Active Incident Roster
          </h2>
          <span className="text-xs text-slate-500 font-semibold">{incidents.length} Registered</span>
        </div>

        {isLoading ? (
          <div className="py-12 text-center text-xs text-slate-400">Loading incidents...</div>
        ) : incidents.length === 0 ? (
          <EmptyState
            title="No active security incidents"
            description="The security monitoring engine has not flagged any active operational incidents."
            actionText="Declare Incident"
            onAction={() => setShowCreateModal(true)}
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="gov-table">
              <thead>
                <tr>
                  <th>Title</th>
                  <th>Severity</th>
                  <th>Lifecycle State</th>
                  <th>Affected Resource</th>
                  <th>Reported</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {incidents.map((inc: any) => (
                  <tr key={inc.id}>
                    <td>
                      <div className="font-bold text-slate-800 text-xs">{inc.title}</div>
                      <div className="font-mono text-[10px] text-slate-400">{inc.id}</div>
                    </td>
                    <td>
                      <StatusBadge status={inc.severity} type="incident" />
                    </td>
                    <td>
                      <StatusBadge status={inc.status} type="incident" />
                    </td>
                    <td className="text-xs font-mono text-slate-600 truncate max-w-[150px]">
                      {inc.affected_resource || '—'}
                    </td>
                    <td className="text-xs text-slate-500 font-mono">
                      {new Date(inc.created_at).toLocaleString('en-IN')}
                    </td>
                    <td>
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => {
                            setSelectedIncident(inc);
                            setActionTargetId(inc.affected_resource || '');
                            setShowActionModal(true);
                          }}
                          className="btn btn-outline text-[11px] py-1 px-2.5 text-slate-700 hover:bg-slate-50"
                        >
                          <Zap className="w-3 h-3 text-amber-600" /> Action
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Declare Incident Modal */}
      <ActionModal
        isOpen={showCreateModal}
        onClose={() => setShowCreateModal(false)}
        title="Declare Security Incident"
        subtitle="Initialize formal incident response tracking"
      >
        <form onSubmit={handleCreate} className="space-y-4 text-xs">
          <div>
            <label className="form-label">Incident Title</label>
            <input
              type="text"
              className="form-input text-xs"
              placeholder="e.g. Center-402 Network Telemetry Dropout"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              required
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="form-label">Severity Level</label>
              <select
                className="form-input text-xs"
                value={severity}
                onChange={(e) => setSeverity(e.target.value)}
              >
                <option value="CRITICAL">CRITICAL</option>
                <option value="HIGH">HIGH</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="LOW">LOW</option>
              </select>
            </div>
            <div>
              <label className="form-label">Affected Resource</label>
              <input
                type="text"
                className="form-input text-xs font-mono"
                placeholder="e.g. centre_402, sess_9812"
                value={affectedResource}
                onChange={(e) => setAffectedResource(e.target.value)}
              />
            </div>
          </div>

          <div>
            <label className="form-label">Description & Context</label>
            <textarea
              className="form-input text-xs min-h-[80px]"
              placeholder="Provide preliminary triage context and observed telemetry..."
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
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
              {createMutation.isPending ? 'Declaring...' : 'Declare Incident'}
            </button>
          </div>
        </form>
      </ActionModal>

      {/* Incident Response Action Modal */}
      <ActionModal
        isOpen={showActionModal}
        onClose={() => setShowActionModal(false)}
        title="Execute Incident Response Action"
        subtitle={`Incident: ${selectedIncident?.title || ''}`}
      >
        <form onSubmit={(e) => { e.preventDefault(); actionMutation.mutate(); }} className="space-y-4 text-xs">
          <div>
            <label className="form-label">Action</label>
            <select
              className="form-input text-xs"
              value={actionType}
              onChange={(e) => setActionType(e.target.value)}
            >
              <option value="RESOLVE">Resolve Incident</option>
              <option value="LOCK_USER">Lock Associated User Account</option>
              <option value="REVOKE_SESSION">Revoke Candidate CBT Session</option>
            </select>
          </div>

          <div>
            <label className="form-label">Target ID</label>
            <input
              type="text"
              className="form-input text-xs font-mono"
              value={actionTargetId}
              onChange={(e) => setActionTargetId(e.target.value)}
              required
            />
          </div>

          <div>
            <label className="form-label">Reason / Justification</label>
            <textarea
              className="form-input text-xs min-h-[70px]"
              placeholder="Enter rationale for this action..."
              value={actionReason}
              onChange={(e) => setActionReason(e.target.value)}
              required
            />
          </div>

          <div className="pt-2 flex justify-end gap-2">
            <button
              type="button"
              className="btn btn-outline text-xs"
              onClick={() => setShowActionModal(false)}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="btn btn-primary text-xs"
              disabled={actionMutation.isPending}
            >
              {actionMutation.isPending ? 'Executing...' : 'Execute Action'}
            </button>
          </div>
        </form>
      </ActionModal>
    </div>
  );
}
