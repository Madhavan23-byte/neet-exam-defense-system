import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { incidentsApi, usersApi } from '../../services/api';
import { useState } from 'react';
import { AlertTriangle, Plus, Zap } from 'lucide-react';

const SEVERITY_COLORS: Record<string, string> = {
  LOW: 'badge-info',
  MEDIUM: 'badge-warning',
  HIGH: 'badge-critical',
  CRITICAL: 'badge-critical',
};

const STATUS_COLORS: Record<string, string> = {
  OPEN: 'badge-critical',
  INVESTIGATING: 'badge-warning',
  CONTAINED: 'badge-warning',
  RESOLVED: 'badge-secure',
};

function CreateIncidentModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [form, setForm] = useState({ title: '', severity: 'HIGH', description: '', affected_resource: '' });
  const mutation = useMutation({
    mutationFn: () => incidentsApi.create(form),
    onSuccess: () => { onCreated(); onClose(); },
  });
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="w-full max-w-md card-elevated animate-fade-in">
        <h2 className="text-lg font-bold text-white mb-5">Create Security Incident</h2>
        <div className="space-y-4">
          <div>
            <label className="form-label">Title</label>
            <input className="form-input" placeholder="Incident title..."
              value={form.title} onChange={e => setForm({ ...form, title: e.target.value })} />
          </div>
          <div>
            <label className="form-label">Severity</label>
            <select className="form-input" value={form.severity} onChange={e => setForm({ ...form, severity: e.target.value })}>
              <option>LOW</option><option>MEDIUM</option><option>HIGH</option><option>CRITICAL</option>
            </select>
          </div>
          <div>
            <label className="form-label">Description</label>
            <textarea className="form-input" rows={3} value={form.description}
              onChange={e => setForm({ ...form, description: e.target.value })} />
          </div>
        </div>
        <div className="flex gap-3 mt-5">
          <button className="btn btn-danger flex-1 justify-center" onClick={() => mutation.mutate()} disabled={!form.title}>
            Create Incident
          </button>
          <button className="btn btn-ghost" onClick={onClose}>Cancel</button>
        </div>
      </div>
    </div>
  );
}

export default function IncidentsPage() {
  const qc = useQueryClient();
  const [showCreate, setShowCreate] = useState(false);
  const [selectedIncident, setSelectedIncident] = useState<any>(null);
  const [actionForm, setActionForm] = useState({ action: 'RESOLVE', target_id: '', reason: '' });

  const { data: incidents = [] } = useQuery({
    queryKey: ['incidents'],
    queryFn: () => incidentsApi.list().then(r => r.data),
    refetchInterval: 10000,
  });

  const actionMutation = useMutation({
    mutationFn: () => incidentsApi.executeAction(
      selectedIncident.id, actionForm.action, actionForm.target_id || selectedIncident.id, actionForm.reason
    ),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['incidents'] });
      setSelectedIncident(null);
    },
  });

  return (
    <div className="p-8">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold text-white">Incident Response</h1>
          <p className="text-slate-400 text-sm mt-1">Security incident management and response actions</p>
        </div>
        <button className="btn btn-danger" onClick={() => setShowCreate(true)}>
          <Plus className="w-4 h-4" /> Create Incident
        </button>
      </div>

      <div className="space-y-3">
        {incidents.map((incident: any) => (
          <div key={incident.id} className="card flex items-center justify-between hover:border-red-500/20 transition-all">
            <div className="flex items-center gap-4">
              <div className="w-10 h-10 rounded-xl bg-red-500/10 flex items-center justify-center shrink-0">
                <AlertTriangle className="w-5 h-5 text-red-400" />
              </div>
              <div>
                <div className="text-sm font-semibold text-white">{incident.title}</div>
                <div className="flex items-center gap-2 mt-1">
                  <span className={SEVERITY_COLORS[incident.severity]}>{incident.severity}</span>
                  <span className={STATUS_COLORS[incident.status]}>{incident.status}</span>
                  {incident.affected_resource && (
                    <span className="text-xs text-slate-500">→ {incident.affected_resource}</span>
                  )}
                </div>
                <div className="text-xs text-slate-600 mt-0.5">
                  {new Date(incident.created_at).toLocaleString()}
                  {incident.resolved_at && ` → Resolved ${new Date(incident.resolved_at).toLocaleString()}`}
                </div>
              </div>
            </div>
            {incident.status !== 'RESOLVED' && (
              <button
                className="btn btn-ghost text-sm shrink-0 ml-4"
                onClick={() => setSelectedIncident(incident)}
              >
                <Zap className="w-3.5 h-3.5" /> Take Action
              </button>
            )}
          </div>
        ))}
        {incidents.length === 0 && (
          <div className="card text-center py-12">
            <AlertTriangle className="w-10 h-10 text-slate-600 mx-auto mb-3" />
            <div className="text-slate-400">No open incidents</div>
          </div>
        )}
      </div>

      {/* Action modal */}
      {selectedIncident && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="w-full max-w-md card-elevated animate-fade-in">
            <h2 className="text-lg font-bold text-white mb-2">Incident Response Action</h2>
            <p className="text-sm text-slate-400 mb-5">{selectedIncident.title}</p>
            <div className="space-y-4">
              <div>
                <label className="form-label">Action</label>
                <select className="form-input" value={actionForm.action}
                  onChange={e => setActionForm({ ...actionForm, action: e.target.value })}>
                  <option value="RESOLVE">RESOLVE</option>
                  <option value="LOCK_USER">LOCK_USER</option>
                  <option value="REVOKE_SESSION">REVOKE_SESSION</option>
                </select>
              </div>
              {actionForm.action !== 'RESOLVE' && (
                <div>
                  <label className="form-label">Target ID</label>
                  <input className="form-input font-mono" placeholder="User ID or Session ID..."
                    value={actionForm.target_id} onChange={e => setActionForm({ ...actionForm, target_id: e.target.value })} />
                </div>
              )}
              <div>
                <label className="form-label">Reason</label>
                <input className="form-input" placeholder="Action justification..."
                  value={actionForm.reason} onChange={e => setActionForm({ ...actionForm, reason: e.target.value })} />
              </div>
            </div>
            <div className="flex gap-3 mt-5">
              <button
                className="btn btn-danger flex-1 justify-center"
                onClick={() => actionMutation.mutate()}
                disabled={!actionForm.reason || actionMutation.isPending}
              >
                {actionMutation.isPending ? 'Executing...' : 'Execute Action'}
              </button>
              <button className="btn btn-ghost" onClick={() => setSelectedIncident(null)}>Cancel</button>
            </div>
          </div>
        </div>
      )}

      {showCreate && (
        <CreateIncidentModal
          onClose={() => setShowCreate(false)}
          onCreated={() => qc.invalidateQueries({ queryKey: ['incidents'] })}
        />
      )}
    </div>
  );
}
