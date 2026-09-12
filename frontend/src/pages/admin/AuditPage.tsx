import { useQuery } from '@tanstack/react-query';
import { auditApi } from '../../services/api';
import { BookCheck, CheckCircle, XCircle, AlertTriangle } from 'lucide-react';

export default function AuditPage() {
  const { data: logs = [], isLoading } = useQuery({
    queryKey: ['audit-logs'],
    queryFn: () => auditApi.getLogs(100).then(r => r.data),
    refetchInterval: 15000,
  });

  const { data: chainStatus, refetch: verifyChain, isFetching: verifying } = useQuery({
    queryKey: ['audit-verify'],
    queryFn: () => auditApi.verifyChain().then(r => r.data),
    refetchInterval: 30000,
  });

  const RESULT_COLORS: Record<string, string> = {
    SUCCESS: 'badge-secure',
    FAILURE: 'badge-critical',
    BLOCKED: 'badge-warning',
    WARNING: 'badge-warning',
  };

  return (
    <div className="p-8">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold text-white">Audit Trail</h1>
          <p className="text-slate-400 text-sm mt-1">Hash-chained tamper-evident event log</p>
        </div>
        <div className="flex items-center gap-3">
          {chainStatus && (
            <div className={`flex items-center gap-2 px-4 py-2 rounded-lg border text-sm font-semibold ${
              chainStatus.valid
                ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                : 'bg-red-500/10 border-red-500/30 text-red-400'
            }`}>
              {chainStatus.valid ? <CheckCircle className="w-4 h-4" /> : <XCircle className="w-4 h-4" />}
              {chainStatus.valid
                ? `Chain Intact · ${chainStatus.entries_checked} entries`
                : `VIOLATION at seq ${chainStatus.broken_at}`}
            </div>
          )}
          <button
            className="btn btn-ghost text-sm"
            onClick={() => verifyChain()}
            disabled={verifying}
          >
            {verifying ? 'Verifying...' : '🔍 Verify Chain'}
          </button>
        </div>
      </div>

      {/* Architecture note */}
      <div className="mb-6 p-4 rounded-xl border border-purple-900/20 bg-purple-950/10 flex gap-3 text-sm text-slate-400">
        <BookCheck className="w-5 h-5 text-purple-400 shrink-0 mt-0.5" />
        <span>
          Each audit entry contains <code className="text-purple-400 text-xs">event_hash = SHA256(event_data + prev_hash)</code>.
          Any modification to historical records invalidates all subsequent hashes, making tampering mathematically detectable.
          The chain verification recomputes all hashes from genesis and compares them.
        </span>
      </div>

      {/* Audit log table */}
      <div className="card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-900/50">
                <th className="text-left py-3 px-4 text-xs text-slate-500 uppercase tracking-wider w-12">Seq</th>
                <th className="text-left py-3 px-4 text-xs text-slate-500 uppercase tracking-wider">Event Type</th>
                <th className="text-left py-3 px-4 text-xs text-slate-500 uppercase tracking-wider">Actor</th>
                <th className="text-left py-3 px-4 text-xs text-slate-500 uppercase tracking-wider">Resource</th>
                <th className="text-left py-3 px-4 text-xs text-slate-500 uppercase tracking-wider">Result</th>
                <th className="text-left py-3 px-4 text-xs text-slate-500 uppercase tracking-wider">Chain Hash</th>
                <th className="text-left py-3 px-4 text-xs text-slate-500 uppercase tracking-wider">Time</th>
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr><td colSpan={7} className="text-center py-8 text-slate-500">Loading audit logs...</td></tr>
              ) : logs.map((log: any) => (
                <tr key={log.id} className="border-b border-slate-800/20 hover:bg-slate-800/20 transition-colors">
                  <td className="py-2.5 px-4 text-xs font-mono text-slate-500">#{log.seq}</td>
                  <td className="py-2.5 px-4 text-xs font-mono text-slate-300 font-medium">{log.event_type}</td>
                  <td className="py-2.5 px-4">
                    <div className="text-xs text-slate-400 font-mono">{log.actor_id?.slice(0, 8) || 'system'}</div>
                    {log.actor_role && <div className="text-xs text-slate-600">{log.actor_role}</div>}
                  </td>
                  <td className="py-2.5 px-4 text-xs text-slate-500">
                    {log.resource_type && <span>{log.resource_type}: {log.resource_id?.slice(0, 8)}</span>}
                  </td>
                  <td className="py-2.5 px-4">
                    <span className={RESULT_COLORS[log.result] || 'badge-info'}>{log.result}</span>
                  </td>
                  <td className="py-2.5 px-4 font-mono text-xs text-purple-400">{log.event_hash}</td>
                  <td className="py-2.5 px-4 text-xs text-slate-500 whitespace-nowrap">
                    {new Date(log.timestamp).toLocaleString()}
                  </td>
                </tr>
              ))}
              {logs.length === 0 && !isLoading && (
                <tr><td colSpan={7} className="text-center py-8 text-slate-500">No audit events yet</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
