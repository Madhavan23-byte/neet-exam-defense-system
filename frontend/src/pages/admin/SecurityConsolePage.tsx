import { useQuery, useMutation } from '@tanstack/react-query';
import { securityApi } from '../../services/api';
import { Activity, AlertTriangle, Shield, TrendingUp } from 'lucide-react';

const SEVERITY_COLORS: Record<string, string> = {
  LOW: 'badge-info',
  MEDIUM: 'badge-warning',
  HIGH: 'badge-critical',
  CRITICAL: 'badge-critical',
};

export default function SecurityConsolePage() {
  const { data: stats } = useQuery({
    queryKey: ['security-stats'],
    queryFn: () => securityApi.getStats().then(r => r.data),
    refetchInterval: 5000,
  });

  const { data: events = [] } = useQuery({
    queryKey: ['security-events'],
    queryFn: () => securityApi.getEvents().then(r => r.data),
    refetchInterval: 5000,
  });

  return (
    <div className="p-8">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold text-white">Security Console</h1>
          <p className="text-slate-400 text-sm mt-1">Real-time anomaly detection and threat monitoring</p>
        </div>
        <div className="flex items-center gap-2 text-xs text-slate-500">
          <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          Live monitoring
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 xl:grid-cols-4 gap-4 mb-8">
        {[
          { label: 'Total Events', value: stats?.total_security_events ?? '—', color: 'blue', icon: <Activity className="w-5 h-5" /> },
          { label: 'Unresolved Critical', value: stats?.unresolved_high_critical ?? '—', color: stats?.unresolved_high_critical > 0 ? 'red' : 'green', icon: <AlertTriangle className="w-5 h-5" /> },
          { label: 'Events (24h)', value: stats?.events_last_24h ?? '—', color: 'amber', icon: <TrendingUp className="w-5 h-5" /> },
          { label: 'Open Incidents', value: stats?.open_incidents ?? '—', color: stats?.open_incidents > 0 ? 'red' : 'green', icon: <Shield className="w-5 h-5" /> },
        ].map((s, i) => (
          <div key={i} className="card-elevated">
            <div className={`w-10 h-10 rounded-xl flex items-center justify-center mb-3 ${
              s.color === 'blue' ? 'bg-blue-500/10 text-blue-400' :
              s.color === 'red' ? 'bg-red-500/10 text-red-400' :
              s.color === 'green' ? 'bg-emerald-500/10 text-emerald-400' :
              'bg-amber-500/10 text-amber-400'
            }`}>
              {s.icon}
            </div>
            <div className="text-2xl font-bold text-white font-mono">{s.value}</div>
            <div className="text-xs text-slate-400 mt-1">{s.label}</div>
          </div>
        ))}
      </div>

      {/* Events table */}
      <div className="card">
        <h2 className="font-bold text-white mb-4">Security Events</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-800">
                <th className="text-left py-2 px-3 text-xs text-slate-500 uppercase tracking-wider">Event Type</th>
                <th className="text-left py-2 px-3 text-xs text-slate-500 uppercase tracking-wider">Severity</th>
                <th className="text-left py-2 px-3 text-xs text-slate-500 uppercase tracking-wider">Risk Score</th>
                <th className="text-left py-2 px-3 text-xs text-slate-500 uppercase tracking-wider">Actor</th>
                <th className="text-left py-2 px-3 text-xs text-slate-500 uppercase tracking-wider">Status</th>
                <th className="text-left py-2 px-3 text-xs text-slate-500 uppercase tracking-wider">Time</th>
              </tr>
            </thead>
            <tbody>
              {events.map((e: any) => (
                <tr key={e.id} className="border-b border-slate-800/30 hover:bg-slate-800/20 transition-colors">
                  <td className="py-3 px-3 font-mono text-xs text-slate-300">{e.event_type}</td>
                  <td className="py-3 px-3">
                    <span className={SEVERITY_COLORS[e.severity] || 'badge-info'}>{e.severity}</span>
                  </td>
                  <td className="py-3 px-3">
                    <div className="flex items-center gap-2">
                      <div className="h-1.5 w-24 bg-slate-800 rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full ${e.risk_score > 0.7 ? 'bg-red-500' : e.risk_score > 0.4 ? 'bg-amber-500' : 'bg-blue-500'}`}
                          style={{ width: `${e.risk_score * 100}%` }}
                        />
                      </div>
                      <span className="text-xs font-mono text-slate-400">{(e.risk_score * 100).toFixed(0)}%</span>
                    </div>
                  </td>
                  <td className="py-3 px-3 text-xs font-mono text-slate-500">{e.actor_id?.slice(0, 12) || 'system'}</td>
                  <td className="py-3 px-3">
                    <span className={e.resolved ? 'badge-secure' : 'badge-critical'}>{e.resolved ? 'RESOLVED' : 'OPEN'}</span>
                  </td>
                  <td className="py-3 px-3 text-xs text-slate-500">
                    {new Date(e.created_at).toLocaleString()}
                  </td>
                </tr>
              ))}
              {events.length === 0 && (
                <tr>
                  <td colSpan={6} className="text-center py-8 text-slate-500">No security events</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
