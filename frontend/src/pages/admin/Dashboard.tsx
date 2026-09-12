import { useQuery } from '@tanstack/react-query';
import { Shield, FileText, Lock, AlertTriangle, Activity, Users, CheckCircle, XCircle, Clock } from 'lucide-react';
import { dashboardApi, auditApi } from '../../services/api';

function StatCard({ title, value, subtitle, icon, color = 'blue' }: {
  title: string; value: string | number; subtitle?: string; icon: React.ReactNode; color?: string;
}) {
  const colorMap: Record<string, string> = {
    blue: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
    green: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
    amber: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
    red: 'bg-red-500/10 text-red-400 border-red-500/20',
    purple: 'bg-purple-500/10 text-purple-400 border-purple-500/20',
  };
  return (
    <div className="card-elevated">
      <div className="flex items-center justify-between mb-4">
        <div className={`w-10 h-10 rounded-xl flex items-center justify-center border ${colorMap[color]}`}>
          {icon}
        </div>
      </div>
      <div className="text-3xl font-bold text-white font-mono mb-1">{value}</div>
      <div className="text-sm font-semibold text-slate-300">{title}</div>
      {subtitle && <div className="text-xs text-slate-500 mt-0.5">{subtitle}</div>}
    </div>
  );
}

function AuditChainStatus() {
  const { data, isLoading } = useQuery({
    queryKey: ['audit-verify'],
    queryFn: () => auditApi.verifyChain().then(r => r.data),
    refetchInterval: 30000,
  });

  if (isLoading) return <div className="text-xs text-slate-500">Verifying chain...</div>;

  return (
    <div className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-semibold ${
      data?.valid
        ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
        : 'bg-red-500/10 text-red-400 border border-red-500/20'
    }`}>
      {data?.valid ? <CheckCircle className="w-3.5 h-3.5" /> : <XCircle className="w-3.5 h-3.5" />}
      {data?.valid
        ? `Chain Intact (${data.entries_checked} entries)`
        : `CHAIN VIOLATION at entry ${data?.broken_at}`}
    </div>
  );
}

export default function Dashboard() {
  const { data: overview, isLoading } = useQuery({
    queryKey: ['dashboard'],
    queryFn: () => dashboardApi.overview().then(r => r.data),
    refetchInterval: 10000,
  });

  const stats = overview?.stats;
  const systemHealth = overview?.system_health;

  return (
    <div className="p-8">
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold text-white">Security Dashboard</h1>
          <p className="text-slate-400 text-sm mt-1">Real-time examination security overview</p>
        </div>
        <div className="flex items-center gap-3">
          <AuditChainStatus />
          <div className="flex items-center gap-1.5 text-xs text-slate-500">
            <Clock className="w-3.5 h-3.5" />
            Auto-refresh 10s
          </div>
        </div>
      </div>

      {/* Stats grid */}
      <div className="grid grid-cols-2 xl:grid-cols-4 gap-4 mb-8">
        <StatCard
          title="Total Exams"
          value={stats?.total_exams ?? '—'}
          subtitle={`${stats?.active_exams ?? 0} currently released`}
          icon={<FileText className="w-5 h-5" />}
          color="blue"
        />
        <StatCard
          title="Encrypted Questions"
          value={stats?.encrypted_questions ?? '—'}
          subtitle={`${stats?.total_questions ?? 0} total questions`}
          icon={<Lock className="w-5 h-5" />}
          color="green"
        />
        <StatCard
          title="Active Sessions"
          value={stats?.active_sessions ?? '—'}
          subtitle="Live exam candidates"
          icon={<Users className="w-5 h-5" />}
          color="purple"
        />
        <StatCard
          title="Security Events (24h)"
          value={stats?.security_events_24h ?? '—'}
          subtitle={`${stats?.critical_unresolved ?? 0} critical unresolved`}
          icon={<AlertTriangle className="w-5 h-5" />}
          color={stats?.critical_unresolved > 0 ? 'red' : 'amber'}
        />
      </div>

      {/* System Health + Recent Exams */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Recent Exams */}
        <div className="xl:col-span-2 card">
          <div className="flex items-center justify-between mb-4">
            <h2 className="font-bold text-white">Recent Exams</h2>
            <a href="/admin/exams" className="text-xs text-blue-400 hover:underline">View all →</a>
          </div>

          {isLoading ? (
            <div className="text-slate-500 text-sm">Loading...</div>
          ) : (
            <div className="space-y-3">
              {(overview?.recent_exams || []).map((exam: any) => (
                <div key={exam.id} className="flex items-center justify-between py-3 border-b border-slate-800/50 last:border-0">
                  <div className="min-w-0">
                    <div className="text-sm font-medium text-white truncate">{exam.title}</div>
                    <div className="text-xs text-slate-500 mt-0.5">
                      {exam.scheduled_start_utc
                        ? new Date(exam.scheduled_start_utc).toLocaleDateString('en-IN', { dateStyle: 'medium' })
                        : 'No schedule set'}
                    </div>
                  </div>
                  <div className="flex items-center gap-2 shrink-0 ml-4">
                    <span className={`badge-info text-xs ${
                      exam.status === 'RELEASED' ? 'badge-secure' :
                      exam.status === 'FROZEN' ? 'badge-critical' :
                      exam.status === 'THRESHOLD_APPROVED' ? 'badge-purple' : 'badge-info'
                    }`}>
                      {exam.status}
                    </span>
                    <span className="badge-warning text-xs">{exam.security_mode}</span>
                  </div>
                </div>
              ))}
              {(!overview?.recent_exams?.length) && (
                <div className="text-slate-500 text-sm py-4 text-center">No exams yet</div>
              )}
            </div>
          )}
        </div>

        {/* System Status */}
        <div className="card">
          <h2 className="font-bold text-white mb-4">System Status</h2>
          <div className="space-y-3">
            {systemHealth && Object.entries(systemHealth).map(([service, status]) => (
              <div key={service} className="flex items-center justify-between">
                <span className="text-sm text-slate-400 capitalize">{service.replace('_', ' ')}</span>
                <span className={`badge-${status === 'healthy' ? 'secure' : status === 'mock_kms_prototype' ? 'warning' : 'critical'} text-xs`}>
                  {String(status).toUpperCase().replace('_', ' ')}
                </span>
              </div>
            ))}

            {/* Open incidents */}
            <div className="mt-4 pt-4 border-t border-slate-800">
              <div className="flex items-center justify-between">
                <span className="text-sm text-slate-400">Open Incidents</span>
                <span className={`font-bold text-lg ${stats?.open_incidents > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                  {stats?.open_incidents ?? 0}
                </span>
              </div>
              {stats?.open_incidents > 0 && (
                <a href="/admin/incidents" className="text-xs text-red-400 hover:underline mt-1 block">
                  View incidents →
                </a>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
