import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  Activity, AlertTriangle, Shield, TrendingUp, RefreshCw,
  Clock, CheckCircle2, AlertOctagon, Filter, Eye
} from 'lucide-react';
import { securityApi } from '../../services/api';
import DataTile from '../../components/ui/DataTile';
import StatusBadge from '../../components/ui/StatusBadge';
import EmptyState from '../../components/ui/EmptyState';

export default function SecurityConsolePage() {
  const [filterSeverity, setFilterSeverity] = useState('ALL');

  // Constraint 4: Real data only from actual backend API
  const {
    data: stats,
    isLoading: statsLoading,
    refetch: refetchStats,
    isFetching: statsFetching,
  } = useQuery({
    queryKey: ['security-stats'],
    queryFn: () => securityApi.getStats().then((r) => r.data),
    refetchInterval: 10000,
  });

  const {
    data: events = [],
    isLoading: eventsLoading,
    refetch: refetchEvents,
    isFetching: eventsFetching,
  } = useQuery({
    queryKey: ['security-events'],
    queryFn: () => securityApi.getEvents().then((r) => r.data || []),
    refetchInterval: 10000,
  });

  const filteredEvents = events.filter((ev: any) => {
    if (filterSeverity === 'ALL') return true;
    return ev.severity === filterSeverity;
  });

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="gov-card-warm flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <h1 className="text-xl font-bold text-[var(--gov-navy-dark)]">
              Threat Observability & Telemetry Console
            </h1>
            <span className="badge-secure">Phase 3C-5C Detection Active</span>
          </div>
          <p className="text-xs text-slate-500">
            Real-time heuristic signal correlation, rate anomaly detection, and tamper telemetry
          </p>
        </div>
        <button
          onClick={() => {
            refetchStats();
            refetchEvents();
          }}
          disabled={statsFetching || eventsFetching}
          className="btn btn-outline text-xs"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${statsFetching || eventsFetching ? 'animate-spin' : ''}`} />
          <span>{statsFetching || eventsFetching ? 'Refreshing...' : 'Refresh Telemetry'}</span>
        </button>
      </div>

      {/* Verified Telemetry Metrics (Constraint 4) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <DataTile
          label="Total Security Events"
          value={statsLoading ? '...' : stats?.total_events ?? events.length}
          subtitle="All recorded telemetry signals"
          icon={<Activity className="w-4 h-4 text-blue-700" />}
        />
        <DataTile
          label="Unresolved Critical"
          value={statsLoading ? '...' : stats?.unresolved_critical ?? 0}
          subtitle="Requiring immediate triage"
          icon={<AlertOctagon className="w-4 h-4 text-red-700" />}
        />
        <DataTile
          label="Tab Switches (24h)"
          value={statsLoading ? '...' : stats?.tab_switch_events ?? 0}
          subtitle="Candidate browser anomalies"
          icon={<TrendingUp className="w-4 h-4 text-amber-700" />}
        />
        <DataTile
          label="Integrity Check Failures"
          value={statsLoading ? '...' : stats?.integrity_failures ?? 0}
          subtitle="Cryptographic hash mismatches"
          icon={<Shield className="w-4 h-4 text-purple-700" />}
        />
      </div>

      {/* Security Telemetry Table */}
      <div className="gov-card">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-[var(--gov-border)] mb-4 gap-2">
          <h2 className="text-sm font-bold text-[var(--gov-navy-dark)] flex items-center gap-2">
            <Activity className="w-4 h-4 text-amber-600" />
            Security Event Feed
          </h2>

          <div className="flex items-center gap-2">
            <Filter className="w-3.5 h-3.5 text-slate-400" />
            <span className="text-xs text-slate-500 font-semibold">Severity:</span>
            <select
              className="form-input text-xs py-1 px-2"
              value={filterSeverity}
              onChange={(e) => setFilterSeverity(e.target.value)}
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>
        </div>

        {eventsLoading ? (
          <div className="py-12 text-center text-xs text-slate-400">Loading security events...</div>
        ) : filteredEvents.length === 0 ? (
          <EmptyState
            title="No security events detected"
            description="System telemetry indicates standard operational activity without anomalies."
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="gov-table">
              <thead>
                <tr>
                  <th>Event Type</th>
                  <th>Severity</th>
                  <th>Resource ID</th>
                  <th>Event Details / Context</th>
                  <th>Timestamp</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {filteredEvents.map((ev: any) => (
                  <tr key={ev.id}>
                    <td className="font-bold text-slate-800 text-xs">{ev.event_type}</td>
                    <td>
                      <StatusBadge status={ev.severity} type="incident" />
                    </td>
                    <td className="font-mono text-xs text-slate-600 truncate max-w-[140px]">
                      {ev.resource_id || 'SYSTEM'}
                    </td>
                    <td className="text-xs text-slate-600 max-w-[280px] truncate" title={JSON.stringify(ev.details)}>
                      {typeof ev.details === 'object' ? JSON.stringify(ev.details) : ev.details || '—'}
                    </td>
                    <td className="text-xs text-slate-500 font-mono">
                      {ev.created_at ? new Date(ev.created_at).toLocaleTimeString('en-IN') : '—'}
                    </td>
                    <td>
                      {ev.resolved ? (
                        <span className="badge-secure">Resolved</span>
                      ) : (
                        <span className="badge-warning">Active</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
