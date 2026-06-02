import { Loader2, RotateCcw } from "lucide-react";
import { SectionCard } from "@/components/SectionCard";
import { StatusBadge, toneForValue } from "@/components/StatusBadge";
import type { ProcessedLog } from "@/types/logguard";

interface LogsFilters {
  severity: string;
  event_type: string;
  route: string;
}

interface LogsTableProps {
  logs: ProcessedLog[];
  filters: LogsFilters;
  filterOptions: {
    severities: string[];
    eventTypes: string[];
    routes: string[];
  };
  loading: boolean;
  onFiltersChange: (filters: LogsFilters) => void;
}

function formatDate(value?: string | null) {
  if (!value) {
    return "n/a";
  }

  return new Date(value).toLocaleString();
}

function SelectFilter({
  label,
  value,
  options,
  onChange
}: {
  label: string;
  value: string;
  options: string[];
  onChange: (value: string) => void;
}) {
  return (
    <label className="flex min-w-[160px] items-center gap-2 text-sm text-slate-400">
      <span className="shrink-0">{label}</span>
      <select
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="h-9 w-full rounded-md border border-white/10 bg-surface-950 px-2 text-sm text-slate-200 outline-none transition focus:border-signal-cyan/60"
      >
        <option value="">All</option>
        {options.map((option) => (
          <option key={option} value={option}>
            {option}
          </option>
        ))}
      </select>
    </label>
  );
}

export function LogsTable({
  logs,
  filters,
  filterOptions,
  loading,
  onFiltersChange
}: LogsTableProps) {
  const hasFilters = Boolean(filters.severity || filters.event_type || filters.route);

  return (
    <SectionCard
      title="Recent Logs"
      eyebrow="PostgreSQL events"
      action={
        <div className="flex flex-wrap items-center justify-end gap-2">
          <SelectFilter
            label="Severity"
            value={filters.severity}
            options={filterOptions.severities}
            onChange={(severity) => onFiltersChange({ ...filters, severity })}
          />
          <SelectFilter
            label="Event"
            value={filters.event_type}
            options={filterOptions.eventTypes}
            onChange={(event_type) => onFiltersChange({ ...filters, event_type })}
          />
          <SelectFilter
            label="Route"
            value={filters.route}
            options={filterOptions.routes}
            onChange={(route) => onFiltersChange({ ...filters, route })}
          />
          <button
            type="button"
            onClick={() => onFiltersChange({ severity: "", event_type: "", route: "" })}
            disabled={!hasFilters}
            title="Reset log filters"
            aria-label="Reset log filters"
            className="inline-flex h-9 w-9 items-center justify-center rounded-md border border-white/10 bg-white/5 text-slate-300 transition hover:border-signal-cyan/35 disabled:cursor-not-allowed disabled:opacity-45"
          >
            <RotateCcw className="h-4 w-4" />
          </button>
        </div>
      }
    >
      {loading ? (
        <div className="flex h-52 items-center justify-center text-sm text-slate-400">
          <Loader2 className="mr-2 h-4 w-4 animate-spin" />
          Loading logs
        </div>
      ) : logs.length === 0 ? (
        <p className="text-sm text-slate-400">No data available</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="stable-table min-w-[1180px] text-left text-sm">
            <thead className="text-xs uppercase tracking-[0.12em] text-slate-500">
              <tr className="border-b border-white/10">
                <th className="w-44 px-3 py-3">Timestamp</th>
                <th className="w-32 px-3 py-3">IP</th>
                <th className="w-32 px-3 py-3">User</th>
                <th className="w-20 px-3 py-3">Method</th>
                <th className="px-3 py-3">Route</th>
                <th className="w-24 px-3 py-3">Status</th>
                <th className="w-36 px-3 py-3">Event</th>
                <th className="w-28 px-3 py-3">Severity</th>
                <th className="w-24 px-3 py-3">Latency</th>
                <th className="w-20 px-3 py-3">Risk</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/10 text-slate-300">
              {logs.map((log) => (
                <tr key={log.id} className="hover:bg-white/[0.03]">
                  <td className="px-3 py-3">{formatDate(log.timestamp)}</td>
                  <td className="px-3 py-3">{log.ip || "n/a"}</td>
                  <td className="px-3 py-3">{log.user_id || "n/a"}</td>
                  <td className="px-3 py-3 font-medium text-slate-100">
                    {log.method || "n/a"}
                  </td>
                  <td className="px-3 py-3">{log.route || "n/a"}</td>
                  <td className="px-3 py-3 tabular-nums">
                    {log.status_code ?? "n/a"}
                  </td>
                  <td className="px-3 py-3">{log.event_type || "n/a"}</td>
                  <td className="px-3 py-3">
                    <StatusBadge
                      label={log.severity || "unknown"}
                      tone={toneForValue(log.severity)}
                    />
                  </td>
                  <td className="px-3 py-3 tabular-nums">
                    {log.response_time_ms !== null && log.response_time_ms !== undefined
                      ? `${Math.round(log.response_time_ms)} ms`
                      : "n/a"}
                  </td>
                  <td className="px-3 py-3 tabular-nums">{log.risk_score ?? "n/a"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </SectionCard>
  );
}
