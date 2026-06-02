import { Activity, Database, RefreshCw, ShieldCheck } from "lucide-react";
import { StatusBadge } from "@/components/StatusBadge";

interface DashboardHeaderProps {
  apiOnline: boolean;
  isRefreshing: boolean;
  lastUpdated?: Date | null;
  onRefresh: () => void;
}

export function DashboardHeader({
  apiOnline,
  isRefreshing,
  lastUpdated,
  onRefresh
}: DashboardHeaderProps) {
  return (
    <header className="rounded-lg border border-white/10 bg-surface-900/88 px-5 py-5 shadow-soft-panel backdrop-blur">
      <div className="flex flex-col gap-5 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex min-w-0 items-start gap-4">
          <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-md border border-signal-cyan/25 bg-signal-cyan/10 text-signal-cyan">
            <ShieldCheck className="h-6 w-6" />
          </div>
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-3">
              <h1 className="text-2xl font-semibold tracking-normal text-slate-50">
                LogGuard AI V3
              </h1>
              <StatusBadge label="V3 Active" tone="anomaly" />
            </div>
            <p className="mt-2 max-w-3xl text-sm text-slate-400">
              PostgreSQL + FastAPI + Transformer Sequence Monitoring
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <StatusBadge
            label={apiOnline ? "API Online" : "API Offline"}
            tone={apiOnline ? "success" : "error"}
          />
          <StatusBadge label="PostgreSQL Connected" tone="success" />
          <button
            type="button"
            onClick={onRefresh}
            disabled={isRefreshing}
            title="Refresh dashboard"
            aria-label="Refresh dashboard"
            className="inline-flex h-9 items-center gap-2 rounded-md border border-white/10 bg-white/5 px-3 text-sm font-medium text-slate-200 transition hover:border-signal-cyan/35 hover:bg-signal-cyan/10 disabled:cursor-not-allowed disabled:opacity-55"
          >
            <RefreshCw className={`h-4 w-4 ${isRefreshing ? "animate-spin" : ""}`} />
            Refresh
          </button>
        </div>
      </div>

      <div className="mt-5 grid gap-3 sm:grid-cols-3">
        <div className="flex items-center gap-3 rounded-md border border-white/10 bg-white/[0.03] px-3 py-2">
          <Activity className="h-4 w-4 text-signal-emerald" />
          <span className="text-sm text-slate-300">Monitoring pipeline active</span>
        </div>
        <div className="flex items-center gap-3 rounded-md border border-white/10 bg-white/[0.03] px-3 py-2">
          <Database className="h-4 w-4 text-signal-cyan" />
          <span className="text-sm text-slate-300">PostgreSQL storage layer</span>
        </div>
        <div className="flex items-center gap-3 rounded-md border border-white/10 bg-white/[0.03] px-3 py-2">
          <ShieldCheck className="h-4 w-4 text-signal-violet" />
          <span className="text-sm text-slate-300">
            {lastUpdated ? `Updated ${lastUpdated.toLocaleTimeString()}` : "Awaiting data"}
          </span>
        </div>
      </div>
    </header>
  );
}
