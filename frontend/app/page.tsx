"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  BarChart3,
  Database,
  GitBranch,
  Layers3,
  Network,
  ShieldAlert,
  Sparkles,
  Target
} from "lucide-react";
import { ChartsPanel } from "@/components/ChartsPanel";
import { ConfusionMatrix } from "@/components/ConfusionMatrix";
import { DashboardHeader } from "@/components/DashboardHeader";
import { IncidentsTable } from "@/components/IncidentsTable";
import { LogsTable } from "@/components/LogsTable";
import { MetricCard } from "@/components/MetricCard";
import { ModelMetricsPanel } from "@/components/ModelMetricsPanel";
import { PredictionsTable } from "@/components/PredictionsTable";
import { SectionCard } from "@/components/SectionCard";
import {
  getCharts,
  getIncidents,
  getLogs,
  getModelMetrics,
  getPredictions,
  getSummary
} from "@/lib/api";
import type {
  ChartsData,
  FinalIncident,
  MetricJson,
  ModelMetric,
  ProcessedLog,
  SequencePrediction,
  SummaryResponse
} from "@/types/logguard";

type LogsFilters = {
  severity: string;
  event_type: string;
  route: string;
};

function formatInteger(value?: number | null) {
  if (value === null || value === undefined) {
    return "n/a";
  }

  return new Intl.NumberFormat().format(value);
}

function asNumber(value: unknown) {
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }

  if (typeof value === "string") {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }

  return null;
}

function readMetric(metrics: MetricJson | null | undefined, paths: string[][]) {
  for (const path of paths) {
    let cursor: unknown = metrics;

    for (const key of path) {
      if (!cursor || typeof cursor !== "object" || !(key in cursor)) {
        cursor = undefined;
        break;
      }

      cursor = (cursor as Record<string, unknown>)[key];
    }

    const numeric = asNumber(cursor);

    if (numeric !== null) {
      return numeric;
    }
  }

  return null;
}

function formatPercent(value: number | null) {
  return value === null ? "n/a" : `${(value * 100).toFixed(1)}%`;
}

function keysFromMap(map?: Record<string, number>) {
  return Object.keys(map || {}).sort((a, b) => a.localeCompare(b));
}

function ErrorPanel({ message }: { message: string }) {
  return (
    <div className="rounded-lg border border-rose-400/30 bg-rose-400/10 p-5 text-rose-100">
      <div className="flex items-start gap-3">
        <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0" />
        <div>
          <p className="font-semibold">FastAPI backend not available.</p>
          <p className="mt-2 text-sm text-rose-100/85">
            Run: uvicorn backend.app.main:app --reload --port 8001
          </p>
          <p className="mt-2 text-sm text-rose-100/70">{message}</p>
        </div>
      </div>
    </div>
  );
}

function LoadingPanel() {
  return (
    <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
      {Array.from({ length: 8 }).map((_, index) => (
        <div
          key={index}
          className="h-[132px] animate-pulse rounded-lg border border-white/10 bg-white/[0.04]"
        />
      ))}
    </div>
  );
}

const evolution = [
  {
    title: "V1",
    label: "Rules + Isolation Forest",
    icon: ShieldAlert,
    tone: "text-signal-amber"
  },
  {
    title: "V2",
    label: "Sequence Transformer",
    icon: GitBranch,
    tone: "text-signal-violet"
  },
  {
    title: "V3",
    label: "PostgreSQL + Dashboard + API",
    icon: Database,
    tone: "text-signal-cyan"
  }
];

export default function DashboardPage() {
  const [summary, setSummary] = useState<SummaryResponse | null>(null);
  const [charts, setCharts] = useState<ChartsData | null>(null);
  const [logs, setLogs] = useState<ProcessedLog[]>([]);
  const [predictions, setPredictions] = useState<SequencePrediction[]>([]);
  const [incidents, setIncidents] = useState<FinalIncident[]>([]);
  const [modelMetrics, setModelMetrics] = useState<ModelMetric[]>([]);
  const [logsFilters, setLogsFilters] = useState<LogsFilters>({
    severity: "",
    event_type: "",
    route: ""
  });
  const [onlyPredictionErrors, setOnlyPredictionErrors] = useState(false);
  const [loading, setLoading] = useState(true);
  const [logsLoading, setLogsLoading] = useState(false);
  const [predictionsLoading, setPredictionsLoading] = useState(false);
  const [incidentsLoading, setIncidentsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);

  const loadDashboard = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const [
        summaryData,
        chartsData,
        logsData,
        predictionsData,
        incidentsData,
        modelMetricsData
      ] = await Promise.all([
        getSummary(),
        getCharts(),
        getLogs({ limit: 30 }),
        getPredictions({ limit: 20 }),
        getIncidents({ limit: 20 }),
        getModelMetrics()
      ]);

      setSummary(summaryData);
      setCharts(chartsData);
      setLogs(logsData);
      setPredictions(predictionsData);
      setIncidents(incidentsData);
      setModelMetrics(modelMetricsData);
      setLastUpdated(new Date());
    } catch (requestError) {
      setError(
        requestError instanceof Error ? requestError.message : "Unknown request error"
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void loadDashboard();
  }, [loadDashboard]);

  useEffect(() => {
    if (loading) {
      return;
    }

    let cancelled = false;
    setLogsLoading(true);

    getLogs({ limit: 50, ...logsFilters })
      .then((data) => {
        if (!cancelled) {
          setLogs(data);
        }
      })
      .catch((requestError) => {
        if (!cancelled) {
          setError(
            requestError instanceof Error ? requestError.message : "Unknown logs error"
          );
        }
      })
      .finally(() => {
        if (!cancelled) {
          setLogsLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [logsFilters, loading]);

  useEffect(() => {
    if (loading) {
      return;
    }

    let cancelled = false;
    setPredictionsLoading(true);

    getPredictions({
      limit: onlyPredictionErrors ? 50 : 20,
      only_errors: onlyPredictionErrors
    })
      .then((data) => {
        if (!cancelled) {
          setPredictions(data);
        }
      })
      .catch((requestError) => {
        if (!cancelled) {
          setError(
            requestError instanceof Error
              ? requestError.message
              : "Unknown predictions error"
          );
        }
      })
      .finally(() => {
        if (!cancelled) {
          setPredictionsLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [onlyPredictionErrors, loading]);

  const filterOptions = useMemo(
    () => ({
      severities: keysFromMap(charts?.logs_by_severity),
      eventTypes: keysFromMap(charts?.logs_by_event_type),
      routes: keysFromMap(charts?.logs_by_route)
    }),
    [charts]
  );

  const transformerMetrics = summary?.transformer_metrics;
  const accuracy = readMetric(transformerMetrics, [
    ["accuracy"],
    ["test_accuracy"],
    ["classification_report", "accuracy"]
  ]);
  const f1Anomaly = readMetric(transformerMetrics, [
    ["f1_anomaly"],
    ["classification_report", "anomaly", "f1-score"]
  ]);
  const recallAnomaly = readMetric(transformerMetrics, [
    ["recall_anomaly"],
    ["classification_report", "anomaly", "recall"]
  ]);

  return (
    <main className="dashboard-shell">
      <div className="mx-auto flex w-full max-w-[1680px] flex-col gap-5 px-4 py-5 sm:px-6 lg:px-8">
        <DashboardHeader
          apiOnline={Boolean(summary)}
          isRefreshing={loading}
          lastUpdated={lastUpdated}
          onRefresh={loadDashboard}
        />

        {error ? <ErrorPanel message={error} /> : null}

        {loading && !summary ? (
          <LoadingPanel />
        ) : summary ? (
          <>
            <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
              <MetricCard
                title="Processed Logs"
                value={formatInteger(summary?.totals.processed_logs)}
                caption="Raw events normalized"
                icon={Activity}
                tone="cyan"
              />
              <MetricCard
                title="Log Sequences"
                value={formatInteger(summary?.totals.log_sequences)}
                caption="Behavior windows"
                icon={Network}
                tone="violet"
              />
              <MetricCard
                title="Predictions"
                value={formatInteger(summary?.totals.sequence_predictions)}
                caption="Transformer outputs"
                icon={Target}
                tone="emerald"
              />
              <MetricCard
                title="Final Incidents"
                value={formatInteger(summary?.totals.final_incidents)}
                caption="Alert manager queue"
                icon={ShieldAlert}
                tone="rose"
              />
              <MetricCard
                title="Model Metrics"
                value={formatInteger(summary?.totals.model_metrics)}
                caption="Stored evaluations"
                icon={BarChart3}
                tone="amber"
              />
              <MetricCard
                title="Transformer Accuracy"
                value={formatPercent(accuracy)}
                caption="Latest metric snapshot"
                icon={Sparkles}
                tone="emerald"
              />
              <MetricCard
                title="F1 Anomaly"
                value={formatPercent(f1Anomaly)}
                caption="Anomaly class quality"
                icon={AlertTriangle}
                tone="violet"
              />
              <MetricCard
                title="Recall Anomaly"
                value={formatPercent(recallAnomaly)}
                caption="Missed anomaly control"
                icon={Layers3}
                tone="cyan"
              />
            </div>

            <SectionCard title="System Evolution" eyebrow="Architecture maturity">
              <div className="grid gap-3 lg:grid-cols-3">
                {evolution.map((item, index) => {
                  const Icon = item.icon;

                  return (
                    <div
                      key={item.title}
                      className="flex min-h-[96px] items-center gap-4 rounded-md border border-white/10 bg-white/[0.03] px-4 py-3"
                    >
                      <span
                        className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-md border border-white/10 bg-white/5 ${item.tone}`}
                      >
                        <Icon className="h-5 w-5" />
                      </span>
                      <div className="min-w-0">
                        <p className="text-sm font-semibold text-slate-50">{item.title}</p>
                        <p className="mt-1 text-sm text-slate-400">{item.label}</p>
                      </div>
                      {index < evolution.length - 1 ? (
                        <div className="ml-auto hidden h-px w-16 bg-white/15 lg:block" />
                      ) : null}
                    </div>
                  );
                })}
              </div>
            </SectionCard>

            <ChartsPanel charts={charts} />

            <div className="grid gap-4 xl:grid-cols-[520px_1fr]">
              <ConfusionMatrix data={summary?.confusion_matrix_from_db} />
              <PredictionsTable
                predictions={predictions}
                onlyErrors={onlyPredictionErrors}
                loading={predictionsLoading}
                onToggleErrors={() => setOnlyPredictionErrors((value) => !value)}
              />
            </div>

            <LogsTable
              logs={logs}
              filters={logsFilters}
              filterOptions={filterOptions}
              loading={logsLoading}
              onFiltersChange={setLogsFilters}
            />

            <IncidentsTable incidents={incidents} loading={incidentsLoading} />

            <ModelMetricsPanel metrics={modelMetrics} />
          </>
        ) : null}
      </div>
    </main>
  );
}
