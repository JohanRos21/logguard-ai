import { Cpu, Database, ShieldAlert, Workflow } from "lucide-react";
import { SectionCard } from "@/components/SectionCard";
import type { MetricJson, ModelMetric } from "@/types/logguard";

interface ModelMetricsPanelProps {
  metrics: ModelMetric[];
}

const modelIcons = {
  "Isolation Forest": ShieldAlert,
  "Alert Manager": Workflow,
  "Sequence Dataset": Database,
  LogSequenceTransformer: Cpu
};

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

function valueByPath(metrics: MetricJson | null, paths: string[][]) {
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

function formatMetric(value: number | null, percent = true) {
  if (value === null) {
    return "n/a";
  }

  if (percent) {
    return `${(value * 100).toFixed(1)}%`;
  }

  return value.toFixed(4);
}

function summarizeMetrics(metric: ModelMetric) {
  const data = metric.metrics_json;
  const classes = data?.classes;

  if (metric.model_name === "LogSequenceTransformer") {
    return [
      ["accuracy", formatMetric(valueByPath(data, [["accuracy"], ["test_accuracy"]]))],
      [
        "precision_anomaly",
        formatMetric(
          valueByPath(data, [
            ["precision_anomaly"],
            ["classification_report", "anomaly", "precision"]
          ])
        )
      ],
      [
        "recall_anomaly",
        formatMetric(
          valueByPath(data, [
            ["recall_anomaly"],
            ["classification_report", "anomaly", "recall"]
          ])
        )
      ],
      [
        "f1_anomaly",
        formatMetric(
          valueByPath(data, [
            ["f1_anomaly"],
            ["classification_report", "anomaly", "f1-score"]
          ])
        )
      ],
      ["loss", formatMetric(valueByPath(data, [["loss"], ["test_loss"]]), false)],
      [
        "classes",
        Array.isArray(classes) ? classes.join(", ") : "normal, anomaly"
      ]
    ];
  }

  return Object.entries(data || {})
    .slice(0, 6)
    .map(([key, value]) => [
      key,
      typeof value === "object" ? JSON.stringify(value) : String(value)
    ]);
}

function latestByModel(metrics: ModelMetric[]) {
  const byModel = new Map<string, ModelMetric>();

  for (const metric of metrics) {
    const name = metric.model_name || "Unknown";

    if (!byModel.has(name)) {
      byModel.set(name, metric);
    }
  }

  return byModel;
}

export function ModelMetricsPanel({ metrics }: ModelMetricsPanelProps) {
  const byModel = latestByModel(metrics);
  const modelNames = [
    "Isolation Forest",
    "Alert Manager",
    "Sequence Dataset",
    "LogSequenceTransformer"
  ];

  return (
    <div className="grid gap-4 xl:grid-cols-4">
      {modelNames.map((modelName) => {
        const metric = byModel.get(modelName);
        const Icon = modelIcons[modelName as keyof typeof modelIcons] || Cpu;

        return (
          <SectionCard key={modelName} title={modelName} eyebrow="Model metrics">
            {metric ? (
              <div className="space-y-3">
                <div className="flex items-center gap-3 text-sm text-slate-400">
                  <span className="flex h-9 w-9 items-center justify-center rounded-md border border-white/10 bg-white/5 text-signal-cyan">
                    <Icon className="h-4 w-4" />
                  </span>
                  <span className="truncate">{metric.metric_source || metric.version || "v3"}</span>
                </div>
                <dl className="space-y-2">
                  {summarizeMetrics(metric).map(([key, value]) => (
                    <div key={key} className="flex items-center justify-between gap-3">
                      <dt className="truncate text-sm text-slate-500">{key}</dt>
                      <dd className="max-w-[160px] truncate text-right text-sm font-medium text-slate-200">
                        {value}
                      </dd>
                    </div>
                  ))}
                </dl>
              </div>
            ) : (
              <p className="text-sm text-slate-400">No data available</p>
            )}
          </SectionCard>
        );
      })}
    </div>
  );
}
