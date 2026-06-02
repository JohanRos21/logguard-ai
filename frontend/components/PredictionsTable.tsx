import { AlertTriangle, CheckCircle2, Filter, Loader2 } from "lucide-react";
import { SectionCard } from "@/components/SectionCard";
import { StatusBadge } from "@/components/StatusBadge";
import type { SequencePrediction } from "@/types/logguard";

interface PredictionsTableProps {
  predictions: SequencePrediction[];
  onlyErrors: boolean;
  loading: boolean;
  onToggleErrors: () => void;
}

function formatProbability(value: number | null) {
  if (value === null || value === undefined) {
    return "n/a";
  }

  return `${(value * 100).toFixed(1)}%`;
}

function isCorrect(prediction: SequencePrediction) {
  return prediction.label === prediction.predicted_label;
}

export function PredictionsTable({
  predictions,
  onlyErrors,
  loading,
  onToggleErrors
}: PredictionsTableProps) {
  return (
    <SectionCard
      title="Recent Predictions"
      eyebrow="Sequence transformer"
      action={
        <button
          type="button"
          onClick={onToggleErrors}
          title="Filter prediction errors"
          className={`inline-flex h-9 items-center gap-2 rounded-md border px-3 text-sm font-medium transition ${
            onlyErrors
              ? "border-rose-400/35 bg-rose-400/10 text-rose-100"
              : "border-white/10 bg-white/5 text-slate-200 hover:border-signal-cyan/35"
          }`}
        >
          {onlyErrors ? <AlertTriangle className="h-4 w-4" /> : <Filter className="h-4 w-4" />}
          Ver solo errores
        </button>
      }
    >
      {loading ? (
        <div className="flex h-44 items-center justify-center text-sm text-slate-400">
          <Loader2 className="mr-2 h-4 w-4 animate-spin" />
          Loading predictions
        </div>
      ) : predictions.length === 0 ? (
        <p className="text-sm text-slate-400">No data available</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="stable-table min-w-[980px] text-left text-sm">
            <thead className="text-xs uppercase tracking-[0.12em] text-slate-500">
              <tr className="border-b border-white/10">
                <th className="w-32 px-3 py-3">Sequence</th>
                <th className="w-36 px-3 py-3">Entity</th>
                <th className="w-24 px-3 py-3">Label</th>
                <th className="w-28 px-3 py-3">Predicted</th>
                <th className="w-28 px-3 py-3">Anomaly</th>
                <th className="w-24 px-3 py-3">Risk</th>
                <th className="px-3 py-3">Main scenarios</th>
                <th className="w-28 px-3 py-3">Result</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/10 text-slate-300">
              {predictions.map((prediction) => {
                const correct = isCorrect(prediction);

                return (
                  <tr key={prediction.id} className="hover:bg-white/[0.03]">
                    <td className="px-3 py-3 font-medium text-slate-100">
                      {prediction.sequence_id || "n/a"}
                    </td>
                    <td className="px-3 py-3">{prediction.entity_id || "n/a"}</td>
                    <td className="px-3 py-3">{prediction.label || "n/a"}</td>
                    <td className="px-3 py-3">{prediction.predicted_label || "n/a"}</td>
                    <td className="px-3 py-3 tabular-nums">
                      {formatProbability(prediction.anomaly_probability)}
                    </td>
                    <td className="px-3 py-3 tabular-nums">
                      {prediction.max_risk_score ?? "n/a"}
                    </td>
                    <td className="px-3 py-3">{prediction.main_scenarios || "n/a"}</td>
                    <td className="px-3 py-3">
                      <StatusBadge
                        label={correct ? "Correct" : "Error"}
                        tone={correct ? "success" : "error"}
                      />
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </SectionCard>
  );
}
