import type { ConfusionMatrixData } from "@/types/logguard";
import { SectionCard } from "@/components/SectionCard";

interface ConfusionMatrixProps {
  data?: ConfusionMatrixData | null;
}

function Cell({
  label,
  value,
  type
}: {
  label: string;
  value: number;
  type: "correct" | "error";
}) {
  const className =
    type === "correct"
      ? "border-emerald-400/25 bg-emerald-400/10 text-emerald-100"
      : "border-rose-400/25 bg-rose-400/10 text-rose-100";

  return (
    <div className={`min-h-[104px] rounded-md border p-4 ${className}`}>
      <p className="text-xs font-medium uppercase tracking-[0.14em] opacity-75">
        {label}
      </p>
      <p className="mt-4 text-3xl font-semibold tabular-nums">{value}</p>
    </div>
  );
}

export function ConfusionMatrix({ data }: ConfusionMatrixProps) {
  const matrix = data || {
    true_normal_pred_normal: 0,
    true_normal_pred_anomaly: 0,
    true_anomaly_pred_normal: 0,
    true_anomaly_pred_anomaly: 0
  };

  const total =
    matrix.true_normal_pred_normal +
    matrix.true_normal_pred_anomaly +
    matrix.true_anomaly_pred_normal +
    matrix.true_anomaly_pred_anomaly;

  const correct =
    matrix.true_normal_pred_normal + matrix.true_anomaly_pred_anomaly;
  const accuracy = total > 0 ? `${((correct / total) * 100).toFixed(1)}%` : "n/a";

  return (
    <SectionCard
      title="Confusion Matrix"
      eyebrow="Transformer validation"
      action={
        <div className="text-right text-sm text-slate-400">
          <span className="font-medium text-slate-200">{accuracy}</span> accuracy
        </div>
      }
    >
      {total === 0 ? (
        <p className="text-sm text-slate-400">No data available</p>
      ) : (
        <div className="space-y-3">
          <div className="grid grid-cols-[120px_1fr_1fr] gap-3 text-sm">
            <div />
            <div className="rounded-md border border-white/10 bg-white/[0.03] px-3 py-2 text-center font-medium text-slate-300">
              Pred Normal
            </div>
            <div className="rounded-md border border-white/10 bg-white/[0.03] px-3 py-2 text-center font-medium text-slate-300">
              Pred Anomaly
            </div>
            <div className="flex items-center rounded-md border border-white/10 bg-white/[0.03] px-3 py-2 font-medium text-slate-300">
              Real Normal
            </div>
            <Cell
              label="True normal"
              value={matrix.true_normal_pred_normal}
              type="correct"
            />
            <Cell
              label="False anomaly"
              value={matrix.true_normal_pred_anomaly}
              type="error"
            />
            <div className="flex items-center rounded-md border border-white/10 bg-white/[0.03] px-3 py-2 font-medium text-slate-300">
              Real Anomaly
            </div>
            <Cell
              label="False normal"
              value={matrix.true_anomaly_pred_normal}
              type="error"
            />
            <Cell
              label="True anomaly"
              value={matrix.true_anomaly_pred_anomaly}
              type="correct"
            />
          </div>
        </div>
      )}
    </SectionCard>
  );
}
