import { CheckCircle2, CircleAlert, CircleHelp, XCircle } from "lucide-react";

type BadgeTone =
  | "normal"
  | "warning"
  | "critical"
  | "anomaly"
  | "success"
  | "error"
  | "neutral";

interface StatusBadgeProps {
  label: string;
  tone?: BadgeTone;
}

const toneClass: Record<BadgeTone, string> = {
  normal: "border-emerald-400/30 bg-emerald-400/10 text-emerald-200",
  success: "border-emerald-400/30 bg-emerald-400/10 text-emerald-200",
  warning: "border-amber-400/35 bg-amber-400/10 text-amber-200",
  critical: "border-rose-400/35 bg-rose-400/10 text-rose-200",
  anomaly: "border-violet-400/35 bg-violet-400/10 text-violet-200",
  error: "border-rose-400/35 bg-rose-400/10 text-rose-200",
  neutral: "border-slate-500/35 bg-white/5 text-slate-200"
};

function Icon({ tone }: { tone: BadgeTone }) {
  if (tone === "success" || tone === "normal") {
    return <CheckCircle2 className="h-3.5 w-3.5" />;
  }

  if (tone === "critical" || tone === "error") {
    return <XCircle className="h-3.5 w-3.5" />;
  }

  if (tone === "warning" || tone === "anomaly") {
    return <CircleAlert className="h-3.5 w-3.5" />;
  }

  return <CircleHelp className="h-3.5 w-3.5" />;
}

export function StatusBadge({ label, tone = "neutral" }: StatusBadgeProps) {
  return (
    <span
      className={`inline-flex h-7 items-center gap-1.5 rounded-md border px-2.5 text-xs font-medium ${toneClass[tone]}`}
    >
      <Icon tone={tone} />
      <span className="truncate">{label}</span>
    </span>
  );
}

export function toneForValue(value?: string | null): BadgeTone {
  const normalized = String(value || "").toLowerCase();

  if (["normal", "ok", "online", "correct"].includes(normalized)) {
    return "success";
  }

  if (["warning", "medium"].includes(normalized)) {
    return "warning";
  }

  if (["critical", "high", "error", "failed"].includes(normalized)) {
    return "critical";
  }

  if (["anomaly", "suspicious"].includes(normalized)) {
    return "anomaly";
  }

  return "neutral";
}
