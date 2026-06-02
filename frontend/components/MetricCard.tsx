import type { LucideIcon } from "lucide-react";

interface MetricCardProps {
  title: string;
  value: string | number;
  caption?: string;
  icon: LucideIcon;
  tone?: "cyan" | "emerald" | "amber" | "rose" | "violet";
}

const toneClass = {
  cyan: "border-signal-cyan/25 bg-signal-cyan/10 text-signal-cyan",
  emerald: "border-signal-emerald/25 bg-signal-emerald/10 text-signal-emerald",
  amber: "border-signal-amber/25 bg-signal-amber/10 text-signal-amber",
  rose: "border-signal-rose/25 bg-signal-rose/10 text-signal-rose",
  violet: "border-signal-violet/25 bg-signal-violet/10 text-signal-violet"
};

export function MetricCard({
  title,
  value,
  caption,
  icon: Icon,
  tone = "cyan"
}: MetricCardProps) {
  return (
    <article className="rounded-lg border border-white/10 bg-surface-900/82 p-4 shadow-soft-panel backdrop-blur">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="truncate text-xs font-medium uppercase tracking-[0.14em] text-slate-400">
            {title}
          </p>
          <p className="mt-3 text-2xl font-semibold tabular-nums text-slate-50">
            {value}
          </p>
        </div>
        <span
          className={`inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-md border ${toneClass[tone]}`}
        >
          <Icon className="h-5 w-5" />
        </span>
      </div>
      {caption ? <p className="mt-3 truncate text-sm text-slate-400">{caption}</p> : null}
    </article>
  );
}
