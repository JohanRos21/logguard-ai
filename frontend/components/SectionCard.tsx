import type { ReactNode } from "react";

interface SectionCardProps {
  title: string;
  eyebrow?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}

export function SectionCard({
  title,
  eyebrow,
  action,
  children,
  className = ""
}: SectionCardProps) {
  return (
    <section
      className={`rounded-lg border border-white/10 bg-surface-900/82 shadow-soft-panel backdrop-blur ${className}`}
    >
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/10 px-5 py-4">
        <div>
          {eyebrow ? (
            <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-signal-cyan">
              {eyebrow}
            </p>
          ) : null}
          <h2 className="mt-1 text-base font-semibold text-slate-50">{title}</h2>
        </div>
        {action}
      </div>
      <div className="p-5">{children}</div>
    </section>
  );
}
