import { Loader2 } from "lucide-react";
import { SectionCard } from "@/components/SectionCard";
import { StatusBadge, toneForValue } from "@/components/StatusBadge";
import type { FinalIncident } from "@/types/logguard";

interface IncidentsTableProps {
  incidents: FinalIncident[];
  loading: boolean;
}

export function IncidentsTable({ incidents, loading }: IncidentsTableProps) {
  return (
    <SectionCard title="Incidents" eyebrow="Final alert manager">
      {loading ? (
        <div className="flex h-44 items-center justify-center text-sm text-slate-400">
          <Loader2 className="mr-2 h-4 w-4 animate-spin" />
          Loading incidents
        </div>
      ) : incidents.length === 0 ? (
        <p className="text-sm text-slate-400">No incidents available</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="stable-table min-w-[1060px] text-left text-sm">
            <thead className="text-xs uppercase tracking-[0.12em] text-slate-500">
              <tr className="border-b border-white/10">
                <th className="w-36 px-3 py-3">Incident</th>
                <th className="w-28 px-3 py-3">Severity</th>
                <th className="w-44 px-3 py-3">Type</th>
                <th className="px-3 py-3">Route</th>
                <th className="w-32 px-3 py-3">IP</th>
                <th className="w-20 px-3 py-3">Events</th>
                <th className="w-20 px-3 py-3">Risk</th>
                <th className="px-3 py-3">Recommendation</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/10 text-slate-300">
              {incidents.map((incident) => (
                <tr key={incident.id} className="hover:bg-white/[0.03]">
                  <td className="px-3 py-3 font-medium text-slate-100">
                    {incident.incident_id || "n/a"}
                  </td>
                  <td className="px-3 py-3">
                    <StatusBadge
                      label={incident.severity || "unknown"}
                      tone={toneForValue(incident.severity)}
                    />
                  </td>
                  <td className="px-3 py-3">{incident.incident_type || "n/a"}</td>
                  <td className="px-3 py-3">{incident.route || "n/a"}</td>
                  <td className="px-3 py-3">{incident.ip || "n/a"}</td>
                  <td className="px-3 py-3 tabular-nums">
                    {incident.events_count ?? "n/a"}
                  </td>
                  <td className="px-3 py-3 tabular-nums">
                    {incident.max_risk_score ?? "n/a"}
                  </td>
                  <td className="px-3 py-3">{incident.recommendation || "n/a"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </SectionCard>
  );
}
