"use client";

import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from "recharts";
import { SectionCard } from "@/components/SectionCard";
import type { ChartsData, CountMap } from "@/types/logguard";

interface ChartsPanelProps {
  charts?: ChartsData | null;
}

const palette = ["#38bdf8", "#34d399", "#fbbf24", "#fb7185", "#a78bfa", "#60a5fa"];

function toChartData(map?: CountMap) {
  return Object.entries(map || {}).map(([name, value]) => ({ name, value }));
}

function EmptyState() {
  return (
    <div className="flex h-[260px] items-center justify-center rounded-md border border-dashed border-white/10 text-sm text-slate-400">
      No data available
    </div>
  );
}

function ChartTooltip({
  active,
  payload,
  label
}: {
  active?: boolean;
  payload?: Array<{ value?: number; name?: string; payload?: { name?: string } }>;
  label?: string;
}) {
  if (!active || !payload?.length) {
    return null;
  }

  const item = payload[0];

  return (
    <div className="rounded-md border border-white/10 bg-surface-950 px-3 py-2 text-sm shadow-soft-panel">
      <p className="font-medium text-slate-100">{label || item.payload?.name || item.name}</p>
      <p className="mt-1 text-slate-400">{item.value ?? 0} events</p>
    </div>
  );
}

function VerticalBarChart({ data }: { data: Array<{ name: string; value: number }> }) {
  if (!data.length) {
    return <EmptyState />;
  }

  return (
    <div className="h-[260px]">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
          <CartesianGrid stroke="rgba(148, 163, 184, 0.14)" vertical={false} />
          <XAxis dataKey="name" stroke="#94a3b8" tick={{ fontSize: 12 }} />
          <YAxis stroke="#94a3b8" tick={{ fontSize: 12 }} allowDecimals={false} />
          <Tooltip content={<ChartTooltip />} cursor={{ fill: "rgba(56,189,248,0.08)" }} />
          <Bar dataKey="value" radius={[4, 4, 0, 0]}>
            {data.map((item, index) => (
              <Cell key={item.name} fill={palette[index % palette.length]} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

function HorizontalBarChart({ data }: { data: Array<{ name: string; value: number }> }) {
  const normalized = data.slice(0, 8);

  if (!normalized.length) {
    return <EmptyState />;
  }

  return (
    <div className="h-[260px]">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart
          data={normalized}
          layout="vertical"
          margin={{ top: 8, right: 10, left: 8, bottom: 0 }}
        >
          <CartesianGrid stroke="rgba(148, 163, 184, 0.14)" horizontal={false} />
          <XAxis type="number" stroke="#94a3b8" tick={{ fontSize: 12 }} allowDecimals={false} />
          <YAxis
            dataKey="name"
            type="category"
            stroke="#94a3b8"
            tick={{ fontSize: 12 }}
            width={110}
          />
          <Tooltip content={<ChartTooltip />} cursor={{ fill: "rgba(56,189,248,0.08)" }} />
          <Bar dataKey="value" radius={[0, 4, 4, 0]} fill="#38bdf8" />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

function DonutChart({ data }: { data: Array<{ name: string; value: number }> }) {
  if (!data.length) {
    return <EmptyState />;
  }

  return (
    <div className="h-[260px]">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={data}
            dataKey="value"
            nameKey="name"
            innerRadius={62}
            outerRadius={94}
            paddingAngle={2}
          >
            {data.map((item, index) => (
              <Cell key={item.name} fill={palette[index % palette.length]} />
            ))}
          </Pie>
          <Tooltip content={<ChartTooltip />} />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}

export function ChartsPanel({ charts }: ChartsPanelProps) {
  const chartBlocks = [
    {
      title: "Logs by Severity",
      eyebrow: "Distribution",
      data: toChartData(charts?.logs_by_severity),
      type: "donut"
    },
    {
      title: "Event Types",
      eyebrow: "Signal mix",
      data: toChartData(charts?.logs_by_event_type),
      type: "bar"
    },
    {
      title: "Sequence Labels",
      eyebrow: "Normal vs anomaly",
      data: toChartData(charts?.sequences_by_label),
      type: "donut"
    },
    {
      title: "Predictions by Label",
      eyebrow: "Transformer output",
      data: toChartData(charts?.predictions_by_label),
      type: "bar"
    },
    {
      title: "Top Routes",
      eyebrow: "Traffic concentration",
      data: toChartData(charts?.logs_by_route),
      type: "horizontal"
    },
    {
      title: "Incidents by Severity",
      eyebrow: "Response queue",
      data: toChartData(charts?.incidents_by_severity),
      type: "donut"
    }
  ];

  return (
    <div className="grid gap-4 xl:grid-cols-3">
      {chartBlocks.map((chart) => (
        <SectionCard key={chart.title} title={chart.title} eyebrow={chart.eyebrow}>
          {chart.type === "donut" ? (
            <DonutChart data={chart.data} />
          ) : chart.type === "horizontal" ? (
            <HorizontalBarChart data={chart.data} />
          ) : (
            <VerticalBarChart data={chart.data} />
          )}
        </SectionCard>
      ))}
    </div>
  );
}
