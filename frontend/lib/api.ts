import type {
  ApiDataResponse,
  ApiListResponse,
  ChartsData,
  FinalIncident,
  IncidentsParams,
  LogsParams,
  ModelMetric,
  PredictionsParams,
  ProcessedLog,
  SequencePrediction,
  SummaryResponse
} from "@/types/logguard";

export const API_BASE_URL =
  process.env.NEXT_PUBLIC_API_BASE_URL || "http://127.0.0.1:8001";

const PROXY_BASE_URL = "/api/backend";
const API_MODE = process.env.NEXT_PUBLIC_API_MODE;
const USE_PROXY =
  API_MODE === "proxy" || process.env.NEXT_PUBLIC_DIRECT_API === "false";

function getBaseUrl() {
  if (typeof window !== "undefined" && USE_PROXY) {
    return PROXY_BASE_URL;
  }

  return API_BASE_URL;
}

function appendParams(url: URL, params?: Record<string, string | number | boolean | undefined>) {
  Object.entries(params || {}).forEach(([key, value]) => {
    if (value !== undefined && value !== "") {
      url.searchParams.set(key, String(value));
    }
  });
}

function buildUrl(path: string, params?: Record<string, string | number | boolean | undefined>) {
  const baseUrl = getBaseUrl().replace(/\/$/, "");
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  const url =
    baseUrl.startsWith("http")
      ? new URL(normalizedPath, baseUrl)
      : new URL(`${baseUrl}${normalizedPath}`, window.location.origin);

  appendParams(url, params);

  return url.toString();
}

async function fetchJson<T>(
  path: string,
  params?: Record<string, string | number | boolean | undefined>
): Promise<T> {
  const response = await fetch(buildUrl(path, params), {
    cache: "no-store"
  });

  if (!response.ok) {
    let detail = response.statusText;

    try {
      const payload = (await response.json()) as { detail?: string; message?: string };
      detail = payload.detail || payload.message || detail;
    } catch {
      // Keep the HTTP status text when the backend is unavailable.
    }

    throw new Error(detail || `Request failed with status ${response.status}`);
  }

  return response.json() as Promise<T>;
}

export function getSummary() {
  return fetchJson<SummaryResponse>("/v3/summary");
}

export async function getCharts() {
  const response = await fetchJson<ApiDataResponse<ChartsData>>("/v3/charts");
  return response.data;
}

export async function getLogs(params: LogsParams = {}) {
  const response = await fetchJson<ApiListResponse<ProcessedLog>>("/v3/logs", {
    limit: params.limit ?? 50,
    severity: params.severity,
    event_type: params.event_type,
    route: params.route
  });

  return response.data;
}

export async function getPredictions(params: PredictionsParams = {}) {
  const response = await fetchJson<ApiListResponse<SequencePrediction>>(
    "/v3/predictions",
    {
      limit: params.limit ?? 50,
      label: params.label,
      predicted_label: params.predicted_label,
      only_errors: params.only_errors
    }
  );

  return response.data;
}

export async function getIncidents(params: IncidentsParams = {}) {
  const response = await fetchJson<ApiListResponse<FinalIncident>>("/v3/incidents", {
    limit: params.limit ?? 50,
    severity: params.severity,
    route: params.route
  });

  return response.data;
}

export async function getModelMetrics() {
  const response = await fetchJson<ApiDataResponse<ModelMetric[]>>("/v3/model-metrics");
  return response.data;
}
