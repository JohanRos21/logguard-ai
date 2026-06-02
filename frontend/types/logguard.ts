export type CountMap = Record<string, number>;

export type MetricJson = Record<string, unknown>;

export interface ApiListResponse<T> {
  version: string;
  storage: string;
  limit: number;
  data: T[];
}

export interface ApiDataResponse<T> {
  version: string;
  storage: string;
  data: T;
}

export interface SummaryTotals {
  processed_logs: number;
  log_sequences: number;
  sequence_predictions: number;
  final_incidents: number;
  model_metrics: number;
}

export interface SummaryDistributions {
  logs_by_severity: CountMap;
  sequences_by_label: CountMap;
  predictions_by_label: CountMap;
  incidents_by_severity: CountMap;
  top_routes: CountMap;
  top_event_types: CountMap;
}

export interface ConfusionMatrixData {
  true_normal_pred_normal: number;
  true_normal_pred_anomaly: number;
  true_anomaly_pred_normal: number;
  true_anomaly_pred_anomaly: number;
}

export interface SummaryResponse {
  version: string;
  storage: string;
  totals: SummaryTotals;
  distributions: SummaryDistributions;
  transformer_metrics: MetricJson | null;
  sequence_dataset_report: MetricJson | null;
  confusion_matrix_from_db: ConfusionMatrixData;
}

export interface ChartsData {
  logs_by_severity: CountMap;
  logs_by_event_type: CountMap;
  logs_by_route: CountMap;
  sequences_by_label: CountMap;
  predictions_by_label: CountMap;
  incidents_by_severity: CountMap;
}

export interface ProcessedLog {
  id: number;
  timestamp: string | null;
  user_id: string | null;
  ip: string | null;
  method: string | null;
  route: string | null;
  status_code: number | null;
  response_time_ms: number | null;
  event_type: string | null;
  message: string | null;
  severity: string | null;
  scenario: string | null;
  scenario_label: string | null;
  risk_score: number | null;
  created_at: string | null;
}

export interface SequencePrediction {
  id: number;
  sequence_id: string | null;
  entity_type: string | null;
  entity_id: string | null;
  start_time: string | null;
  end_time: string | null;
  window_size: number | null;
  label: string | null;
  label_id: number | null;
  predicted_label: string | null;
  predicted_label_id: number | null;
  anomaly_probability: number | null;
  normal_probability: number | null;
  max_risk_score: number | null;
  max_response_time: number | null;
  main_scenarios: string | null;
  reason: string | null;
  created_at: string | null;
}

export interface FinalIncident {
  id: number;
  incident_id: string | null;
  severity: string | null;
  severity_rank: number | null;
  incident_type: string | null;
  sources: string | null;
  detection_types: string | null;
  first_seen: string | null;
  last_seen: string | null;
  events_count: number | null;
  user_id: string | null;
  ip: string | null;
  method: string | null;
  route: string | null;
  status_code: number | null;
  max_response_time_ms: number | null;
  event_type: string | null;
  max_risk_score: number | null;
  min_anomaly_score: number | null;
  reason: string | null;
  recommendation: string | null;
  created_at: string | null;
}

export interface ModelMetric {
  id: number;
  version: string | null;
  model_name: string | null;
  metric_source: string | null;
  metrics_json: MetricJson | null;
  created_at: string | null;
}

export interface LogsParams {
  limit?: number;
  severity?: string;
  event_type?: string;
  route?: string;
}

export interface PredictionsParams {
  limit?: number;
  label?: string;
  predicted_label?: string;
  only_errors?: boolean;
}

export interface IncidentsParams {
  limit?: number;
  severity?: string;
  route?: string;
}
