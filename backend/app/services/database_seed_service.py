import json
import os
from typing import Any, Dict, List, Optional

import pandas as pd
from sqlalchemy import text

from backend.app.database import Base, engine, get_db_session
from backend.app import db_models
from backend.app.db_models import (
    FinalIncident,
    LogSequence,
    ModelMetric,
    ProcessedLog,
    SequencePrediction,
)


LOGS_PROCESSED_PATH = "data/processed/logs_processed.csv"
LOG_SEQUENCES_PATH = "data/processed/log_sequences.csv"
SEQUENCE_PREDICTIONS_PATH = "reports/sequence_transformer_predictions.csv"
FINAL_INCIDENTS_PATH = "reports/final_incidents.csv"

INCIDENT_SUMMARY_PATH = "reports/incident_summary.json"
ANOMALY_DETECTION_REPORT_PATH = "reports/anomaly_detection_report.json"
SEQUENCE_DATASET_REPORT_PATH = "reports/sequence_dataset_report.json"
SEQUENCE_TRANSFORMER_REPORT_PATH = "reports/sequence_transformer_report.json"


def safe_value(value):
    if pd.isna(value):
        return None

    return value


def safe_int(value):
    value = safe_value(value)

    if value is None or value == "":
        return None

    try:
        return int(float(value))
    except (ValueError, TypeError):
        return None


def safe_float(value):
    value = safe_value(value)

    if value is None or value == "":
        return None

    try:
        return float(value)
    except (ValueError, TypeError):
        return None


def safe_str(value):
    value = safe_value(value)

    if value is None:
        return None

    return str(value)


def safe_datetime(value):
    value = safe_value(value)

    if value is None or value == "":
        return None

    parsed = pd.to_datetime(value, errors="coerce")

    if pd.isna(parsed):
        return None

    return parsed.to_pydatetime()


def load_csv(path: str) -> pd.DataFrame:
    if not os.path.exists(path):
        print(f"No se encontró: {path}. Se omitirá.")
        return pd.DataFrame()

    return pd.read_csv(path, encoding="utf-8-sig")


def load_json(path: str) -> Optional[Dict[str, Any]]:
    if not os.path.exists(path):
        print(f"No se encontró: {path}. Se omitirá.")
        return None

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def recreate_tables():
    """
    Para V3 inicial usamos un seed reproducible:
    borra las tablas y las vuelve a crear.

    Esto evita duplicados cada vez que cargas los CSV/JSON otra vez.
    Más adelante, en una versión más real, usaríamos migraciones y upserts.
    """

    import backend.app.db_models  # noqa: F401

    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


def map_processed_log(row: pd.Series) -> Dict[str, Any]:
    return {
        "timestamp": safe_datetime(row.get("timestamp")),
        "user_id": safe_str(row.get("user_id")),
        "ip": safe_str(row.get("ip")),
        "method": safe_str(row.get("method")),
        "route": safe_str(row.get("route")),
        "status_code": safe_int(row.get("status_code")),
        "response_time_ms": safe_float(row.get("response_time_ms")),
        "event_type": safe_str(row.get("event_type")),
        "message": safe_str(row.get("message")),
        "severity": safe_str(row.get("severity")),
        "scenario": safe_str(row.get("scenario")),
        "scenario_label": safe_str(row.get("scenario_label")),
        "hour": safe_int(row.get("hour")),
        "day_of_week": safe_int(row.get("day_of_week")),
        "minute": safe_int(row.get("minute")),
        "is_weekend": safe_int(row.get("is_weekend")),
        "is_night": safe_int(row.get("is_night")),
        "is_success": safe_int(row.get("is_success")),
        "is_client_error": safe_int(row.get("is_client_error")),
        "is_server_error": safe_int(row.get("is_server_error")),
        "is_error": safe_int(row.get("is_error")),
        "is_slow": safe_int(row.get("is_slow")),
        "is_very_slow": safe_int(row.get("is_very_slow")),
        "is_critical_route": safe_int(row.get("is_critical_route")),
        "is_auth_event": safe_int(row.get("is_auth_event")),
        "is_payment_event": safe_int(row.get("is_payment_event")),
        "is_warning_event": safe_int(row.get("is_warning_event")),
        "is_critical_event": safe_int(row.get("is_critical_event")),
        "is_login_failed": safe_int(row.get("is_login_failed")),
        "is_unauthorized": safe_int(row.get("is_unauthorized")),
        "is_payment_failed": safe_int(row.get("is_payment_failed")),
        "is_database_timeout": safe_int(row.get("is_database_timeout")),
        "requests_by_ip": safe_int(row.get("requests_by_ip")),
        "requests_by_user": safe_int(row.get("requests_by_user")),
        "requests_by_route": safe_int(row.get("requests_by_route")),
        "errors_by_ip": safe_int(row.get("errors_by_ip")),
        "errors_by_route": safe_int(row.get("errors_by_route")),
        "failed_logins_by_ip": safe_int(row.get("failed_logins_by_ip")),
        "failed_logins_by_user": safe_int(row.get("failed_logins_by_user")),
        "unauthorized_by_ip": safe_int(row.get("unauthorized_by_ip")),
        "payment_failures_by_route": safe_int(row.get("payment_failures_by_route")),
        "avg_response_by_route": safe_float(row.get("avg_response_by_route")),
        "max_response_by_route": safe_float(row.get("max_response_by_route")),
        "method_code": safe_int(row.get("method_code")),
        "route_code": safe_int(row.get("route_code")),
        "event_type_code": safe_int(row.get("event_type_code")),
        "severity_code": safe_int(row.get("severity_code")),
        "risk_score": safe_int(row.get("risk_score")),
    }


def map_log_sequence(row: pd.Series) -> Dict[str, Any]:
    return {
        "sequence_id": safe_str(row.get("sequence_id")),
        "entity_type": safe_str(row.get("entity_type")),
        "entity_id": safe_str(row.get("entity_id")),
        "start_time": safe_datetime(row.get("start_time")),
        "end_time": safe_datetime(row.get("end_time")),
        "window_size": safe_int(row.get("window_size")),
        "event_sequence": safe_str(row.get("event_sequence")),
        "route_sequence": safe_str(row.get("route_sequence")),
        "status_sequence": safe_str(row.get("status_sequence")),
        "method_sequence": safe_str(row.get("method_sequence")),
        "avg_response_time": safe_float(row.get("avg_response_time")),
        "max_response_time": safe_float(row.get("max_response_time")),
        "max_risk_score": safe_int(row.get("max_risk_score")),
        "critical_count": safe_int(row.get("critical_count")),
        "warning_count": safe_int(row.get("warning_count")),
        "error_count": safe_int(row.get("error_count")),
        "server_error_count": safe_int(row.get("server_error_count")),
        "slow_count": safe_int(row.get("slow_count")),
        "very_slow_count": safe_int(row.get("very_slow_count")),
        "critical_route_count": safe_int(row.get("critical_route_count")),
        "login_failed_count": safe_int(row.get("login_failed_count")),
        "unauthorized_count": safe_int(row.get("unauthorized_count")),
        "payment_failed_count": safe_int(row.get("payment_failed_count")),
        "database_timeout_count": safe_int(row.get("database_timeout_count")),
        "label": safe_str(row.get("label")),
        "label_id": safe_int(row.get("label_id")),
        "reason": safe_str(row.get("reason")),
        "scenario_sequence": safe_str(row.get("scenario_sequence")),
        "main_scenarios": safe_str(row.get("main_scenarios")),
        "scenario_label_sequence": safe_str(row.get("scenario_label_sequence")),
        "scenario_label_distribution": safe_str(row.get("scenario_label_distribution")),
    }


def map_sequence_prediction(row: pd.Series) -> Dict[str, Any]:
    return {
        "sequence_id": safe_str(row.get("sequence_id")),
        "entity_type": safe_str(row.get("entity_type")),
        "entity_id": safe_str(row.get("entity_id")),
        "start_time": safe_datetime(row.get("start_time")),
        "end_time": safe_datetime(row.get("end_time")),
        "window_size": safe_int(row.get("window_size")),
        "event_sequence": safe_str(row.get("event_sequence")),
        "route_sequence": safe_str(row.get("route_sequence")),
        "status_sequence": safe_str(row.get("status_sequence")),
        "method_sequence": safe_str(row.get("method_sequence")),
        "label": safe_str(row.get("label")),
        "label_id": safe_int(row.get("label_id")),
        "predicted_label": safe_str(row.get("predicted_label")),
        "predicted_label_id": safe_int(row.get("predicted_label_id")),
        "anomaly_probability": safe_float(row.get("anomaly_probability")),
        "normal_probability": safe_float(row.get("normal_probability")),
        "max_risk_score": safe_int(row.get("max_risk_score")),
        "max_response_time": safe_float(row.get("max_response_time")),
        "main_scenarios": safe_str(row.get("main_scenarios")),
        "reason": safe_str(row.get("reason")),
    }


def map_final_incident(row: pd.Series) -> Dict[str, Any]:
    return {
        "incident_id": safe_str(row.get("incident_id")),
        "severity": safe_str(row.get("severity")),
        "severity_rank": safe_int(row.get("severity_rank")),
        "incident_type": safe_str(row.get("incident_type")),
        "sources": safe_str(row.get("sources")),
        "detection_types": safe_str(row.get("detection_types")),
        "first_seen": safe_datetime(row.get("first_seen")),
        "last_seen": safe_datetime(row.get("last_seen")),
        "events_count": safe_int(row.get("events_count")),
        "user_id": safe_str(row.get("user_id")),
        "ip": safe_str(row.get("ip")),
        "method": safe_str(row.get("method")),
        "route": safe_str(row.get("route")),
        "status_code": safe_int(row.get("status_code")),
        "max_response_time_ms": safe_float(row.get("max_response_time_ms")),
        "event_type": safe_str(row.get("event_type")),
        "max_risk_score": safe_int(row.get("max_risk_score")),
        "min_anomaly_score": safe_float(row.get("min_anomaly_score")),
        "reason": safe_str(row.get("reason")),
        "recommendation": safe_str(row.get("recommendation")),
    }


def bulk_insert(session, model, records: List[Dict[str, Any]], chunk_size: int = 1000):
    if not records:
        return 0

    total = 0

    for start in range(0, len(records), chunk_size):
        chunk = records[start:start + chunk_size]
        session.bulk_insert_mappings(model, chunk)
        total += len(chunk)

    return total


def seed_processed_logs(session):
    df = load_csv(LOGS_PROCESSED_PATH)

    if df.empty:
        return 0

    records = [map_processed_log(row) for _, row in df.iterrows()]
    return bulk_insert(session, ProcessedLog, records)


def seed_log_sequences(session):
    df = load_csv(LOG_SEQUENCES_PATH)

    if df.empty:
        return 0

    records = [map_log_sequence(row) for _, row in df.iterrows()]
    return bulk_insert(session, LogSequence, records)


def seed_sequence_predictions(session):
    df = load_csv(SEQUENCE_PREDICTIONS_PATH)

    if df.empty:
        return 0

    records = [map_sequence_prediction(row) for _, row in df.iterrows()]
    return bulk_insert(session, SequencePrediction, records)


def seed_final_incidents(session):
    df = load_csv(FINAL_INCIDENTS_PATH)

    if df.empty:
        return 0

    records = [map_final_incident(row) for _, row in df.iterrows()]
    return bulk_insert(session, FinalIncident, records)


def seed_model_metrics(session):
    metric_files = [
        {
            "version": "v1",
            "model_name": "Isolation Forest",
            "metric_source": ANOMALY_DETECTION_REPORT_PATH,
        },
        {
            "version": "v1",
            "model_name": "Alert Manager",
            "metric_source": INCIDENT_SUMMARY_PATH,
        },
        {
            "version": "v2",
            "model_name": "Sequence Dataset",
            "metric_source": SEQUENCE_DATASET_REPORT_PATH,
        },
        {
            "version": "v2",
            "model_name": "LogSequenceTransformer",
            "metric_source": SEQUENCE_TRANSFORMER_REPORT_PATH,
        },
    ]

    records = []

    for item in metric_files:
        metrics_json = load_json(item["metric_source"])

        if metrics_json is None:
            continue

        records.append({
            "version": item["version"],
            "model_name": item["model_name"],
            "metric_source": item["metric_source"],
            "metrics_json": metrics_json,
        })

    return bulk_insert(session, ModelMetric, records)


def print_table_counts(session):
    tables = [
        "processed_logs",
        "log_sequences",
        "sequence_predictions",
        "final_incidents",
        "model_metrics",
    ]

    print("\nRegistros cargados en PostgreSQL:")

    for table in tables:
        count = session.execute(text(f"SELECT COUNT(*) FROM {table}")).scalar()
        print(f"- {table}: {count}")


def main():
    print("Recreando tablas de PostgreSQL...")
    recreate_tables()

    print("Cargando datos de LogGuard AI V3...")

    with get_db_session() as session:
        processed_logs_count = seed_processed_logs(session)
        log_sequences_count = seed_log_sequences(session)
        sequence_predictions_count = seed_sequence_predictions(session)
        final_incidents_count = seed_final_incidents(session)
        model_metrics_count = seed_model_metrics(session)

        print("\nResumen de carga:")
        print(f"- processed_logs: {processed_logs_count}")
        print(f"- log_sequences: {log_sequences_count}")
        print(f"- sequence_predictions: {sequence_predictions_count}")
        print(f"- final_incidents: {final_incidents_count}")
        print(f"- model_metrics: {model_metrics_count}")

        print_table_counts(session)

    print("\nSeed completado correctamente.")


if __name__ == "__main__":
    main()