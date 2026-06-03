import os
import json
from typing import Any, Dict, List, Optional

import pandas as pd
from fastapi import Depends, FastAPI, HTTPException, Query, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from backend.app.ingestion_schemas import (
    IngestBatchRequest,
    IngestLogRequest,
    IngestLogResponse,
)
from backend.app.ml.predict_anomaly import predict_anomaly
from backend.app.ml.predict_sequence_transformer import predict_sequence

from backend.app.services.database_query_service import (
    get_v3_chart_data,
    get_v3_incidents,
    get_v3_logs,
    get_v3_model_metrics,
    get_v3_predictions,
    get_v3_sequences,
    get_v3_summary,
)
from backend.app.services.ingestion_service import (
    get_ingested_logs,
    get_ingested_logs_summary,
    ingest_batch,
    ingest_log,
)
from backend.app.services.realtime_sequence_service import (
    analyze_ingested_sequences,
    get_ingested_sequence_predictions,
    get_real_monitoring_summary,
)
from backend.app.services.real_incident_service import (
    generate_real_incidents,
    get_real_incidents,
    get_real_incidents_summary,
)
from backend.app.services.async_analysis_service import enqueue_ingested_entity_analysis
from backend.app.services.incident_lifecycle_service import (
    IncidentNotFoundError,
    InvalidIncidentTransitionError,
    acknowledge_incident,
    get_incident_lifecycle_summary,
    list_incidents_by_status,
    reopen_incident,
    resolve_incident,
)
from backend.app.services.notification_service import (
    get_notifications_summary,
    list_notification_events,
    queue_test_webhook_notification,
)

from backend.app.v4_schemas import (
    V4AdaptiveBatchRequest,
    V4AdaptiveLogRequest,
    V4NormalizationPreviewRequest,
)
from backend.app.v5_schemas import (
    V5AnalyzeEntityAsyncRequest,
    V5IncidentActionRequest,
    V5NotificationListResponse,
    V5NotificationSummaryResponse,
    V5ResolveIncidentRequest,
    V5TestWebhookRequest,
)
from backend.app.services.log_normalizer_service import (
    get_available_adapters,
    normalize_external_log,
)

from celery.result import AsyncResult

from backend.app.celery_app import app as celery_app
from backend.app.tasks import ping_worker


RULE_ALERTS_PATH = "reports/rule_alerts.csv"
ML_ANOMALIES_PATH = "reports/ml_anomalies.csv"
FINAL_INCIDENTS_PATH = "reports/final_incidents.csv"
INCIDENT_SUMMARY_PATH = "reports/incident_summary.json"
ANOMALY_REPORT_PATH = "reports/anomaly_detection_report.json"

SEQUENCE_DATASET_REPORT_PATH = "reports/sequence_dataset_report.json"
SEQUENCE_TRANSFORMER_REPORT_PATH = "reports/sequence_transformer_report.json"
SEQUENCE_TRANSFORMER_PREDICTIONS_PATH = "reports/sequence_transformer_predictions.csv"


app = FastAPI(
    title="LogGuard AI",
    description=(
        "API para monitoreo, detección de anomalías y gestión de incidentes "
        "en logs web. Incluye V1 con reglas + Isolation Forest y V2 con "
        "Transformer secuencial."
    ),
    version="2.0.0"
)

CORS_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "LOGGUARD_CORS_ORIGINS",
        "http://127.0.0.1:3000,http://localhost:3000,"
        "http://127.0.0.1:3001,http://localhost:3001",
    ).split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

bearer_auth = HTTPBearer(
    auto_error=False,
    scheme_name="LogGuard API Key",
    description="Use LOGGUARD_API_KEY as a Bearer token.",
)


def validate_ingestion_api_key(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(bearer_auth),
):
    expected_api_key = os.getenv("LOGGUARD_API_KEY", "change-me")

    if not credentials:
        raise HTTPException(status_code=401, detail="Missing authorization header.")

    if credentials.scheme.lower() != "bearer" or credentials.credentials != expected_api_key:
        raise HTTPException(status_code=401, detail="Invalid API key.")

    return True


class LogFeaturesInput(BaseModel):
    features: Dict[str, Any]


class SequenceInput(BaseModel):
    event_sequence: List[str] = Field(
        ...,
        example=[
            "login_failed",
            "login_failed",
            "unauthorized_access",
            "server_error"
        ]
    )
    route_sequence: List[str] = Field(
        ...,
        example=[
            "/login",
            "/login",
            "/dashboard/admin",
            "/api/admin/users"
        ]
    )
    status_sequence: List[str] = Field(
        ...,
        example=[
            "401",
            "401",
            "403",
            "500"
        ]
    )
    method_sequence: List[str] = Field(
        ...,
        example=[
            "POST",
            "POST",
            "GET",
            "GET"
        ]
    )
    threshold: float = Field(
        default=0.50,
        ge=0.0,
        le=1.0,
        description="Umbral para clasificar una secuencia como anomaly."
    )


def read_json_file(path: str):
    if not os.path.exists(path):
        raise HTTPException(
            status_code=404,
            detail=f"No se encontró el archivo: {path}"
        )

    with open(path, "r", encoding="utf-8") as file:
        return json.load(file)


def read_csv_file(path: str):
    if not os.path.exists(path):
        raise HTTPException(
            status_code=404,
            detail=f"No se encontró el archivo: {path}"
        )

    return pd.read_csv(path, encoding="utf-8-sig")


def dataframe_to_records(
    df: pd.DataFrame,
    limit: int,
    severity: Optional[str] = None,
    route: Optional[str] = None,
):
    if severity and "severity" in df.columns:
        df = df[df["severity"].astype(str).str.lower() == severity.lower()]

    if route and "route" in df.columns:
        df = df[df["route"].astype(str) == route]

    df = df.head(limit)

    return df.to_dict(orient="records")


def infer_final_severity_from_features(features: Dict[str, Any], ml_result: Dict[str, Any]):
    """
    La IA de V1 detecta si algo es anómalo, pero la severidad final también
    depende del impacto operativo. Por eso combinamos resultado ML con
    risk_score, ruta crítica, error 5xx, pago fallido o timeout de base de datos.
    """

    risk_score = int(features.get("risk_score", 0))
    is_critical_route = int(features.get("is_critical_route", 0))
    is_server_error = int(features.get("is_server_error", 0))
    is_payment_failed = int(features.get("is_payment_failed", 0))
    is_database_timeout = int(features.get("is_database_timeout", 0))
    is_very_slow = int(features.get("is_very_slow", 0))

    is_anomaly = bool(ml_result.get("is_anomaly", False))

    critical_condition = (
        risk_score >= 18
        or (
            is_critical_route == 1
            and (
                is_server_error == 1
                or is_payment_failed == 1
                or is_database_timeout == 1
                or is_very_slow == 1
            )
        )
    )

    if critical_condition:
        return "critical"

    if is_anomaly or risk_score >= 10:
        return "warning"

    return "normal"


def build_recommendation(features: Dict[str, Any], final_severity: str):
    event_type = str(features.get("event_type", ""))
    route = str(features.get("route", ""))

    if final_severity == "critical":
        if "payment" in event_type or "payments" in route:
            return "Revisar pasarela de pagos, errores del backend, webhooks y disponibilidad del servicio."

        if "database" in event_type or "database" in route:
            return "Revisar conexión a base de datos, consultas lentas, índices y carga del servidor."

        if "login" in event_type or "unauthorized" in event_type:
            return "Revisar IPs sospechosas, sesiones, permisos y posibles intentos de acceso no autorizado."

        return "Revisar el evento de forma prioritaria y validar si corresponde a un incidente activo."

    if final_severity == "warning":
        return "Monitorear si el patrón se repite y revisar logs relacionados del mismo usuario, IP o ruta."

    return "No se requiere acción inmediata."


def validate_sequence_lengths(payload: SequenceInput):
    lengths = {
        "event_sequence": len(payload.event_sequence),
        "route_sequence": len(payload.route_sequence),
        "status_sequence": len(payload.status_sequence),
        "method_sequence": len(payload.method_sequence),
    }

    unique_lengths = set(lengths.values())

    if len(unique_lengths) != 1:
        raise HTTPException(
            status_code=400,
            detail={
                "message": "Todas las secuencias deben tener la misma longitud.",
                "lengths": lengths,
            }
        )

    if len(payload.event_sequence) == 0:
        raise HTTPException(
            status_code=400,
            detail="La secuencia no puede estar vacía."
        )


@app.get("/")
def root():
    return {
        "project": "LogGuard AI",
        "status": "running",
        "description": "Sistema inteligente de detección de anomalías e incidentes en logs web.",
        "version": "2.0.0",
        "modules": {
            "v1": "Reglas + Isolation Forest + Alert Manager",
            "v2": "Transformer secuencial para patrones de logs"
        }
    }


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "message": "LogGuard AI API funcionando correctamente.",
        "version": "2.0.0"
    }


@app.get("/metrics")
def get_metrics():
    incident_summary = read_json_file(INCIDENT_SUMMARY_PATH)
    anomaly_report = read_json_file(ANOMALY_REPORT_PATH)

    return {
        "version": "v1",
        "incident_summary": incident_summary,
        "anomaly_detection_report": anomaly_report
    }


@app.get("/alerts")
def get_rule_alerts(
    limit: int = Query(default=50, ge=1, le=500),
    severity: Optional[str] = None,
    route: Optional[str] = None,
):
    df = read_csv_file(RULE_ALERTS_PATH)

    return {
        "total": len(df),
        "limit": limit,
        "data": dataframe_to_records(df, limit, severity, route)
    }


@app.get("/anomalies")
def get_ml_anomalies(
    limit: int = Query(default=50, ge=1, le=500),
    severity: Optional[str] = None,
    route: Optional[str] = None,
):
    df = read_csv_file(ML_ANOMALIES_PATH)

    return {
        "total": len(df),
        "limit": limit,
        "data": dataframe_to_records(df, limit, severity, route)
    }


@app.get("/incidents")
def get_final_incidents(
    limit: int = Query(default=50, ge=1, le=500),
    severity: Optional[str] = None,
    route: Optional[str] = None,
):
    df = read_csv_file(FINAL_INCIDENTS_PATH)

    return {
        "total": len(df),
        "limit": limit,
        "data": dataframe_to_records(df, limit, severity, route)
    }


@app.get("/incidents/{incident_id}")
def get_incident_by_id(incident_id: str):
    df = read_csv_file(FINAL_INCIDENTS_PATH)

    incident = df[df["incident_id"].astype(str) == incident_id]

    if incident.empty:
        raise HTTPException(
            status_code=404,
            detail=f"No se encontró el incidente: {incident_id}"
        )

    return incident.iloc[0].to_dict()


@app.post("/analyze-log")
def analyze_log(payload: LogFeaturesInput):
    """
    Endpoint V1.

    Analiza un log usando features ya procesadas.
    Usa Isolation Forest y luego ajusta severidad con lógica de negocio.
    """

    try:
        ml_result = predict_anomaly(payload.features)
        final_severity = infer_final_severity_from_features(payload.features, ml_result)

        return {
            "version": "v1",
            "model": "Isolation Forest",
            "ml_result": ml_result,
            "final_severity": final_severity,
            "recommendation": build_recommendation(payload.features, final_severity)
        }

    except Exception as error:
        raise HTTPException(
            status_code=400,
            detail=str(error)
        )


@app.get("/v2/metrics")
def get_v2_metrics():
    sequence_dataset_report = read_json_file(SEQUENCE_DATASET_REPORT_PATH)
    sequence_transformer_report = read_json_file(SEQUENCE_TRANSFORMER_REPORT_PATH)

    return {
        "version": "v2",
        "sequence_dataset_report": sequence_dataset_report,
        "sequence_transformer_report": sequence_transformer_report
    }


@app.get("/v2/sequence-predictions")
def get_v2_sequence_predictions(
    limit: int = Query(default=50, ge=1, le=500),
    predicted_label: Optional[str] = None,
    label: Optional[str] = None,
):
    df = read_csv_file(SEQUENCE_TRANSFORMER_PREDICTIONS_PATH)

    if predicted_label and "predicted_label" in df.columns:
        df = df[df["predicted_label"].astype(str).str.lower() == predicted_label.lower()]

    if label and "label" in df.columns:
        df = df[df["label"].astype(str).str.lower() == label.lower()]

    df = df.head(limit)

    return {
        "version": "v2",
        "total": len(df),
        "limit": limit,
        "data": df.to_dict(orient="records")
    }


@app.post("/v2/analyze-sequence")
def analyze_sequence(payload: SequenceInput):
    """
    Endpoint V2.

    Analiza una secuencia de logs usando el Transformer secuencial.
    Este endpoint ya no mira un log aislado, sino un patrón de comportamiento.
    """

    validate_sequence_lengths(payload)

    try:
        result = predict_sequence(
            event_sequence=payload.event_sequence,
            route_sequence=payload.route_sequence,
            status_sequence=payload.status_sequence,
            method_sequence=payload.method_sequence,
            threshold=payload.threshold,
        )

        return {
            "version": "v2",
            "model": "LogSequenceTransformer",
            "result": result
        }

    except Exception as error:
        raise HTTPException(
            status_code=400,
            detail=str(error)
        )


@app.get("/v3/summary")
def v3_summary():
    return get_v3_summary()


@app.get("/v3/logs")
def v3_logs(
    limit: int = Query(default=50, ge=1, le=500),
    severity: Optional[str] = None,
    route: Optional[str] = None,
    event_type: Optional[str] = None,
):
    return {
        "version": "v3",
        "storage": "PostgreSQL",
        "limit": limit,
        "data": get_v3_logs(
            limit=limit,
            severity=severity,
            route=route,
            event_type=event_type,
        )
    }


@app.get("/v3/sequences")
def v3_sequences(
    limit: int = Query(default=50, ge=1, le=500),
    label: Optional[str] = None,
    entity_id: Optional[str] = None,
):
    return {
        "version": "v3",
        "storage": "PostgreSQL",
        "limit": limit,
        "data": get_v3_sequences(
            limit=limit,
            label=label,
            entity_id=entity_id,
        )
    }


@app.get("/v3/predictions")
def v3_predictions(
    limit: int = Query(default=50, ge=1, le=500),
    label: Optional[str] = None,
    predicted_label: Optional[str] = None,
    only_errors: bool = False,
):
    return {
        "version": "v3",
        "storage": "PostgreSQL",
        "limit": limit,
        "data": get_v3_predictions(
            limit=limit,
            label=label,
            predicted_label=predicted_label,
            only_errors=only_errors,
        )
    }


@app.get("/v3/incidents")
def v3_incidents(
    limit: int = Query(default=50, ge=1, le=500),
    severity: Optional[str] = None,
    route: Optional[str] = None,
):
    return {
        "version": "v3",
        "storage": "PostgreSQL",
        "limit": limit,
        "data": get_v3_incidents(
            limit=limit,
            severity=severity,
            route=route,
        )
    }


@app.get("/v3/model-metrics")
def v3_model_metrics():
    return {
        "version": "v3",
        "storage": "PostgreSQL",
        "data": get_v3_model_metrics()
    }


@app.get("/v3/charts")
def v3_charts():
    return {
        "version": "v3",
        "storage": "PostgreSQL",
        "data": get_v3_chart_data()
    }


@app.post("/v3/ingest-log", response_model=IngestLogResponse)
def v3_ingest_log(
    payload: IngestLogRequest,
    _authorized: bool = Depends(validate_ingestion_api_key),
):
    try:
        result = ingest_log(payload)

        return {
            "status": "accepted",
            "id": result["id"],
            "source_severity": result["source_severity"],
            "final_severity": result["final_severity"],
            "auto_analysis": result["auto_analysis"],
        }
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))


@app.post("/v3/ingest-batch")
def v3_ingest_batch(
    payload: IngestBatchRequest,
    _authorized: bool = Depends(validate_ingestion_api_key),
):
    try:
        batch_result = ingest_batch(payload)
        results = batch_result["results"]

        return {
            "status": "accepted",
            "total_received": len(payload.logs),
            "total_saved": len(results),
            "saved_ids": [result["id"] for result in results],
            "auto_analysis": batch_result["auto_analysis"],
        }
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error))


@app.get("/v3/ingested-logs")
def v3_ingested_logs(
    source: Optional[str] = None,
    event_type: Optional[str] = None,
    final_severity: Optional[str] = None,
    ip: Optional[str] = None,
    limit: int = Query(default=50, ge=1, le=500),
):
    return {
        "version": "v3",
        "storage": "PostgreSQL",
        "limit": limit,
        "data": get_ingested_logs(
            limit=limit,
            source=source,
            event_type=event_type,
            final_severity=final_severity,
            ip=ip,
        ),
    }


@app.get("/v3/ingested-logs/summary")
def v3_ingested_logs_summary():
    return {
        "version": "v3",
        "storage": "PostgreSQL",
        "data": get_ingested_logs_summary(),
    }


@app.post("/v3/analyze-ingested-sequences")
def v3_analyze_ingested_sequences(
    group_by: str = Query(default="ip"),
    window_size: int = Query(default=20, ge=1),
    limit_entities: Optional[int] = Query(default=None, ge=1),
    source: Optional[str] = None,
):
    try:
        return analyze_ingested_sequences(
            group_by=group_by,
            window_size=window_size,
            limit_entities=limit_entities,
            source=source,
        )
    except Exception as error:
        raise HTTPException(status_code=400, detail=str(error))


@app.get("/v3/ingested-sequence-predictions")
def v3_ingested_sequence_predictions(
    entity_id: Optional[str] = None,
    ai_prediction: Optional[str] = None,
    final_severity: Optional[str] = None,
    source: Optional[str] = None,
    limit: int = Query(default=50, ge=1, le=500),
):
    return {
        "version": "v3",
        "storage": "PostgreSQL",
        "limit": limit,
        "data": get_ingested_sequence_predictions(
            limit=limit,
            entity_id=entity_id,
            ai_prediction=ai_prediction,
            final_severity=final_severity,
            source=source,
        ),
    }


@app.get("/v3/real-monitoring-summary")
def v3_real_monitoring_summary():
    return get_real_monitoring_summary()


@app.post("/v3/generate-real-incidents")
def v3_generate_real_incidents():
    try:
        return generate_real_incidents()
    except Exception as error:
        raise HTTPException(status_code=400, detail=str(error))


@app.get("/v3/real-incidents")
def v3_real_incidents(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    incident_type: Optional[str] = None,
    entity_id: Optional[str] = None,
    source: Optional[str] = None,
    limit: int = Query(default=50, ge=1, le=500),
):
    return {
        "version": "v3",
        "storage": "PostgreSQL",
        "limit": limit,
        "data": get_real_incidents(
            limit=limit,
            severity=severity,
            status=status,
            incident_type=incident_type,
            entity_id=entity_id,
            source=source,
        ),
    }


@app.get("/v3/real-incidents/summary")
def v3_real_incidents_summary():
    return get_real_incidents_summary()


def normalize_v4_request(
    adapter: str,
    source: Optional[str],
    environment: Optional[str],
    payload: Any,
) -> Dict[str, Any]:
    return normalize_external_log(
        raw_log={
            "source": source,
            "environment": environment,
            "payload": payload,
        },
        adapter=adapter,
        source=source,
        environment=environment,
    )


def normalized_log_to_ingest_request(normalized_log: Dict[str, Any]) -> IngestLogRequest:
    return IngestLogRequest(**normalized_log)


def build_ingest_log_response(result: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "status": "accepted",
        "id": result["id"],
        "source_severity": result["source_severity"],
        "final_severity": result["final_severity"],
        "auto_analysis": result["auto_analysis"],
    }


@app.get("/v4/adapters")
def v4_adapters():
    return {
        "version": "v4",
        "feature": "Universal Log Adapter",
        "available_adapters": get_available_adapters(),
    }


@app.post("/v4/normalization-preview")
def v4_normalization_preview(
    request: V4NormalizationPreviewRequest,
    _authorized: bool = Depends(validate_ingestion_api_key),
):
    result = normalize_v4_request(
        adapter=request.adapter,
        source=request.source,
        environment=request.environment,
        payload=request.payload,
    )

    return {
        "version": "v4",
        "mode": "preview",
        **result,
    }


@app.post("/v4/ingest-adaptive-log")
def v4_ingest_adaptive_log(
    request: V4AdaptiveLogRequest,
    _authorized: bool = Depends(validate_ingestion_api_key),
):
    result = normalize_v4_request(
        adapter=request.adapter,
        source=request.source,
        environment=request.environment,
        payload=request.payload,
    )

    if not result["success"]:
        raise HTTPException(
            status_code=422,
            detail={
                "adapter_used": result["adapter_used"],
                "errors": result["errors"],
                "warnings": result["warnings"],
            },
        )

    try:
        ingest_payload = normalized_log_to_ingest_request(result["normalized_log"])
        ingestion_result = build_ingest_log_response(ingest_log(ingest_payload))
    except ValueError as error:
        raise HTTPException(status_code=422, detail=str(error))

    return {
        "version": "v4",
        "status": "accepted",
        "adapter_used": result["adapter_used"],
        "normalized_log": result["normalized_log"],
        "ingestion_result": ingestion_result,
    }


@app.post("/v4/ingest-adaptive-batch")
def v4_ingest_adaptive_batch(
    request: V4AdaptiveBatchRequest,
    _authorized: bool = Depends(validate_ingestion_api_key),
):
    normalized_payloads = []
    errors = []

    for index, raw_log in enumerate(request.logs):
        result = normalize_v4_request(
            adapter=request.adapter,
            source=request.source,
            environment=request.environment,
            payload=raw_log,
        )

        if not result["success"]:
            errors.append({
                "index": index,
                "adapter_used": result["adapter_used"],
                "errors": result["errors"],
                "warnings": result["warnings"],
            })
            continue

        try:
            normalized_payloads.append(
                normalized_log_to_ingest_request(result["normalized_log"])
            )
        except ValueError as error:
            errors.append({
                "index": index,
                "adapter_used": result["adapter_used"],
                "errors": [str(error)],
                "warnings": result["warnings"],
            })

    ingestion_result = None

    if normalized_payloads:
        batch_result = ingest_batch(IngestBatchRequest(logs=normalized_payloads))
        saved_results = batch_result["results"]
        ingestion_result = {
            "status": "accepted",
            "total_received": len(normalized_payloads),
            "total_saved": len(saved_results),
            "saved_ids": [item["id"] for item in saved_results],
            "auto_analysis": batch_result["auto_analysis"],
        }

    total_failed = len(errors)
    status = "accepted"

    if total_failed and normalized_payloads:
        status = "partial"
    elif total_failed and not normalized_payloads:
        status = "failed"

    return {
        "version": "v4",
        "status": status,
        "total_received": len(request.logs),
        "total_normalized": len(normalized_payloads),
        "total_failed": total_failed,
        "ingestion_result": ingestion_result,
        "errors": errors,
    }



@app.post("/v5/worker-ping")
def v5_worker_ping(message: str = "ping"):
    task = ping_worker.delay(message)

    return {
        "version": "v5",
        "status": "queued",
        "task_id": task.id,
        "message": message,
    }


@app.post("/v5/analyze-entity-async")
def v5_analyze_entity_async(
    request: V5AnalyzeEntityAsyncRequest,
    _authorized: bool = Depends(validate_ingestion_api_key),
):
    queue_result = enqueue_ingested_entity_analysis(
        entity_type=request.entity_type,
        entity_id=request.entity_id,
        window_size=request.window_size,
        source=request.source,
        group_by=request.group_by,
    )

    if not queue_result.get("queued"):
        return {
            "version": "v5",
            "status": "queue_failed",
            **queue_result,
        }

    return {
        "version": "v5",
        "status": "queued",
        "task_id": queue_result["task_id"],
        "entity_type": queue_result["entity_type"],
        "entity_id": queue_result["entity_id"],
    }


def lifecycle_error_response(error: Exception):
    if isinstance(error, IncidentNotFoundError):
        raise HTTPException(status_code=404, detail=str(error))

    if isinstance(error, InvalidIncidentTransitionError):
        raise HTTPException(status_code=400, detail=str(error))

    raise error


@app.get("/v5/incidents")
def v5_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    incident_type: Optional[str] = None,
    entity_id: Optional[str] = None,
    limit: int = Query(default=50, ge=1, le=500),
    _authorized: bool = Depends(validate_ingestion_api_key),
):
    try:
        return {
            "version": "v5",
            "limit": limit,
            "data": list_incidents_by_status(
                status=status,
                severity=severity,
                incident_type=incident_type,
                entity_id=entity_id,
                limit=limit,
            ),
        }
    except Exception as error:
        lifecycle_error_response(error)


@app.get("/v5/incidents/summary")
def v5_incidents_summary(
    _authorized: bool = Depends(validate_ingestion_api_key),
):
    return {
        "version": "v5",
        "data": get_incident_lifecycle_summary(),
    }


@app.patch("/v5/incidents/{incident_id}/acknowledge")
def v5_acknowledge_incident(
    incident_id: str,
    request: V5IncidentActionRequest,
    _authorized: bool = Depends(validate_ingestion_api_key),
):
    try:
        incident = acknowledge_incident(
            incident_id=incident_id,
            acknowledged_by=request.actor,
            note=request.note,
        )

        return {
            "version": "v5",
            "status": "acknowledged",
            "incident_id": incident_id,
            "incident": incident,
        }
    except Exception as error:
        lifecycle_error_response(error)


@app.patch("/v5/incidents/{incident_id}/resolve")
def v5_resolve_incident(
    incident_id: str,
    request: V5ResolveIncidentRequest,
    _authorized: bool = Depends(validate_ingestion_api_key),
):
    try:
        incident = resolve_incident(
            incident_id=incident_id,
            resolved_by=request.actor,
            resolution_note=request.resolution_note,
        )

        return {
            "version": "v5",
            "status": "resolved",
            "incident_id": incident_id,
            "incident": incident,
        }
    except Exception as error:
        lifecycle_error_response(error)


@app.patch("/v5/incidents/{incident_id}/reopen")
def v5_reopen_incident(
    incident_id: str,
    request: V5IncidentActionRequest,
    _authorized: bool = Depends(validate_ingestion_api_key),
):
    try:
        incident = reopen_incident(
            incident_id=incident_id,
            reopened_by=request.actor,
            note=request.note,
        )

        return {
            "version": "v5",
            "status": "open",
            "incident_id": incident_id,
            "incident": incident,
        }
    except Exception as error:
        lifecycle_error_response(error)


@app.get("/v5/notifications", response_model=V5NotificationListResponse)
def v5_notifications(
    status: Optional[str] = None,
    channel: Optional[str] = None,
    event_type: Optional[str] = None,
    incident_id: Optional[str] = None,
    limit: int = Query(default=50, ge=1, le=500),
    _authorized: bool = Depends(validate_ingestion_api_key),
):
    return {
        "version": "v5",
        "limit": limit,
        "data": list_notification_events(
            status=status,
            channel=channel,
            event_type=event_type,
            incident_id=incident_id,
            limit=limit,
        ),
    }


@app.get("/v5/notifications/summary", response_model=V5NotificationSummaryResponse)
def v5_notifications_summary(
    _authorized: bool = Depends(validate_ingestion_api_key),
):
    return {
        "version": "v5",
        "data": get_notifications_summary(),
    }


@app.post("/v5/notifications/test-webhook")
def v5_test_webhook_notification(
    request: V5TestWebhookRequest,
    _authorized: bool = Depends(validate_ingestion_api_key),
):
    result = queue_test_webhook_notification(request.message)

    return {
        "version": "v5",
        **result,
    }


@app.get("/v5/tasks/{task_id}")
def v5_task_status(task_id: str):
    result = AsyncResult(task_id, app=celery_app)

    response = {
        "version": "v5",
        "task_id": task_id,
        "status": result.status,
        "ready": result.ready(),
    }

    if result.ready():
        response["result"] = result.result

    return response
