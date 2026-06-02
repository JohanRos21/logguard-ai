import os
import json
from typing import Any, Dict, List, Optional

import pandas as pd
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from backend.app.ml.predict_anomaly import predict_anomaly
from backend.app.ml.predict_sequence_transformer import predict_sequence


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