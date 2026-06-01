import os
import json
from typing import Any, Dict, Optional

import pandas as pd
from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

from backend.app.ml.predict_anomaly import predict_anomaly


RULE_ALERTS_PATH = "reports/rule_alerts.csv"
ML_ANOMALIES_PATH = "reports/ml_anomalies.csv"
FINAL_INCIDENTS_PATH = "reports/final_incidents.csv"
INCIDENT_SUMMARY_PATH = "reports/incident_summary.json"
ANOMALY_REPORT_PATH = "reports/anomaly_detection_report.json"


app = FastAPI(
    title="LogGuard AI",
    description="API para monitoreo, detección de anomalías y gestión de incidentes en logs web.",
    version="1.0.0"
)


class LogFeaturesInput(BaseModel):
    features: Dict[str, Any]


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

    df = pd.read_csv(path, encoding="utf-8-sig")
    return df


def dataframe_to_records(
    df: pd.DataFrame,
    limit: int,
    severity: Optional[str] = None,
    route: Optional[str] = None,
):
    if severity:
        df = df[df["severity"].astype(str).str.lower() == severity.lower()]

    if route:
        df = df[df["route"].astype(str) == route]

    df = df.head(limit)

    return df.to_dict(orient="records")


def infer_final_severity_from_features(features: Dict[str, Any], ml_result: Dict[str, Any]):
    """
    La IA detecta si algo es anómalo, pero la severidad final también depende
    del impacto operativo. Por eso combinamos el resultado ML con señales como
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


@app.get("/")
def root():
    return {
        "project": "LogGuard AI",
        "status": "running",
        "description": "Sistema inteligente de detección de anomalías e incidentes en logs web.",
        "version": "1.0.0"
    }


@app.get("/health")
def health_check():
    return {
        "status": "ok",
        "message": "LogGuard AI API funcionando correctamente."
    }


@app.get("/metrics")
def get_metrics():
    incident_summary = read_json_file(INCIDENT_SUMMARY_PATH)
    anomaly_report = read_json_file(ANOMALY_REPORT_PATH)

    return {
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
    Este endpoint analiza un log nuevo usando el modelo ya entrenado.

    En la v1 recibe features ya procesadas, no un log crudo.
    Eso mantiene la API simple y consistente con el entrenamiento del modelo.
    En una v2 podríamos agregar un endpoint que reciba logs crudos y los procese automáticamente.
    """

    try:
        ml_result = predict_anomaly(payload.features)
        final_severity = infer_final_severity_from_features(payload.features, ml_result)

        return {
            "ml_result": ml_result,
            "final_severity": final_severity,
            "recommendation": build_recommendation(payload.features, final_severity)
        }

    except Exception as error:
        raise HTTPException(
            status_code=400,
            detail=str(error)
        )