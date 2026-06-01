import os
import json
import pandas as pd


RULE_ALERTS_PATH = "reports/rule_alerts.csv"
ML_ANOMALIES_PATH = "reports/ml_anomalies.csv"

FINAL_INCIDENTS_CSV_PATH = "reports/final_incidents.csv"
FINAL_INCIDENTS_JSON_PATH = "reports/final_incidents.json"
INCIDENT_SUMMARY_PATH = "reports/incident_summary.json"


SEVERITY_RANK = {
    "normal": 0,
    "warning": 1,
    "critical": 2,
}


def load_csv_if_exists(path):
    if not os.path.exists(path):
        return pd.DataFrame()

    return pd.read_csv(path, encoding="utf-8-sig")


def normalize_severity(severity):
    severity = str(severity).lower().strip()

    if severity not in SEVERITY_RANK:
        return "warning"

    return severity


def infer_ml_severity(row):
    """
    El modelo Isolation Forest solo responde si un log parece normal o anómalo.
    Pero eso no significa que sepa si el impacto real es warning o critical.

    Por ejemplo:
    - Un log raro en una ruta normal puede ser warning.
    - Un log raro en pagos, base de datos o una ruta crítica puede ser critical.

    Por eso aquí combinamos:
    - anomaly_score del modelo ML
    - risk_score calculado en el procesamiento
    - si la ruta es crítica
    - si hubo error 500
    - si es pago fallido
    - si es timeout de base de datos
    - si es acceso no autorizado
    """

    risk_score = int(row.get("risk_score", 0))
    anomaly_score = float(row.get("anomaly_score", 0))

    is_critical_route = int(row.get("is_critical_route", 0))
    is_server_error = int(row.get("is_server_error", 0))
    is_payment_failed = int(row.get("is_payment_failed", 0))
    is_database_timeout = int(row.get("is_database_timeout", 0))
    is_very_slow = int(row.get("is_very_slow", 0))
    is_unauthorized = int(row.get("is_unauthorized", 0))

    critical_business_condition = (
        is_critical_route == 1
        and (
            is_server_error == 1
            or is_payment_failed == 1
            or is_database_timeout == 1
            or is_very_slow == 1
        )
    )

    security_condition = is_unauthorized == 1 and risk_score >= 10

    if risk_score >= 18 or critical_business_condition or security_condition:
        return "critical"

    if risk_score >= 10:
        return "warning"

    if anomaly_score < -0.12:
        return "warning"

    return "warning"


def create_event_from_rule(row):
    """
    Convierte una alerta generada por el motor de reglas en un evento de detección.

    Importante:
    Todavía no lo llamamos incidente final porque puede haber muchas alertas
    relacionadas al mismo problema. Primero se recolectan como evidencias.
    """

    severity = normalize_severity(row.get("severity", "warning"))

    return {
        "source": "rule_engine",
        "severity": severity,
        "severity_rank": SEVERITY_RANK[severity],
        "detection_type": row.get("alert_type", "rule_alert"),
        "timestamp": row.get("timestamp"),
        "user_id": row.get("user_id"),
        "ip": row.get("ip"),
        "method": row.get("method"),
        "route": row.get("route"),
        "status_code": int(row.get("status_code", 0)),
        "response_time_ms": float(row.get("response_time_ms", 0)),
        "event_type": row.get("event_type"),
        "risk_score": int(row.get("risk_score", 0)),
        "anomaly_score": None,
        "reason": row.get("reason"),
        "recommendation": row.get("recommendation"),
    }


def build_ml_reason(row, severity):
    route = row.get("route", "unknown")
    event_type = row.get("event_type", "unknown")
    risk_score = int(row.get("risk_score", 0))
    anomaly_score = float(row.get("anomaly_score", 0))

    if severity == "critical":
        return (
            f"El modelo ML detectó un comportamiento anómalo en {route}. "
            f"El evento {event_type} presenta posible impacto crítico "
            f"según risk_score={risk_score} y anomaly_score={anomaly_score:.4f}."
        )

    return (
        f"El modelo ML detectó un comportamiento inusual en {route}. "
        f"Evento: {event_type}. risk_score={risk_score}, anomaly_score={anomaly_score:.4f}."
    )


def build_ml_recommendation(row, severity):
    route = str(row.get("route", ""))
    event_type = str(row.get("event_type", ""))

    if severity == "critical":
        if "payment" in event_type or "payments" in route:
            return "Revisar pasarela de pagos, errores del backend, webhooks y disponibilidad del servicio."

        if "database" in event_type or "database" in route:
            return "Revisar conexión a base de datos, consultas lentas, índices y carga del servidor."

        if "login" in event_type or "unauthorized" in event_type:
            return "Revisar IPs sospechosas, sesiones, permisos y posibles intentos de acceso no autorizado."

        return "Revisar el evento de forma prioritaria y validar si corresponde a un incidente activo."

    return "Monitorear si el patrón se repite y revisar logs relacionados del mismo usuario, IP o ruta."


def create_event_from_ml(row):
    """
    Convierte una anomalía detectada por IA en un evento de detección.

    El ML aporta una evidencia diferente a las reglas:
    - Las reglas detectan casos explícitos.
    - El modelo detecta comportamiento raro respecto al patrón general.

    Luego ambas fuentes se combinan en incidentes consolidados.
    """

    severity = infer_ml_severity(row)

    return {
        "source": "ml_anomaly_detector",
        "severity": severity,
        "severity_rank": SEVERITY_RANK[severity],
        "detection_type": "ml_anomaly",
        "timestamp": row.get("timestamp"),
        "user_id": row.get("user_id"),
        "ip": row.get("ip"),
        "method": row.get("method"),
        "route": row.get("route"),
        "status_code": int(row.get("status_code", 0)),
        "response_time_ms": float(row.get("response_time_ms", 0)),
        "event_type": row.get("event_type"),
        "risk_score": int(row.get("risk_score", 0)),
        "anomaly_score": float(row.get("anomaly_score", 0)),
        "reason": build_ml_reason(row, severity),
        "recommendation": build_ml_recommendation(row, severity),
    }


def collect_detection_events(rule_alerts_df, ml_anomalies_df):
    """
    Junta todas las detecciones del sistema.

    Aquí todavía no estamos agrupando.
    Solo convertimos:
    - alertas del motor de reglas
    - anomalías del modelo ML

    en un formato común llamado detection event.
    """

    events = []

    if not rule_alerts_df.empty:
        for _, row in rule_alerts_df.iterrows():
            events.append(create_event_from_rule(row))

    if not ml_anomalies_df.empty:
        for _, row in ml_anomalies_df.iterrows():
            events.append(create_event_from_ml(row))

    events_df = pd.DataFrame(events)

    if events_df.empty:
        return events_df

    # Quitamos duplicados exactos dentro de la misma fuente.
    # No eliminamos coincidencias entre rule_engine y ML porque ambas evidencias son útiles.
    events_df = events_df.drop_duplicates(
        subset=[
            "source",
            "detection_type",
            "timestamp",
            "ip",
            "route",
            "event_type",
        ]
    ).reset_index(drop=True)

    return events_df


def add_grouping_fields(events_df):
    df = events_df.copy()

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    """
    El problema que vimos:
    Un mismo fallo en /api/payments generaba muchas filas:
    - error 500
    - pago fallido
    - ruta crítica lenta
    - high risk score
    - anomalía ML

    Técnicamente son alertas distintas, pero para un dashboard o reporte
    deben verse como un solo incidente consolidado.

    Por eso usamos una ventana de tiempo de 10 minutos.
    Todas las detecciones parecidas dentro de esa ventana se agrupan.
    """
    df["time_window"] = df["timestamp"].dt.floor("10min")

    """
    La clave de agrupación define cuándo varias detecciones pertenecen
    al mismo incidente.

    Agrupamos por:
    - ruta
    - IP
    - tipo de evento
    - ventana de tiempo

    Esto reduce ruido, pero conserva contexto suficiente para investigar.
    """
    df["group_key"] = (
        df["route"].astype(str)
        + "|"
        + df["ip"].astype(str)
        + "|"
        + df["event_type"].astype(str)
        + "|"
        + df["time_window"].astype(str)
    )

    return df


def choose_incident_type(detection_types):
    """
    Un incidente consolidado puede tener muchas evidencias.
    Por ejemplo:
    - critical_route_server_error
    - payment_failure_outage
    - high_risk_score
    - ml_anomaly

    Esta función elige el tipo principal del incidente.
    Se priorizan los tipos más importantes para negocio y seguridad.
    """

    detection_types = set(detection_types)

    priority_order = [
        "payment_failure_outage",
        "database_timeout",
        "critical_route_server_error",
        "critical_route_very_slow",
        "brute_force_attempt",
        "repeated_unauthorized_access",
        "unauthorized_admin_access",
        "high_risk_score",
        "ml_anomaly",
        "medium_risk_score",
        "slow_response",
        "single_payment_failure",
        "multiple_failed_logins_user",
    ]

    for item in priority_order:
        if item in detection_types:
            return item

    return list(detection_types)[0] if detection_types else "incident"


def choose_recommendation(group):
    """
    Si el grupo tiene eventos críticos, usamos la recomendación de uno crítico.
    Si no, usamos la primera recomendación disponible.

    Esto evita que un incidente crítico termine con una recomendación débil.
    """

    critical_rows = group[group["severity"] == "critical"]

    if not critical_rows.empty:
        return critical_rows.iloc[0]["recommendation"]

    return group.iloc[0]["recommendation"]


def build_group_reason(group, incident_type, severity):
    route = group["route"].iloc[0]
    event_type = group["event_type"].iloc[0]
    total_events = len(group)

    detection_types = sorted(group["detection_type"].dropna().unique().tolist())
    sources = sorted(group["source"].dropna().unique().tolist())

    return (
        f"Se consolidaron {total_events} detecciones relacionadas en {route}. "
        f"Evento principal: {event_type}. "
        f"Tipo de incidente: {incident_type}. "
        f"Severidad final: {severity}. "
        f"Fuentes: {', '.join(sources)}. "
        f"Evidencias: {', '.join(detection_types)}."
    )


def consolidate_incidents(events_df):
    """
    Convierte muchas detecciones individuales en incidentes finales.

    Esta es la parte central del Alert Manager:
    - recibe eventos de reglas e IA
    - agrupa eventos relacionados
    - elige severidad final
    - elige tipo principal del incidente
    - conserva evidencias
    - ordena por prioridad

    Sin este paso, el sistema sería demasiado ruidoso.
    """

    if events_df.empty:
        return pd.DataFrame()

    df = add_grouping_fields(events_df)

    incidents = []

    for _, group in df.groupby("group_key"):
        max_severity_rank = int(group["severity_rank"].max())
        severity = "critical" if max_severity_rank == 2 else "warning"

        detection_types = group["detection_type"].dropna().unique().tolist()
        sources = group["source"].dropna().unique().tolist()

        incident_type = choose_incident_type(detection_types)

        # El peor caso del grupo representa la prioridad real del incidente.
        max_risk_score = int(group["risk_score"].max())
        max_response_time = float(group["response_time_ms"].max())

        anomaly_scores = group["anomaly_score"].dropna()
        min_anomaly_score = float(anomaly_scores.min()) if not anomaly_scores.empty else None

        first_timestamp = group["timestamp"].min()
        last_timestamp = group["timestamp"].max()

        representative = group.sort_values(
            by=["severity_rank", "risk_score", "response_time_ms"],
            ascending=[False, False, False]
        ).iloc[0]

        incidents.append({
            "severity": severity,
            "severity_rank": max_severity_rank,
            "incident_type": incident_type,
            "sources": ", ".join(sorted(sources)),
            "detection_types": ", ".join(sorted(detection_types)),
            "first_seen": first_timestamp,
            "last_seen": last_timestamp,
            "events_count": int(len(group)),
            "user_id": representative["user_id"],
            "ip": representative["ip"],
            "method": representative["method"],
            "route": representative["route"],
            "status_code": int(representative["status_code"]),
            "max_response_time_ms": max_response_time,
            "event_type": representative["event_type"],
            "max_risk_score": max_risk_score,
            "min_anomaly_score": min_anomaly_score,
            "reason": build_group_reason(group, incident_type, severity),
            "recommendation": choose_recommendation(group),
        })

    incidents_df = pd.DataFrame(incidents)

    # Ordenamos para que lo más urgente aparezca arriba:
    # primero critical, luego mayor risk_score, más eventos y más lentitud.
    incidents_df = incidents_df.sort_values(
        by=["severity_rank", "max_risk_score", "events_count", "max_response_time_ms"],
        ascending=[False, False, False, False]
    ).reset_index(drop=True)

    incidents_df.insert(
        0,
        "incident_id",
        [f"INC-{i + 1:05d}" for i in range(len(incidents_df))]
    )

    return incidents_df


def build_summary(incidents_df):
    if incidents_df.empty:
        return {
            "total_incidents": 0,
            "by_severity": {},
            "by_type": {},
            "by_sources": {},
            "top_routes": {},
            "top_ips": {},
        }

    return {
        "total_incidents": int(len(incidents_df)),
        "by_severity": incidents_df["severity"].value_counts().to_dict(),
        "by_type": incidents_df["incident_type"].value_counts().head(20).to_dict(),
        "by_sources": incidents_df["sources"].value_counts().head(20).to_dict(),
        "top_routes": incidents_df["route"].value_counts().head(10).to_dict(),
        "top_ips": incidents_df["ip"].value_counts().head(10).to_dict(),
    }


def save_outputs(incidents_df, summary):
    os.makedirs("reports", exist_ok=True)

    incidents_df.to_csv(
        FINAL_INCIDENTS_CSV_PATH,
        index=False,
        encoding="utf-8-sig"
    )

    with open(FINAL_INCIDENTS_JSON_PATH, "w", encoding="utf-8") as file:
        json.dump(
            incidents_df.to_dict(orient="records"),
            file,
            indent=4,
            ensure_ascii=False,
            default=str
        )

    with open(INCIDENT_SUMMARY_PATH, "w", encoding="utf-8") as file:
        json.dump(summary, file, indent=4, ensure_ascii=False)


def run_alert_manager():
    rule_alerts_df = load_csv_if_exists(RULE_ALERTS_PATH)
    ml_anomalies_df = load_csv_if_exists(ML_ANOMALIES_PATH)

    if rule_alerts_df.empty and ml_anomalies_df.empty:
        raise FileNotFoundError(
            "No se encontraron alertas ni anomalías. "
            "Ejecuta primero rule_engine_service.py y train_anomaly_model.py"
        )

    events_df = collect_detection_events(rule_alerts_df, ml_anomalies_df)
    incidents_df = consolidate_incidents(events_df)
    summary = build_summary(incidents_df)

    save_outputs(incidents_df, summary)

    return incidents_df, summary


def main():
    incidents_df, summary = run_alert_manager()

    print(f"Incidentes CSV guardados en: {FINAL_INCIDENTS_CSV_PATH}")
    print(f"Incidentes JSON guardados en: {FINAL_INCIDENTS_JSON_PATH}")
    print(f"Resumen guardado en: {INCIDENT_SUMMARY_PATH}")

    print("\nResumen:")
    print(json.dumps(summary, indent=4, ensure_ascii=False))

    if not incidents_df.empty:
        print("\nTop 10 incidentes consolidados:")
        columns = [
            "incident_id",
            "severity",
            "incident_type",
            "sources",
            "route",
            "event_type",
            "events_count",
            "max_risk_score",
            "min_anomaly_score",
        ]

        print(incidents_df[columns].head(10).to_string(index=False))


if __name__ == "__main__":
    main()