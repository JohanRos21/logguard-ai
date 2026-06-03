import hashlib
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple

from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from backend.app.database import get_db_session
from backend.app.db_models import IngestedSequencePrediction, RealIncident


ADMIN_ROUTES = {
    "/dashboard/admin",
    "/api/admin/users",
    "/api/database",
}

PAYMENT_ROUTES = {
    "/api/payments",
}

DATABASE_ROUTES = {
    "/api/database",
}

TITLE_BY_TYPE = {
    "repeated_unauthorized_access": "Accesos no autorizados repetidos desde {entity_id}",
    "brute_force_suspected": "Posible fuerza bruta detectada desde {entity_id}",
    "admin_probe": "Exploracion de rutas administrativas desde {entity_id}",
    "payment_risk": "Riesgo en flujo de pagos detectado desde {entity_id}",
    "database_risk": "Riesgo de base de datos detectado desde {entity_id}",
    "performance_degradation": "Degradacion de rendimiento detectada desde {entity_id}",
    "generic_anomaly": "Comportamiento anomalo detectado desde {entity_id}",
}

RECOMMENDATION_BY_TYPE = {
    "repeated_unauthorized_access": (
        "Revisar sesiones activas, permisos, proteccion de rutas y reglas de acceso."
    ),
    "brute_force_suspected": (
        "Revisar rate limiting, bloqueo temporal, intentos fallidos y proteccion de credenciales."
    ),
    "admin_probe": (
        "Revisar accesos a rutas administrativas, permisos del usuario y posibles intentos de exploracion."
    ),
    "payment_risk": (
        "Revisar pasarela de pagos, webhooks, ordenes fallidas y validaciones de transaccion."
    ),
    "database_risk": (
        "Revisar disponibilidad de base de datos, timeouts, consultas lentas y conexiones."
    ),
    "performance_degradation": (
        "Revisar tiempos de respuesta, endpoints lentos, carga del servidor y consultas pesadas."
    ),
    "generic_anomaly": (
        "Revisar la secuencia de eventos asociada y validar si corresponde a comportamiento esperado."
    ),
}

SEVERITY_RANK = {
    "normal": 0,
    "warning": 1,
    "critical": 2,
}


def serialize_value(value):
    if isinstance(value, datetime):
        return value.isoformat()

    return value


def serialize_incident(row: RealIncident) -> Dict[str, Any]:
    data = {}

    for column in row.__table__.columns:
        value = getattr(row, column.name)
        data[column.name] = serialize_value(value)

    return data


def sequence_tokens(value: Optional[str]) -> List[str]:
    return [token.strip() for token in str(value or "").split() if token.strip()]


def normalize_token(value: str) -> str:
    return str(value or "").strip().lower()


def route_matches(routes: Iterable[str], patterns: Iterable[str]) -> bool:
    normalized_patterns = [pattern.lower().rstrip("/") for pattern in patterns]

    for route in routes:
        normalized_route = normalize_token(route).rstrip("/")

        if any(
            normalized_route == pattern
            or normalized_route.startswith(f"{pattern}/")
            for pattern in normalized_patterns
        ):
            return True

    return False


def count_statuses(statuses: Iterable[str], expected: Iterable[str]) -> int:
    expected_values = set(expected)

    return sum(1 for status in statuses if str(status) in expected_values)


def classify_incident_type(prediction: IngestedSequencePrediction) -> str:
    events = [normalize_token(event) for event in sequence_tokens(prediction.event_sequence)]
    routes = sequence_tokens(prediction.route_sequence)
    statuses = sequence_tokens(prediction.status_sequence)

    login_failed_count = events.count("login_failed")
    unauthorized_count = events.count("unauthorized_access")
    auth_status_count = count_statuses(statuses, {"401", "403"})
    slow_count = events.count("slow_response")

    if route_matches(routes, ADMIN_ROUTES):
        return "admin_probe"

    if "payment_failed" in events or route_matches(routes, PAYMENT_ROUTES):
        return "payment_risk"

    if "database_timeout" in events or route_matches(routes, DATABASE_ROUTES):
        return "database_risk"

    if (
        login_failed_count >= 5
        or auth_status_count >= 5
        or (login_failed_count >= 2 and unauthorized_count >= 1)
    ):
        return "brute_force_suspected"

    if unauthorized_count >= 2 or auth_status_count >= max(3, len(statuses) // 2):
        return "repeated_unauthorized_access"

    if slow_count >= 2:
        return "performance_degradation"

    return "generic_anomaly"


def normalize_severity(value: Optional[str]) -> str:
    severity = normalize_token(value)

    if severity in SEVERITY_RANK:
        return severity

    return "warning"


def highest_severity(values: Iterable[str]) -> str:
    return max(values, key=lambda severity: SEVERITY_RANK.get(severity, 0))


def infer_incident_severity(
    prediction: IngestedSequencePrediction,
    incident_type: str,
) -> str:
    prediction_severity = normalize_severity(prediction.final_severity)
    probability = float(prediction.anomaly_probability or 0.0)

    if prediction_severity == "critical":
        return "critical"

    if incident_type in {"admin_probe", "payment_risk", "database_risk"}:
        return "critical"

    if incident_type == "brute_force_suspected":
        return "critical" if probability >= 0.90 else "warning"

    if incident_type == "repeated_unauthorized_access":
        return "critical" if probability >= 0.90 else "warning"

    if incident_type == "performance_degradation":
        return "critical" if probability >= 0.95 else "warning"

    if incident_type == "generic_anomaly":
        return prediction_severity

    return "critical" if probability >= 0.90 else prediction_severity


def incident_hash(
    entity_type: str,
    entity_id: str,
    incident_type: str,
    source: Optional[str],
    occurrence_key: Optional[str] = None,
) -> str:
    parts = [
        entity_type,
        entity_id,
        incident_type,
        source or "unknown",
    ]

    if occurrence_key:
        parts.append(occurrence_key)

    raw_value = "|".join(parts)

    return hashlib.sha256(raw_value.encode("utf-8")).hexdigest()


def incident_id_from_hash(hash_value: str) -> str:
    return f"REAL-{hash_value[:12].upper()}"


def csv_to_set(value: Optional[str]) -> set:
    return {
        item.strip()
        for item in str(value or "").split(",")
        if item.strip()
    }


def values_to_csv(values: Iterable[Any]) -> str:
    return ", ".join(sorted({str(value) for value in values if value is not None and str(value)}))


def build_reason(
    incident_type: str,
    event_types: Iterable[str],
    routes: Iterable[str],
    max_probability: float,
) -> str:
    events_text = values_to_csv(event_types) or "sin eventos especificos"
    routes_text = values_to_csv(routes) or "sin rutas especificas"

    return (
        f"Predicciones reales del Transformer clasificadas como {incident_type}. "
        f"Probabilidad maxima de anomalia: {max_probability:.4f}. "
        f"Eventos relacionados: {events_text}. Rutas relacionadas: {routes_text}."
    )


def aggregate_predictions(
    predictions: List[IngestedSequencePrediction],
    incident_type: str,
) -> Dict[str, Any]:
    first_prediction = predictions[0]
    sequence_ids = {str(prediction.id) for prediction in predictions}
    event_types = set()
    routes = set()
    severities = []
    events_count = 0

    for prediction in predictions:
        events = [normalize_token(event) for event in sequence_tokens(prediction.event_sequence)]
        prediction_routes = sequence_tokens(prediction.route_sequence)

        event_types.update(events)
        routes.update(prediction_routes)
        events_count += len(events)
        severities.append(infer_incident_severity(prediction, incident_type))

    max_probability = max(float(prediction.anomaly_probability or 0.0) for prediction in predictions)
    first_seen = min(prediction.start_time for prediction in predictions if prediction.start_time)
    last_seen = max(prediction.end_time for prediction in predictions if prediction.end_time)
    entity_id = str(first_prediction.entity_id)

    return {
        "title": TITLE_BY_TYPE[incident_type].format(entity_id=entity_id),
        "incident_type": incident_type,
        "severity": highest_severity(severities),
        "status": "open",
        "entity_type": first_prediction.entity_type,
        "entity_id": entity_id,
        "source": first_prediction.source,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "events_count": events_count,
        "sequences_count": len(sequence_ids),
        "max_anomaly_probability": max_probability,
        "related_routes": values_to_csv(routes),
        "related_event_types": values_to_csv(event_types),
        "related_sequence_ids": values_to_csv(sequence_ids),
        "reason": build_reason(
            incident_type=incident_type,
            event_types=event_types,
            routes=routes,
            max_probability=max_probability,
        ),
        "recommendation": RECOMMENDATION_BY_TYPE[incident_type],
    }


def create_incident(
    session: Session,
    hash_value: str,
    aggregate: Dict[str, Any],
) -> None:
    incident = RealIncident(
        incident_id=incident_id_from_hash(hash_value),
        incident_hash=hash_value,
        **aggregate,
    )

    session.add(incident)


def update_incident(
    incident: RealIncident,
    new_predictions: List[IngestedSequencePrediction],
    incident_type: str,
) -> None:
    aggregate = aggregate_predictions(new_predictions, incident_type)
    existing_sequence_ids = csv_to_set(incident.related_sequence_ids)
    new_sequence_ids = csv_to_set(aggregate["related_sequence_ids"])

    incident.status = "open"
    incident.severity = highest_severity([incident.severity, aggregate["severity"]])
    incident.first_seen = min(
        value
        for value in [incident.first_seen, aggregate["first_seen"]]
        if value is not None
    )
    incident.last_seen = max(
        value
        for value in [incident.last_seen, aggregate["last_seen"]]
        if value is not None
    )
    incident.events_count = int(incident.events_count or 0) + int(aggregate["events_count"] or 0)
    incident.sequences_count = len(existing_sequence_ids | new_sequence_ids)
    incident.max_anomaly_probability = max(
        float(incident.max_anomaly_probability or 0.0),
        float(aggregate["max_anomaly_probability"] or 0.0),
    )
    incident.related_routes = values_to_csv(
        csv_to_set(incident.related_routes) | csv_to_set(aggregate["related_routes"])
    )
    incident.related_event_types = values_to_csv(
        csv_to_set(incident.related_event_types) | csv_to_set(aggregate["related_event_types"])
    )
    incident.related_sequence_ids = values_to_csv(existing_sequence_ids | new_sequence_ids)
    incident.reason = build_reason(
        incident_type=incident.incident_type,
        event_types=csv_to_set(incident.related_event_types),
        routes=csv_to_set(incident.related_routes),
        max_probability=incident.max_anomaly_probability or 0.0,
    )
    incident.recommendation = RECOMMENDATION_BY_TYPE[incident.incident_type]
    incident.updated_at = datetime.utcnow()


def group_key(prediction: IngestedSequencePrediction) -> Tuple[str, str, str, str]:
    incident_type = classify_incident_type(prediction)

    return (
        prediction.entity_type,
        str(prediction.entity_id),
        incident_type,
        prediction.source or "unknown",
    )


def matching_incidents_query(
    session: Session,
    entity_type: str,
    entity_id: str,
    incident_type: str,
    source: str,
):
    query = session.query(RealIncident).filter(
        RealIncident.entity_type == entity_type,
        RealIncident.entity_id == entity_id,
        RealIncident.incident_type == incident_type,
    )

    if source == "unknown":
        return query.filter(RealIncident.source.is_(None))

    return query.filter(RealIncident.source == source)


def incident_sequence_ids(incidents: List[RealIncident]) -> set:
    known_sequence_ids = set()

    for incident in incidents:
        known_sequence_ids.update(csv_to_set(incident.related_sequence_ids))

    return known_sequence_ids


def generate_real_incidents(
    entity_type: Optional[str] = None,
    entity_id: Optional[str] = None,
    entity_ids: Optional[List[str]] = None,
    source: Optional[str] = None,
    limit: Optional[int] = None,
) -> Dict[str, int]:
    stats = {
        "predictions_checked": 0,
        "incidents_created": 0,
        "incidents_updated": 0,
        "skipped_non_anomalies": 0,
        "skipped_duplicates": 0,
    }

    with get_db_session() as session:
        query = session.query(IngestedSequencePrediction)

        if entity_type:
            query = query.filter(IngestedSequencePrediction.entity_type == entity_type)

        if entity_id:
            query = query.filter(IngestedSequencePrediction.entity_id == entity_id)

        if entity_ids:
            query = query.filter(IngestedSequencePrediction.entity_id.in_(entity_ids))

        if source:
            query = query.filter(IngestedSequencePrediction.source == source)

        query = query.order_by(IngestedSequencePrediction.start_time.asc(), IngestedSequencePrediction.id.asc())

        if limit:
            query = query.limit(limit)

        grouped_predictions = defaultdict(list)

        for prediction in query.all():
            stats["predictions_checked"] += 1

            if prediction.ai_prediction != "anomaly":
                stats["skipped_non_anomalies"] += 1
                continue

            grouped_predictions[group_key(prediction)].append(prediction)

        for key, predictions in grouped_predictions.items():
            grouped_entity_type, grouped_entity_id, incident_type, grouped_source = key

            matching_incidents = (
                matching_incidents_query(
                    session=session,
                    entity_type=grouped_entity_type,
                    entity_id=grouped_entity_id,
                    incident_type=incident_type,
                    source=grouped_source,
                )
                .order_by(desc(RealIncident.created_at))
                .all()
            )
            active_incident = next(
                (
                    incident
                    for incident in matching_incidents
                    if incident.status in {"open", "acknowledged"}
                ),
                None,
            )
            known_sequence_ids = incident_sequence_ids(matching_incidents)

            if not matching_incidents:
                aggregate = aggregate_predictions(predictions, incident_type)
                create_incident(
                    session=session,
                    hash_value=incident_hash(
                        entity_type=grouped_entity_type,
                        entity_id=grouped_entity_id,
                        incident_type=incident_type,
                        source=grouped_source,
                    ),
                    aggregate=aggregate,
                )
                stats["incidents_created"] += 1
                continue

            new_predictions = [
                prediction
                for prediction in predictions
                if str(prediction.id) not in known_sequence_ids
            ]

            if not new_predictions:
                stats["skipped_duplicates"] += len(predictions)
                continue

            if active_incident is not None:
                update_incident(active_incident, new_predictions, incident_type)
                stats["incidents_updated"] += 1
                continue

            occurrence_key = values_to_csv(str(prediction.id) for prediction in new_predictions)
            aggregate = aggregate_predictions(new_predictions, incident_type)
            create_incident(
                session=session,
                hash_value=incident_hash(
                    entity_type=grouped_entity_type,
                    entity_id=grouped_entity_id,
                    incident_type=incident_type,
                    source=grouped_source,
                    occurrence_key=occurrence_key,
                ),
                aggregate=aggregate,
            )
            stats["incidents_created"] += 1

    return stats


def safe_generate_real_incidents_for_entity(
    entity_type: str,
    entity_id: Optional[str],
    source: Optional[str] = None,
) -> Dict[str, Any]:
    try:
        return generate_real_incidents(
            entity_type=entity_type,
            entity_id=str(entity_id) if entity_id else None,
            source=source,
        )
    except Exception as error:
        return {
            "status": "failed",
            "predictions_checked": 0,
            "incidents_created": 0,
            "incidents_updated": 0,
            "skipped_non_anomalies": 0,
            "skipped_duplicates": 0,
            "error": str(error)[:250],
        }


def safe_generate_real_incidents_for_entities(
    entity_type: str,
    entity_ids: List[str],
    source: Optional[str] = None,
) -> Dict[str, Any]:
    try:
        return generate_real_incidents(
            entity_type=entity_type,
            entity_ids=sorted({str(entity_id) for entity_id in entity_ids if entity_id}),
            source=source,
        )
    except Exception as error:
        return {
            "status": "failed",
            "predictions_checked": 0,
            "incidents_created": 0,
            "incidents_updated": 0,
            "skipped_non_anomalies": 0,
            "skipped_duplicates": 0,
            "error": str(error)[:250],
        }


def get_real_incidents(
    limit: int = 50,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    incident_type: Optional[str] = None,
    entity_id: Optional[str] = None,
    source: Optional[str] = None,
) -> List[Dict[str, Any]]:
    with get_db_session() as session:
        query = session.query(RealIncident)

        if severity:
            query = query.filter(RealIncident.severity == severity)

        if status:
            query = query.filter(RealIncident.status == status)

        if incident_type:
            query = query.filter(RealIncident.incident_type == incident_type)

        if entity_id:
            query = query.filter(RealIncident.entity_id == entity_id)

        if source:
            query = query.filter(RealIncident.source == source)

        rows = (
            query
            .order_by(desc(RealIncident.last_seen), desc(RealIncident.created_at))
            .limit(limit)
            .all()
        )

        return [serialize_incident(row) for row in rows]


def count_table(session: Session, model) -> int:
    return session.query(func.count(model.id)).scalar() or 0


def group_counts(session: Session, column, limit: int = 10) -> Dict[str, int]:
    rows = (
        session.query(column, func.count(RealIncident.id))
        .group_by(column)
        .order_by(desc(func.count(RealIncident.id)))
        .limit(limit)
        .all()
    )

    return {str(key): count for key, count in rows if key is not None}


def get_real_incidents_summary() -> Dict[str, Any]:
    with get_db_session() as session:
        open_incidents = (
            session.query(func.count(RealIncident.id))
            .filter(RealIncident.status == "open")
            .scalar()
            or 0
        )
        critical_incidents = (
            session.query(func.count(RealIncident.id))
            .filter(RealIncident.severity == "critical")
            .scalar()
            or 0
        )

        return {
            "total_real_incidents": count_table(session, RealIncident),
            "open_incidents": open_incidents,
            "critical_incidents": critical_incidents,
            "incidents_by_type": group_counts(session, RealIncident.incident_type),
            "incidents_by_severity": group_counts(session, RealIncident.severity),
            "incidents_by_status": group_counts(session, RealIncident.status),
            "top_entities": group_counts(session, RealIncident.entity_id),
            "top_sources": group_counts(session, RealIncident.source),
        }
