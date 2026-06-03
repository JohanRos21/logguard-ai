import hashlib
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from backend.app.database import get_db_session
from backend.app.db_models import IngestedLog, IngestedSequencePrediction
from backend.app.ml.predict_sequence_transformer import predict_sequence


MODEL_WINDOW_SIZE = 20
VALID_GROUP_BY = {"ip", "user_id"}


def serialize_value(value):
    if isinstance(value, datetime):
        return value.isoformat()

    return value


def serialize_prediction(row: IngestedSequencePrediction) -> Dict[str, Any]:
    data = {}

    for column in row.__table__.columns:
        value = getattr(row, column.name)
        data[column.name] = serialize_value(value)

    return data


def validate_group_by(group_by: str) -> str:
    if group_by not in VALID_GROUP_BY:
        raise ValueError("group_by debe ser 'ip' o 'user_id'.")

    return group_by


def validate_window_size(window_size: int) -> int:
    if window_size != MODEL_WINDOW_SIZE:
        raise ValueError("El Transformer actual solo acepta ventanas de 20 eventos.")

    return window_size


def get_group_column(group_by: str):
    validate_group_by(group_by)

    if group_by == "user_id":
        return IngestedLog.user_id

    return IngestedLog.ip


def sequence_to_text(values: List[Any]) -> str:
    return " ".join(str(value) for value in values)


def sequence_hash(entity_type: str, entity_id: str, logs: List[IngestedLog]) -> str:
    raw_value = "|".join([
        entity_type,
        str(entity_id),
        ",".join(str(log.id) for log in logs),
    ])

    return hashlib.sha256(raw_value.encode("utf-8")).hexdigest()


def get_window_source(logs: List[IngestedLog]) -> Optional[str]:
    sources = sorted({log.source for log in logs if log.source})

    if not sources:
        return None

    if len(sources) == 1:
        return sources[0]

    return "mixed"


def get_entity_rows(
    session: Session,
    group_by: str,
    source: Optional[str],
    limit_entities: Optional[int],
):
    group_column = get_group_column(group_by)

    query = (
        session.query(
            group_column.label("entity_id"),
            func.count(IngestedLog.id).label("total_logs"),
        )
        .filter(group_column.isnot(None))
        .filter(IngestedLog.timestamp.isnot(None))
    )

    if source:
        query = query.filter(IngestedLog.source == source)

    query = (
        query
        .group_by(group_column)
        .order_by(desc(func.count(IngestedLog.id)))
    )

    if limit_entities:
        query = query.limit(limit_entities)

    return query.all()


def get_logs_for_entity(
    session: Session,
    group_by: str,
    entity_id: str,
    source: Optional[str],
) -> List[IngestedLog]:
    group_column = get_group_column(group_by)

    query = (
        session.query(IngestedLog)
        .filter(group_column == entity_id)
        .filter(IngestedLog.timestamp.isnot(None))
    )

    if source:
        query = query.filter(IngestedLog.source == source)

    return (
        query
        .order_by(IngestedLog.timestamp.asc(), IngestedLog.id.asc())
        .all()
    )


def prediction_exists(session: Session, hash_value: str) -> bool:
    return (
        session.query(IngestedSequencePrediction.id)
        .filter(IngestedSequencePrediction.sequence_hash == hash_value)
        .first()
        is not None
    )


def build_insufficient_logs_result(
    entity_type: str,
    entity_id: str,
    window_size: int,
    available_logs: int,
) -> Dict[str, Any]:
    return {
        "status": "insufficient_logs",
        "entity_type": entity_type,
        "entity_id": str(entity_id),
        "required_window_size": window_size,
        "available_logs": available_logs,
    }


def build_duplicate_result(entity_type: str, entity_id: str) -> Dict[str, Any]:
    return {
        "status": "duplicate",
        "entity_type": entity_type,
        "entity_id": str(entity_id),
        "sequences_analyzed": 0,
        "anomalies_detected": 0,
        "skipped_duplicates": 1,
    }


def build_prediction_record(
    entity_type: str,
    entity_id: str,
    logs: List[IngestedLog],
    hash_value: str,
) -> IngestedSequencePrediction:
    event_sequence = [log.event_type for log in logs]
    route_sequence = [log.route for log in logs]
    status_sequence = [str(log.status_code) for log in logs]
    method_sequence = [log.method for log in logs]

    result = predict_sequence(
        event_sequence=event_sequence,
        route_sequence=route_sequence,
        status_sequence=status_sequence,
        method_sequence=method_sequence,
    )

    return IngestedSequencePrediction(
        sequence_hash=hash_value,
        entity_type=entity_type,
        entity_id=str(entity_id),
        start_time=logs[0].timestamp,
        end_time=logs[-1].timestamp,
        window_size=len(logs),
        event_sequence=sequence_to_text(event_sequence),
        route_sequence=sequence_to_text(route_sequence),
        status_sequence=sequence_to_text(status_sequence),
        method_sequence=sequence_to_text(method_sequence),
        ai_prediction=result["prediction"],
        anomaly_probability=result["anomaly_probability"],
        normal_probability=result["normal_probability"],
        final_severity=result.get("severity_suggestion", "normal"),
        source=get_window_source(logs),
    )


def analyze_recent_entity_sequences(
    session: Session,
    group_by: str = "ip",
    entity_id: Optional[str] = None,
    window_size: int = MODEL_WINDOW_SIZE,
    source: Optional[str] = None,
) -> Dict[str, Any]:
    group_by = validate_group_by(group_by)
    window_size = validate_window_size(window_size)

    if not entity_id:
        return build_insufficient_logs_result(
            entity_type=group_by,
            entity_id="",
            window_size=window_size,
            available_logs=0,
        )

    logs = get_logs_for_entity(
        session=session,
        group_by=group_by,
        entity_id=str(entity_id),
        source=source,
    )

    if len(logs) < window_size:
        return build_insufficient_logs_result(
            entity_type=group_by,
            entity_id=str(entity_id),
            window_size=window_size,
            available_logs=len(logs),
        )

    window_logs = logs[-window_size:]
    hash_value = sequence_hash(group_by, str(entity_id), window_logs)

    if prediction_exists(session, hash_value):
        return build_duplicate_result(
            entity_type=group_by,
            entity_id=str(entity_id),
        )

    record = build_prediction_record(
        entity_type=group_by,
        entity_id=str(entity_id),
        logs=window_logs,
        hash_value=hash_value,
    )

    session.add(record)

    anomalies_detected = 1 if record.ai_prediction == "anomaly" else 0

    return {
        "status": "analyzed",
        "entity_type": group_by,
        "entity_id": str(entity_id),
        "sequences_analyzed": 1,
        "anomalies_detected": anomalies_detected,
    }


def analyze_entities_after_ingestion(
    entity_ids: List[str],
    group_by: str = "ip",
    window_size: int = MODEL_WINDOW_SIZE,
    source: Optional[str] = None,
) -> Dict[str, int]:
    group_by = validate_group_by(group_by)
    window_size = validate_window_size(window_size)

    unique_entity_ids = sorted({str(entity_id) for entity_id in entity_ids if entity_id})
    summary = {
        "entities_checked": 0,
        "sequences_analyzed": 0,
        "anomalies_detected": 0,
        "skipped_insufficient_logs": 0,
        "skipped_duplicates": 0,
    }

    with get_db_session() as session:
        for entity_id in unique_entity_ids:
            summary["entities_checked"] += 1
            result = analyze_recent_entity_sequences(
                session=session,
                group_by=group_by,
                entity_id=entity_id,
                window_size=window_size,
                source=source,
            )

            if result["status"] == "insufficient_logs":
                summary["skipped_insufficient_logs"] += 1
                continue

            if result["status"] == "duplicate":
                summary["skipped_duplicates"] += 1
                continue

            summary["sequences_analyzed"] += result.get("sequences_analyzed", 0)
            summary["anomalies_detected"] += result.get("anomalies_detected", 0)

    return summary


def safe_analyze_recent_entity_after_ingestion(
    entity_id: Optional[str],
    group_by: str = "ip",
    window_size: int = MODEL_WINDOW_SIZE,
    source: Optional[str] = None,
) -> Dict[str, Any]:
    try:
        with get_db_session() as session:
            return analyze_recent_entity_sequences(
                session=session,
                group_by=group_by,
                entity_id=entity_id,
                window_size=window_size,
                source=source,
            )
    except Exception as error:
        return {
            "status": "failed",
            "entity_type": group_by,
            "entity_id": str(entity_id) if entity_id else "",
            "error": str(error)[:250],
        }


def safe_analyze_entities_after_ingestion(
    entity_ids: List[str],
    group_by: str = "ip",
    window_size: int = MODEL_WINDOW_SIZE,
    source: Optional[str] = None,
) -> Dict[str, Any]:
    try:
        return analyze_entities_after_ingestion(
            entity_ids=entity_ids,
            group_by=group_by,
            window_size=window_size,
            source=source,
        )
    except Exception as error:
        return {
            "status": "failed",
            "entities_checked": 0,
            "sequences_analyzed": 0,
            "anomalies_detected": 0,
            "skipped_insufficient_logs": 0,
            "skipped_duplicates": 0,
            "error": str(error)[:250],
        }


def analyze_ingested_sequences(
    group_by: str = "ip",
    window_size: int = MODEL_WINDOW_SIZE,
    limit_entities: Optional[int] = None,
    source: Optional[str] = None,
) -> Dict[str, int]:
    group_by = validate_group_by(group_by)
    window_size = validate_window_size(window_size)

    total_entities_checked = 0
    sequences_analyzed = 0
    anomalies_detected = 0
    skipped_insufficient_logs = 0
    skipped_duplicates = 0

    with get_db_session() as session:
        entity_rows = get_entity_rows(
            session=session,
            group_by=group_by,
            source=source,
            limit_entities=limit_entities,
        )

        for entity_id, _total_logs in entity_rows:
            total_entities_checked += 1
            logs = get_logs_for_entity(
                session=session,
                group_by=group_by,
                entity_id=entity_id,
                source=source,
            )

            if len(logs) < window_size:
                skipped_insufficient_logs += 1
                continue

            for start_index in range(0, len(logs) - window_size + 1):
                window_logs = logs[start_index:start_index + window_size]
                hash_value = sequence_hash(group_by, str(entity_id), window_logs)

                if prediction_exists(session, hash_value):
                    skipped_duplicates += 1
                    continue

                record = build_prediction_record(
                    entity_type=group_by,
                    entity_id=str(entity_id),
                    logs=window_logs,
                    hash_value=hash_value,
                )

                session.add(record)
                sequences_analyzed += 1

                if record.ai_prediction == "anomaly":
                    anomalies_detected += 1

    return {
        "total_entities_checked": total_entities_checked,
        "sequences_analyzed": sequences_analyzed,
        "anomalies_detected": anomalies_detected,
        "skipped_insufficient_logs": skipped_insufficient_logs,
        "skipped_duplicates": skipped_duplicates,
    }


def get_ingested_sequence_predictions(
    limit: int = 50,
    entity_id: Optional[str] = None,
    ai_prediction: Optional[str] = None,
    final_severity: Optional[str] = None,
    source: Optional[str] = None,
) -> List[Dict[str, Any]]:
    with get_db_session() as session:
        query = session.query(IngestedSequencePrediction)

        if entity_id:
            query = query.filter(IngestedSequencePrediction.entity_id == entity_id)

        if ai_prediction:
            query = query.filter(IngestedSequencePrediction.ai_prediction == ai_prediction)

        if final_severity:
            query = query.filter(IngestedSequencePrediction.final_severity == final_severity)

        if source:
            query = query.filter(IngestedSequencePrediction.source == source)

        rows = (
            query
            .order_by(desc(IngestedSequencePrediction.created_at))
            .limit(limit)
            .all()
        )

        return [serialize_prediction(row) for row in rows]


def group_counts(session: Session, model, column, limit: int = 10) -> Dict[str, int]:
    rows = (
        session.query(column, func.count(model.id))
        .group_by(column)
        .order_by(desc(func.count(model.id)))
        .limit(limit)
        .all()
    )

    return {str(key): count for key, count in rows if key is not None}


def count_table(session: Session, model) -> int:
    return session.query(func.count(model.id)).scalar() or 0


def get_real_monitoring_summary() -> Dict[str, Any]:
    with get_db_session() as session:
        anomalies_detected = (
            session.query(func.count(IngestedSequencePrediction.id))
            .filter(IngestedSequencePrediction.ai_prediction == "anomaly")
            .scalar()
            or 0
        )

        return {
            "total_ingested_logs": count_table(session, IngestedLog),
            "total_ingested_sequence_predictions": count_table(
                session,
                IngestedSequencePrediction,
            ),
            "anomalies_detected": anomalies_detected,
            "logs_by_event_type": group_counts(session, IngestedLog, IngestedLog.event_type),
            "logs_by_final_severity": group_counts(
                session,
                IngestedLog,
                IngestedLog.final_severity,
            ),
            "predictions_by_ai_prediction": group_counts(
                session,
                IngestedSequencePrediction,
                IngestedSequencePrediction.ai_prediction,
            ),
            "top_ips": group_counts(session, IngestedLog, IngestedLog.ip),
            "top_routes": group_counts(session, IngestedLog, IngestedLog.route),
        }
