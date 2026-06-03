from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy import desc, func

from backend.app.database import get_db_session
from backend.app.db_models import (
    FinalIncident,
    LogSequence,
    ModelMetric,
    ProcessedLog,
    SequencePrediction,
)


def serialize_value(value):
    if isinstance(value, datetime):
        return value.isoformat()

    return value


def serialize_model(instance) -> Dict[str, Any]:
    data = {}

    for column in instance.__table__.columns:
        value = getattr(instance, column.name)
        data[column.name] = serialize_value(value)

    return data


def count_table(session, model):
    return session.query(func.count(model.id)).scalar()


def get_group_counts(session, model, column, limit: int = 10):
    rows = (
        session.query(column, func.count(model.id))
        .group_by(column)
        .order_by(desc(func.count(model.id)))
        .limit(limit)
        .all()
    )

    return {
        str(key): count
        for key, count in rows
        if key is not None
    }


def get_prediction_confusion_matrix(session):
    """
    Calcula matriz de confusión desde la tabla sequence_predictions.

    label_id:
    0 = normal
    1 = anomaly

    predicted_label_id:
    0 = normal
    1 = anomaly
    """

    rows = session.query(
        SequencePrediction.label_id,
        SequencePrediction.predicted_label_id,
        func.count(SequencePrediction.id),
    ).group_by(
        SequencePrediction.label_id,
        SequencePrediction.predicted_label_id,
    ).all()

    matrix = {
        "true_normal_pred_normal": 0,
        "true_normal_pred_anomaly": 0,
        "true_anomaly_pred_normal": 0,
        "true_anomaly_pred_anomaly": 0,
    }

    for label_id, predicted_label_id, count in rows:
        if label_id == 0 and predicted_label_id == 0:
            matrix["true_normal_pred_normal"] = count
        elif label_id == 0 and predicted_label_id == 1:
            matrix["true_normal_pred_anomaly"] = count
        elif label_id == 1 and predicted_label_id == 0:
            matrix["true_anomaly_pred_normal"] = count
        elif label_id == 1 and predicted_label_id == 1:
            matrix["true_anomaly_pred_anomaly"] = count

    return matrix


def get_v3_summary():
    with get_db_session() as session:
        transformer_metrics = (
            session.query(ModelMetric)
            .filter(ModelMetric.model_name == "LogSequenceTransformer")
            .order_by(desc(ModelMetric.created_at))
            .first()
        )

        sequence_dataset_metrics = (
            session.query(ModelMetric)
            .filter(ModelMetric.model_name == "Sequence Dataset")
            .order_by(desc(ModelMetric.created_at))
            .first()
        )

        return {
            "version": "v3",
            "storage": "PostgreSQL",
            "totals": {
                "processed_logs": count_table(session, ProcessedLog),
                "log_sequences": count_table(session, LogSequence),
                "sequence_predictions": count_table(session, SequencePrediction),
                "final_incidents": count_table(session, FinalIncident),
                "model_metrics": count_table(session, ModelMetric),
            },
            "distributions": {
                "logs_by_severity": get_group_counts(session, ProcessedLog, ProcessedLog.severity),
                "sequences_by_label": get_group_counts(session, LogSequence, LogSequence.label),
                "predictions_by_label": get_group_counts(session, SequencePrediction, SequencePrediction.predicted_label),
                "incidents_by_severity": get_group_counts(session, FinalIncident, FinalIncident.severity),
                "top_routes": get_group_counts(session, ProcessedLog, ProcessedLog.route),
                "top_event_types": get_group_counts(session, ProcessedLog, ProcessedLog.event_type),
            },
            "transformer_metrics": transformer_metrics.metrics_json if transformer_metrics else None,
            "sequence_dataset_report": sequence_dataset_metrics.metrics_json if sequence_dataset_metrics else None,
            "confusion_matrix_from_db": get_prediction_confusion_matrix(session),
        }


def get_v3_logs(
    limit: int = 50,
    severity: Optional[str] = None,
    route: Optional[str] = None,
    event_type: Optional[str] = None,
):
    with get_db_session() as session:
        query = session.query(ProcessedLog)

        if severity:
            query = query.filter(ProcessedLog.severity == severity)

        if route:
            query = query.filter(ProcessedLog.route == route)

        if event_type:
            query = query.filter(ProcessedLog.event_type == event_type)

        rows = (
            query
            .order_by(desc(ProcessedLog.timestamp))
            .limit(limit)
            .all()
        )

        return [serialize_model(row) for row in rows]


def get_v3_sequences(
    limit: int = 50,
    label: Optional[str] = None,
    entity_id: Optional[str] = None,
):
    with get_db_session() as session:
        query = session.query(LogSequence)

        if label:
            query = query.filter(LogSequence.label == label)

        if entity_id:
            query = query.filter(LogSequence.entity_id == entity_id)

        rows = (
            query
            .order_by(desc(LogSequence.start_time))
            .limit(limit)
            .all()
        )

        return [serialize_model(row) for row in rows]


def get_v3_predictions(
    limit: int = 50,
    label: Optional[str] = None,
    predicted_label: Optional[str] = None,
    only_errors: bool = False,
):
    with get_db_session() as session:
        query = session.query(SequencePrediction)

        if label:
            query = query.filter(SequencePrediction.label == label)

        if predicted_label:
            query = query.filter(SequencePrediction.predicted_label == predicted_label)

        if only_errors:
            query = query.filter(SequencePrediction.label_id != SequencePrediction.predicted_label_id)

        rows = (
            query
            .order_by(desc(SequencePrediction.anomaly_probability))
            .limit(limit)
            .all()
        )

        return [serialize_model(row) for row in rows]


def get_v3_incidents(
    limit: int = 50,
    severity: Optional[str] = None,
    route: Optional[str] = None,
):
    with get_db_session() as session:
        query = session.query(FinalIncident)

        if severity:
            query = query.filter(FinalIncident.severity == severity)

        if route:
            query = query.filter(FinalIncident.route == route)

        rows = (
            query
            .order_by(desc(FinalIncident.last_seen))
            .limit(limit)
            .all()
        )

        return [serialize_model(row) for row in rows]


def get_v3_model_metrics():
    with get_db_session() as session:
        rows = (
            session.query(ModelMetric)
            .order_by(desc(ModelMetric.created_at))
            .all()
        )

        return [serialize_model(row) for row in rows]


def get_v3_chart_data():
    with get_db_session() as session:
        return {
            "logs_by_severity": get_group_counts(session, ProcessedLog, ProcessedLog.severity, limit=20),
            "logs_by_event_type": get_group_counts(session, ProcessedLog, ProcessedLog.event_type, limit=20),
            "logs_by_route": get_group_counts(session, ProcessedLog, ProcessedLog.route, limit=20),
            "sequences_by_label": get_group_counts(session, LogSequence, LogSequence.label, limit=20),
            "predictions_by_label": get_group_counts(session, SequencePrediction, SequencePrediction.predicted_label, limit=20),
            "incidents_by_severity": get_group_counts(session, FinalIncident, FinalIncident.severity, limit=20),
        }