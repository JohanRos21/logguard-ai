import json
import os
import secrets
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from sqlalchemy import desc
from sqlalchemy.orm import Session

from backend.app.database import get_db_session
from backend.app.db_models import (
    IncidentFeedback,
    IngestedSequencePrediction,
    ModelVersion,
    Project,
    RealIncident,
    RetrainingJob,
)
from backend.app.services.model_training_bridge import prepare_candidate_model
from backend.app.services.usage_service import record_usage_event


PROJECT_ROOT = Path(__file__).resolve().parents[3]
RETRAINING_DATA_DIR = PROJECT_ROOT / "data" / "retraining"
MODEL_NAME = "sequence_transformer"

VALID_FEEDBACK_LABELS = {
    "confirmed_anomaly",
    "false_positive",
    "normal_behavior",
    "needs_review",
}
VALIDATED_FEEDBACK_LABELS = {
    "confirmed_anomaly",
    "false_positive",
    "normal_behavior",
}
VALID_JOB_MODES = {"dataset_only", "dry_run", "train_candidate"}
VALID_JOB_STATUSES = {"pending", "running", "completed", "failed", "cancelled"}
VALID_MODEL_STATUSES = {"candidate", "active", "archived", "failed"}
VALID_SCOPES = {"global", "project"}


class RetrainingServiceError(Exception):
    pass


class RetrainingNotFoundError(RetrainingServiceError):
    pass


class RetrainingPermissionError(RetrainingServiceError):
    pass


class RetrainingValidationError(RetrainingServiceError):
    pass


def utcnow() -> datetime:
    return datetime.utcnow()


def serialize_value(value):
    if isinstance(value, datetime):
        return value.isoformat()

    return value


def json_dumps(value: Optional[Dict[str, Any]]) -> str:
    return json.dumps(value or {}, ensure_ascii=False, sort_keys=True)


def json_loads(value: Optional[str]) -> Dict[str, Any]:
    if not value:
        return {}

    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return {}

    return parsed if isinstance(parsed, dict) else {}


def relative_data_path(path: Path) -> str:
    return path.relative_to(PROJECT_ROOT).as_posix()


def training_actual_enabled() -> bool:
    return str(os.getenv("LOGGUARD_RETRAINING_ACTUAL_ENABLED", "false")).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def generate_id(prefix: str, session: Session, model, field_name: str) -> str:
    for _ in range(20):
        candidate = f"{prefix}-{secrets.token_hex(4).upper()}"
        exists = (
            session.query(model.id)
            .filter(getattr(model, field_name) == candidate)
            .first()
        )

        if not exists:
            return candidate

    return f"{prefix}-{secrets.token_hex(6).upper()}"


def validate_feedback_label(label: str) -> str:
    value = str(label or "").strip().lower()

    if value not in VALID_FEEDBACK_LABELS:
        raise RetrainingValidationError(
            "label debe ser confirmed_anomaly, false_positive, normal_behavior o needs_review."
        )

    return value


def validate_job_mode(mode: str) -> str:
    value = str(mode or "dataset_only").strip().lower()

    if value not in VALID_JOB_MODES:
        raise RetrainingValidationError("mode debe ser dataset_only, dry_run o train_candidate.")

    return value


def validate_scope(scope: str) -> str:
    value = str(scope or "global").strip().lower()

    if value not in VALID_SCOPES:
        raise RetrainingValidationError("scope debe ser global o project.")

    return value


def validate_job_status(status: str) -> str:
    value = str(status or "").strip().lower()

    if value not in VALID_JOB_STATUSES:
        raise RetrainingValidationError("status de retraining invalido.")

    return value


def validate_model_status(status: str) -> str:
    value = str(status or "").strip().lower()

    if value not in VALID_MODEL_STATUSES:
        raise RetrainingValidationError("status de model version invalido.")

    return value


def validate_confidence(confidence: Optional[float]) -> Optional[float]:
    if confidence is None:
        return None

    value = float(confidence)

    if value < 0 or value > 1:
        raise RetrainingValidationError("confidence debe estar entre 0 y 1.")

    return value


def get_project_or_raise(session: Session, project_id: str) -> Project:
    project = (
        session.query(Project)
        .filter(Project.project_id == project_id)
        .first()
    )

    if project is None:
        raise RetrainingNotFoundError(f"No se encontro el proyecto: {project_id}")

    return project


def get_incident_or_raise(session: Session, incident_id: str) -> RealIncident:
    incident = (
        session.query(RealIncident)
        .filter(RealIncident.incident_id == incident_id)
        .first()
    )

    if incident is None:
        raise RetrainingNotFoundError(f"No se encontro el incidente: {incident_id}")

    return incident


def get_feedback_or_raise(session: Session, feedback_id: str) -> IncidentFeedback:
    feedback = (
        session.query(IncidentFeedback)
        .filter(IncidentFeedback.feedback_id == feedback_id)
        .first()
    )

    if feedback is None:
        raise RetrainingNotFoundError(f"No se encontro el feedback: {feedback_id}")

    return feedback


def get_retraining_job_or_raise(session: Session, job_id: str) -> RetrainingJob:
    job = (
        session.query(RetrainingJob)
        .filter(RetrainingJob.job_id == job_id)
        .first()
    )

    if job is None:
        raise RetrainingNotFoundError(f"No se encontro el retraining job: {job_id}")

    return job


def get_model_version_or_raise(session: Session, model_version_id: str) -> ModelVersion:
    model_version = (
        session.query(ModelVersion)
        .filter(ModelVersion.model_version_id == model_version_id)
        .first()
    )

    if model_version is None:
        raise RetrainingNotFoundError(
            f"No se encontro model version: {model_version_id}"
        )

    return model_version


def get_prediction(session: Session, prediction_id: Optional[str]) -> Optional[IngestedSequencePrediction]:
    if not prediction_id:
        return None

    value = str(prediction_id).strip()

    if value.isdigit():
        return (
            session.query(IngestedSequencePrediction)
            .filter(IngestedSequencePrediction.id == int(value))
            .first()
        )

    return (
        session.query(IngestedSequencePrediction)
        .filter(IngestedSequencePrediction.sequence_hash == value)
        .first()
    )


def serialize_feedback(row: IncidentFeedback) -> Dict[str, Any]:
    return {
        "id": row.id,
        "feedback_id": row.feedback_id,
        "project_id": row.project_id,
        "incident_id": row.incident_id,
        "prediction_id": row.prediction_id,
        "label": row.label,
        "confidence": row.confidence,
        "reviewer": row.reviewer,
        "note": row.note,
        "source": row.source,
        "created_at": serialize_value(row.created_at),
        "updated_at": serialize_value(row.updated_at),
    }


def serialize_job(row: RetrainingJob) -> Dict[str, Any]:
    return {
        "id": row.id,
        "job_id": row.job_id,
        "project_id": row.project_id,
        "scope": row.scope,
        "status": row.status,
        "mode": row.mode,
        "requested_by": row.requested_by,
        "actual_training_requested": bool(row.actual_training_requested),
        "actual_training_executed": bool(row.actual_training_executed),
        "active_model_replaced": bool(row.active_model_replaced),
        "feedback_count": row.feedback_count or 0,
        "dataset_size": row.dataset_size or 0,
        "parameters": json_loads(row.parameters_json),
        "metrics": json_loads(row.metrics_json),
        "output_dataset_path": row.output_dataset_path,
        "output_artifact_path": row.output_artifact_path,
        "error_message": row.error_message,
        "created_at": serialize_value(row.created_at),
        "started_at": serialize_value(row.started_at),
        "completed_at": serialize_value(row.completed_at),
    }


def serialize_model_version(row: ModelVersion) -> Dict[str, Any]:
    return {
        "id": row.id,
        "model_version_id": row.model_version_id,
        "project_id": row.project_id,
        "scope": row.scope,
        "model_name": row.model_name,
        "version_tag": row.version_tag,
        "status": row.status,
        "is_default": bool(row.is_default),
        "source_job_id": row.source_job_id,
        "artifact_path": row.artifact_path,
        "metrics": json_loads(row.metrics_json),
        "activated_by": row.activated_by,
        "activation_note": row.activation_note,
        "created_at": serialize_value(row.created_at),
        "activated_at": serialize_value(row.activated_at),
        "archived_at": serialize_value(row.archived_at),
    }


def assert_project_feedback_access(
    auth_project_id: Optional[str],
    incident: RealIncident,
) -> None:
    if not auth_project_id:
        return

    if incident.project_id != auth_project_id:
        raise RetrainingPermissionError(
            "Project API key solo puede operar feedback de incidentes de su proyecto."
        )


def create_incident_feedback(
    incident_id: str,
    label: str,
    prediction_id: Optional[str] = None,
    project_id: Optional[str] = None,
    confidence: Optional[float] = None,
    reviewer: Optional[str] = None,
    note: Optional[str] = None,
    source: str = "manual",
    auth_project_id: Optional[str] = None,
) -> Dict[str, Any]:
    normalized_label = validate_feedback_label(label)
    normalized_source = str(source or "manual").strip().lower() or "manual"
    normalized_confidence = validate_confidence(confidence)

    with get_db_session() as session:
        incident = get_incident_or_raise(session, incident_id)
        assert_project_feedback_access(auth_project_id, incident)

        effective_project_id = auth_project_id or project_id or incident.project_id

        if project_id and incident.project_id and project_id != incident.project_id:
            raise RetrainingValidationError(
                "project_id no coincide con el proyecto del incidente."
            )

        if effective_project_id:
            get_project_or_raise(session, effective_project_id)

        prediction = get_prediction(session, prediction_id)

        if prediction_id and prediction is None:
            raise RetrainingNotFoundError(f"No se encontro la prediccion: {prediction_id}")

        if prediction and effective_project_id and prediction.project_id:
            if prediction.project_id != effective_project_id:
                raise RetrainingValidationError(
                    "prediction_id no coincide con el proyecto del feedback."
                )

        feedback = IncidentFeedback(
            feedback_id=generate_id("FB", session, IncidentFeedback, "feedback_id"),
            project_id=effective_project_id,
            incident_id=incident.incident_id,
            prediction_id=str(prediction_id).strip() if prediction_id else None,
            label=normalized_label,
            confidence=normalized_confidence,
            reviewer=reviewer,
            note=note,
            source=normalized_source,
        )
        session.add(feedback)
        session.flush()

        record_usage_event(
            db=session,
            project_id=effective_project_id,
            event_type="feedback.created",
            quantity=1,
            metadata={
                "feedback_id": feedback.feedback_id,
                "incident_id": incident.incident_id,
                "label": normalized_label,
            },
        )

        return serialize_feedback(feedback)


def list_incident_feedback(
    incident_id: Optional[str] = None,
    project_id: Optional[str] = None,
    label: Optional[str] = None,
    limit: int = 50,
    auth_project_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    with get_db_session() as session:
        query = session.query(IncidentFeedback)

        if auth_project_id:
            query = query.filter(IncidentFeedback.project_id == auth_project_id)
        elif project_id:
            query = query.filter(IncidentFeedback.project_id == project_id)

        if incident_id:
            query = query.filter(IncidentFeedback.incident_id == incident_id)

        if label:
            query = query.filter(IncidentFeedback.label == validate_feedback_label(label))

        rows = (
            query
            .order_by(desc(IncidentFeedback.created_at), desc(IncidentFeedback.id))
            .limit(limit)
            .all()
        )

        return [serialize_feedback(row) for row in rows]


def get_feedback_for_incident(
    incident_id: str,
    limit: int = 50,
    auth_project_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    return list_incident_feedback(
        incident_id=incident_id,
        limit=limit,
        auth_project_id=auth_project_id,
    )


def create_retraining_job(
    project_id: Optional[str] = None,
    mode: str = "dataset_only",
    scope: str = "global",
    actual_training_requested: Optional[bool] = None,
    requested_by: Optional[str] = None,
    parameters: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    normalized_mode = validate_job_mode(mode)
    normalized_scope = validate_scope(scope)
    parameters = parameters or {}
    requested_training = (
        normalized_mode == "train_candidate"
        if actual_training_requested is None
        else bool(actual_training_requested)
    )

    if normalized_scope == "global":
        project_id = None

    if normalized_scope == "project" and not project_id:
        raise RetrainingValidationError("scope project requiere project_id.")

    with get_db_session() as session:
        if project_id:
            get_project_or_raise(session, project_id)

        job = RetrainingJob(
            job_id=generate_id("RETRAIN", session, RetrainingJob, "job_id"),
            project_id=project_id,
            scope=normalized_scope,
            status="pending",
            mode=normalized_mode,
            requested_by=requested_by,
            actual_training_requested=requested_training,
            actual_training_executed=False,
            active_model_replaced=False,
            parameters_json=json_dumps(parameters),
            feedback_count=0,
            dataset_size=0,
        )
        session.add(job)
        session.flush()

        record_usage_event(
            db=session,
            project_id=project_id,
            event_type="retraining_job.created",
            quantity=1,
            metadata={
                "job_id": job.job_id,
                "mode": normalized_mode,
                "scope": normalized_scope,
                "actual_training_requested": requested_training,
            },
        )

        return serialize_job(job)


def list_retraining_jobs(
    project_id: Optional[str] = None,
    scope: Optional[str] = None,
    status: Optional[str] = None,
    mode: Optional[str] = None,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    with get_db_session() as session:
        query = session.query(RetrainingJob)

        if project_id:
            query = query.filter(RetrainingJob.project_id == project_id)

        if scope:
            query = query.filter(RetrainingJob.scope == validate_scope(scope))

        if status:
            query = query.filter(RetrainingJob.status == validate_job_status(status))

        if mode:
            query = query.filter(RetrainingJob.mode == validate_job_mode(mode))

        rows = (
            query
            .order_by(desc(RetrainingJob.created_at), desc(RetrainingJob.id))
            .limit(limit)
            .all()
        )

        return [serialize_job(row) for row in rows]


def get_retraining_job(job_id: str) -> Dict[str, Any]:
    with get_db_session() as session:
        return serialize_job(get_retraining_job_or_raise(session, job_id))


def cancel_retraining_job(job_id: str) -> Dict[str, Any]:
    with get_db_session() as session:
        job = get_retraining_job_or_raise(session, job_id)

        if job.status in {"completed", "failed", "cancelled"}:
            return serialize_job(job)

        job.status = "cancelled"
        job.completed_at = utcnow()
        session.flush()

        return serialize_job(job)


def mark_retraining_job_failed(job_id: str, error_message: str) -> Dict[str, Any]:
    with get_db_session() as session:
        job = get_retraining_job_or_raise(session, job_id)
        job.status = "failed"
        job.error_message = str(error_message)[:1000]
        job.completed_at = utcnow()
        session.flush()

        return serialize_job(job)


def feedback_query_for_dataset(
    session: Session,
    project_id: Optional[str],
):
    query = session.query(IncidentFeedback).filter(
        IncidentFeedback.label.in_(sorted(VALIDATED_FEEDBACK_LABELS))
    )

    if project_id:
        query = query.filter(IncidentFeedback.project_id == project_id)

    return query.order_by(IncidentFeedback.created_at.asc(), IncidentFeedback.id.asc())


def serialize_related_incident(incident: Optional[RealIncident]) -> Optional[Dict[str, Any]]:
    if incident is None:
        return None

    return {
        "incident_id": incident.incident_id,
        "project_id": incident.project_id,
        "incident_type": incident.incident_type,
        "severity": incident.severity,
        "status": incident.status,
        "entity_type": incident.entity_type,
        "entity_id": incident.entity_id,
        "source": incident.source,
        "first_seen": serialize_value(incident.first_seen),
        "last_seen": serialize_value(incident.last_seen),
        "events_count": incident.events_count,
        "sequences_count": incident.sequences_count,
        "max_anomaly_probability": incident.max_anomaly_probability,
        "related_routes": incident.related_routes,
        "related_event_types": incident.related_event_types,
        "related_sequence_ids": incident.related_sequence_ids,
    }


def serialize_related_prediction(
    prediction: Optional[IngestedSequencePrediction],
) -> Optional[Dict[str, Any]]:
    if prediction is None:
        return None

    return {
        "id": prediction.id,
        "project_id": prediction.project_id,
        "entity_type": prediction.entity_type,
        "entity_id": prediction.entity_id,
        "start_time": serialize_value(prediction.start_time),
        "end_time": serialize_value(prediction.end_time),
        "window_size": prediction.window_size,
        "event_sequence": prediction.event_sequence,
        "route_sequence": prediction.route_sequence,
        "status_sequence": prediction.status_sequence,
        "method_sequence": prediction.method_sequence,
        "ai_prediction": prediction.ai_prediction,
        "anomaly_probability": prediction.anomaly_probability,
        "normal_probability": prediction.normal_probability,
        "final_severity": prediction.final_severity,
        "source": prediction.source,
    }


def build_feedback_dataset_record(
    session: Session,
    feedback: IncidentFeedback,
) -> Dict[str, Any]:
    incident = (
        session.query(RealIncident)
        .filter(RealIncident.incident_id == feedback.incident_id)
        .first()
    )
    prediction = get_prediction(session, feedback.prediction_id)

    return {
        "project_id": feedback.project_id,
        "incident_id": feedback.incident_id,
        "prediction_id": feedback.prediction_id,
        "feedback_id": feedback.feedback_id,
        "label": feedback.label,
        "confidence": feedback.confidence,
        "note": feedback.note,
        "source": feedback.source,
        "created_at": serialize_value(feedback.created_at),
        "incident": serialize_related_incident(incident),
        "prediction": serialize_related_prediction(prediction),
    }


def build_feedback_dataset(
    job_id: str,
    project_id: Optional[str],
    scope: str,
    parameters: Dict[str, Any],
    mode: str,
) -> Dict[str, Any]:
    job_dir = RETRAINING_DATA_DIR / job_id
    dataset_path = job_dir / "feedback_dataset.jsonl"
    job_dir.mkdir(parents=True, exist_ok=True)

    with get_db_session() as session:
        total_feedback = (
            session.query(IncidentFeedback)
            .filter(IncidentFeedback.project_id == project_id)
            .count()
            if project_id
            else session.query(IncidentFeedback).count()
        )
        feedback_rows = feedback_query_for_dataset(session, project_id).all()
        records = [
            build_feedback_dataset_record(session, feedback)
            for feedback in feedback_rows
        ]

    with dataset_path.open("w", encoding="utf-8") as file:
        for record in records:
            file.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")

    label_distribution = Counter(record["label"] for record in records)
    min_feedback = int(parameters.get("min_feedback", 1) or 1)
    insufficient_feedback = len(records) < min_feedback

    metrics = {
        "mode": mode,
        "scope": scope,
        "project_id": project_id,
        "feedback_count": total_feedback,
        "validated_feedback_count": len(records),
        "dataset_size": len(records),
        "label_distribution": dict(label_distribution),
        "min_feedback": min_feedback,
        "insufficient_feedback": insufficient_feedback,
        "training_actual_enabled": training_actual_enabled(),
        "actual_training_executed": False,
        "active_model_replaced": False,
    }

    return {
        "feedback_count": total_feedback,
        "dataset_size": len(records),
        "metrics": metrics,
        "output_dataset_path": relative_data_path(dataset_path),
    }


def write_candidate_metadata(
    job_id: str,
    project_id: Optional[str],
    metrics: Dict[str, Any],
    dataset_path: str,
) -> str:
    artifact_path = RETRAINING_DATA_DIR / job_id / "candidate_model_metadata.json"
    artifact = {
        "model_name": MODEL_NAME,
        "project_id": project_id,
        "source_job_id": job_id,
        "dataset_path": dataset_path,
        "metrics": metrics,
        "created_at": serialize_value(utcnow()),
        "training_actual_enabled": training_actual_enabled(),
        "actual_training_executed": False,
        "active_model_replaced": False,
        "note": (
            "Training real esta protegido por LOGGUARD_RETRAINING_ACTUAL_ENABLED "
            "y no reemplaza artefactos activos automaticamente."
        ),
    }

    artifact_path.write_text(
        json.dumps(artifact, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    return relative_data_path(artifact_path)


def create_candidate_model_version(
    project_id: Optional[str],
    scope: str,
    source_job_id: str,
    artifact_path: Optional[str],
    metrics: Optional[Dict[str, Any]] = None,
    version_tag: Optional[str] = None,
) -> Dict[str, Any]:
    with get_db_session() as session:
        return serialize_model_version(
            create_candidate_model_version_row(
                session=session,
                project_id=project_id,
                scope=scope,
                source_job_id=source_job_id,
                artifact_path=artifact_path,
                metrics=metrics,
                version_tag=version_tag,
            )
        )


def create_candidate_model_version_row(
    session: Session,
    project_id: Optional[str],
    scope: str,
    source_job_id: str,
    artifact_path: Optional[str],
    metrics: Optional[Dict[str, Any]] = None,
    version_tag: Optional[str] = None,
) -> ModelVersion:
    normalized_scope = validate_scope(scope)

    if normalized_scope == "global":
        project_id = None

    if normalized_scope == "project" and not project_id:
        raise RetrainingValidationError("scope project requiere project_id.")

    if project_id:
        get_project_or_raise(session, project_id)

    model_version = ModelVersion(
        model_version_id=generate_id("MODEL", session, ModelVersion, "model_version_id"),
        project_id=project_id,
        scope=normalized_scope,
        model_name=MODEL_NAME,
        version_tag=version_tag or f"{source_job_id.lower()}-{utcnow().strftime('%Y%m%d%H%M%S')}",
        status="candidate",
        is_default=False,
        source_job_id=source_job_id,
        artifact_path=artifact_path,
        metrics_json=json_dumps(metrics or {}),
    )
    session.add(model_version)
    session.flush()

    return model_version


def complete_retraining_job(
    job_id: str,
    dataset_result: Dict[str, Any],
) -> Dict[str, Any]:
    metrics = dataset_result["metrics"]
    mode = metrics["mode"]
    insufficient_feedback = bool(metrics["insufficient_feedback"])
    output_artifact_path = None
    error_message = None
    status = "completed"
    actual_training_executed = False
    active_model_replaced = False

    if mode == "train_candidate" and insufficient_feedback:
        status = "failed"
        error_message = "Insufficient validated feedback for train_candidate."

    with get_db_session() as session:
        job = get_retraining_job_or_raise(session, job_id)

        if job.status == "cancelled":
            return serialize_job(job)

        if mode == "train_candidate" and not insufficient_feedback:
            bridge_result = prepare_candidate_model(
                job_id=job.job_id,
                project_id=job.project_id,
                scope=job.scope,
                dataset_path=dataset_result["output_dataset_path"],
                metrics=metrics,
                actual_training_requested=bool(job.actual_training_requested),
            )
            output_artifact_path = bridge_result["artifact_path"]
            metrics = bridge_result["metrics"]
            metrics["candidate_metadata_created"] = True
            actual_training_executed = bool(bridge_result["actual_training_executed"])
            active_model_replaced = bool(bridge_result["active_model_replaced"])
            create_candidate_model_version_row(
                session=session,
                project_id=job.project_id,
                scope=job.scope,
                source_job_id=job.job_id,
                artifact_path=output_artifact_path,
                metrics=metrics,
            )

        job.status = status
        job.feedback_count = int(dataset_result["feedback_count"] or 0)
        job.dataset_size = int(dataset_result["dataset_size"] or 0)
        job.output_dataset_path = dataset_result["output_dataset_path"]
        job.output_artifact_path = output_artifact_path
        job.metrics_json = json_dumps(metrics)
        job.error_message = error_message
        job.actual_training_executed = actual_training_executed
        job.active_model_replaced = active_model_replaced
        job.completed_at = utcnow()
        session.flush()

        return serialize_job(job)


def run_retraining_job(job_id: str) -> Dict[str, Any]:
    try:
        with get_db_session() as session:
            job = get_retraining_job_or_raise(session, job_id)

            if job.status == "cancelled":
                return serialize_job(job)

            if job.status not in {"pending", "running"}:
                return serialize_job(job)

            job.status = "running"
            job.started_at = job.started_at or utcnow()
            job.error_message = None
            session.flush()

            project_id = job.project_id
            scope = validate_scope(job.scope)
            mode = validate_job_mode(job.mode)
            parameters = json_loads(job.parameters_json)

        dataset_result = build_feedback_dataset(
            job_id=job_id,
            project_id=project_id,
            scope=scope,
            parameters=parameters,
            mode=mode,
        )

        if mode == "dry_run":
            dataset_result["metrics"]["dry_run"] = True
            dataset_result["metrics"]["candidate_metadata_created"] = False

        if mode == "dataset_only":
            dataset_result["metrics"]["candidate_metadata_created"] = False

        return complete_retraining_job(
            job_id=job_id,
            dataset_result=dataset_result,
        )
    except Exception as error:
        try:
            return mark_retraining_job_failed(job_id, str(error)[:1000])
        except Exception:
            return {
                "job_id": job_id,
                "status": "failed",
                "error_message": str(error)[:1000],
            }


def list_model_versions(
    project_id: Optional[str] = None,
    scope: Optional[str] = None,
    status: Optional[str] = None,
    model_name: Optional[str] = None,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    with get_db_session() as session:
        query = session.query(ModelVersion)

        if project_id:
            query = query.filter(ModelVersion.project_id == project_id)

        if scope:
            query = query.filter(ModelVersion.scope == validate_scope(scope))

        if status:
            query = query.filter(ModelVersion.status == validate_model_status(status))

        if model_name:
            query = query.filter(ModelVersion.model_name == model_name)

        rows = (
            query
            .order_by(desc(ModelVersion.created_at), desc(ModelVersion.id))
            .limit(limit)
            .all()
        )

        return [serialize_model_version(row) for row in rows]


def activate_model_version(model_version_id: str) -> Dict[str, Any]:
    from backend.app.services.model_registry_service import activate_model_version as activate

    return activate(model_version_id=model_version_id)
