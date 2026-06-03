import os
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional

from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from backend.app.database import get_db_session
from backend.app.db_models import IngestedLog
from backend.app.ingestion_schemas import IngestBatchRequest, IngestLogRequest
from backend.app.services.async_analysis_service import enqueue_ingested_entity_analysis
from backend.app.services.realtime_sequence_service import (
    safe_analyze_entities_after_ingestion,
    safe_analyze_recent_entity_after_ingestion,
)
from backend.app.services.real_incident_service import (
    safe_generate_real_incidents_for_entities,
    safe_generate_real_incidents_for_entity,
)
from backend.app.services.usage_service import enforce_plan_limit, increment_usage


SENSITIVE_METADATA_KEYS = {
    "access_token",
    "api_key",
    "authorization",
    "cookie",
    "csrf",
    "password",
    "refresh_token",
    "secret",
    "session",
    "token",
}

SENSITIVE_ROUTES = (
    "/dashboard/admin",
    "/api/admin/users",
    "/api/payments",
    "/api/enrollments",
    "/api/database",
)

PROTECTIVE_LOGIN_EVENTS = {
    "captcha_required",
    "login_blocked",
    "login_rate_limited",
}

NORMAL_EVENTS = {
    "data_loaded",
    "login_success",
    "record_created",
}

WARNING_EVENTS = {
    "captcha_required",
    "login_blocked",
    "login_failed",
    "login_rate_limited",
    "slow_response",
    "validation_error",
}

CRITICAL_EVENTS = {
    "database_timeout",
    "login_attempt_after_block",
}


def is_async_analysis_enabled() -> bool:
    return os.getenv("LOGGUARD_ASYNC_ANALYSIS", "false").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def sanitize_metadata(value: Any) -> Any:
    if isinstance(value, dict):
        sanitized = {}

        for key, nested_value in value.items():
            normalized_key = str(key).lower()

            if any(sensitive_key in normalized_key for sensitive_key in SENSITIVE_METADATA_KEYS):
                continue

            sanitized[str(key)] = sanitize_metadata(nested_value)

        return sanitized

    if isinstance(value, list):
        return [sanitize_metadata(item) for item in value]

    return value


def normalize_string(value: Optional[str], default: Optional[str] = None) -> Optional[str]:
    if value is None:
        return default

    normalized = str(value).strip()

    if not normalized:
        return default

    return normalized


def normalize_payload(payload: IngestLogRequest) -> Dict[str, Any]:
    data = payload.model_dump() if hasattr(payload, "model_dump") else payload.dict()

    normalized = {
        "timestamp": data.get("timestamp") or datetime.utcnow(),
        "source": normalize_string(data.get("source")),
        "environment": normalize_string(data.get("environment"), "development"),
        "event_type": normalize_string(data.get("event_type")),
        "source_severity": normalize_string(data.get("source_severity")),
        "user_id": normalize_string(data.get("user_id")),
        "role": normalize_string(data.get("role")),
        "ip": normalize_string(data.get("ip")),
        "method": normalize_string(data.get("method")),
        "route": normalize_string(data.get("route")),
        "status_code": int(data.get("status_code")),
        "response_time_ms": float(data.get("response_time_ms")),
        "message": normalize_string(data.get("message")),
        "metadata_json": sanitize_metadata(data.get("metadata") or {}),
    }

    missing = [
        field
        for field in (
            "source",
            "event_type",
            "ip",
            "method",
            "route",
            "status_code",
            "response_time_ms",
            "message",
        )
        if normalized.get(field) is None
    ]

    if missing:
        raise ValueError(f"Missing required fields: {', '.join(missing)}")

    normalized["event_type"] = normalized["event_type"].lower()
    normalized["source_severity"] = (
        normalized["source_severity"].lower()
        if normalized["source_severity"]
        else infer_source_severity(normalized)
    )
    normalized["method"] = normalized["method"].upper()

    return normalized


def is_sensitive_route(route: Optional[str]) -> bool:
    normalized_route = str(route or "").lower().rstrip("/")

    return any(
        normalized_route == sensitive_route
        or normalized_route.startswith(f"{sensitive_route}/")
        for sensitive_route in SENSITIVE_ROUTES
    )


def is_payment_route(route: Optional[str]) -> bool:
    return "/api/payments" in str(route or "").lower()


def infer_source_severity(data: Dict[str, Any]) -> str:
    event_type = data["event_type"].lower()
    status_code = int(data["status_code"])

    if (
        event_type in CRITICAL_EVENTS
        or status_code >= 500
        or (event_type == "unauthorized_access" and is_sensitive_route(data.get("route")))
    ):
        return "critical"

    if event_type in WARNING_EVENTS or status_code >= 400 or data["response_time_ms"] >= 1000:
        return "warning"

    return "normal"


def count_recent_events(
    session: Session,
    data: Dict[str, Any],
    event_types: Iterable[str],
    minutes: int = 15,
):
    timestamp = data["timestamp"]
    window_start = timestamp - timedelta(minutes=minutes)

    query = session.query(IngestedLog).filter(
        IngestedLog.timestamp >= window_start,
        IngestedLog.timestamp <= timestamp,
        IngestedLog.ip == data["ip"],
    )

    return query.filter(IngestedLog.event_type.in_(list(event_types))).count()


def recent_failed_login_user_count(session: Session, data: Dict[str, Any], minutes: int = 15) -> int:
    timestamp = data["timestamp"]
    window_start = timestamp - timedelta(minutes=minutes)

    rows = (
        session.query(IngestedLog.user_id)
        .filter(
            IngestedLog.timestamp >= window_start,
            IngestedLog.timestamp <= timestamp,
            IngestedLog.ip == data["ip"],
            IngestedLog.event_type == "login_failed",
            IngestedLog.user_id.isnot(None),
        )
        .distinct()
        .all()
    )

    users = {row[0] for row in rows if row[0]}

    if data.get("user_id"):
        users.add(data["user_id"])

    return len(users)


def has_recent_sensitive_unauthorized(
    session: Session,
    data: Dict[str, Any],
    minutes: int = 15,
) -> bool:
    timestamp = data["timestamp"]
    window_start = timestamp - timedelta(minutes=minutes)

    rows = (
        session.query(IngestedLog.route)
        .filter(
            IngestedLog.timestamp >= window_start,
            IngestedLog.timestamp <= timestamp,
            IngestedLog.ip == data["ip"],
            IngestedLog.event_type == "unauthorized_access",
        )
        .all()
    )

    return any(is_sensitive_route(row[0]) for row in rows)


def recent_login_failures_for_admin(session: Session, data: Dict[str, Any], minutes: int = 15) -> int:
    timestamp = data["timestamp"]
    window_start = timestamp - timedelta(minutes=minutes)
    query = session.query(IngestedLog).filter(
        IngestedLog.timestamp >= window_start,
        IngestedLog.timestamp <= timestamp,
        IngestedLog.event_type == "login_failed",
        IngestedLog.role == "ADMIN",
    )

    if data.get("user_id"):
        query = query.filter(IngestedLog.user_id == data["user_id"])
    else:
        query = query.filter(IngestedLog.ip == data["ip"])

    return query.count()


def mark_security_misconfiguration(data: Dict[str, Any]) -> None:
    metadata = data.setdefault("metadata_json", {})
    metadata["possible_security_misconfiguration"] = (
        "many_login_failed_without_login_blocked_rate_limited_or_captcha"
    )


def compute_final_severity(session: Session, data: Dict[str, Any]) -> str:
    event_type = data["event_type"]
    route = data["route"]
    status_code = int(data["status_code"])
    source_severity = data["source_severity"]
    role = str(data.get("role") or "").upper()

    if event_type in NORMAL_EVENTS:
        return "normal"

    if event_type == "login_attempt_after_block":
        return "critical"

    if event_type == "database_timeout" or status_code >= 500:
        return "critical"

    if event_type == "unauthorized_access" and is_sensitive_route(route):
        return "critical"

    if event_type == "payment_failed" and is_payment_route(route):
        return "critical" if status_code >= 500 or source_severity == "critical" else "warning"

    if event_type == "login_failed":
        recent_failures = count_recent_events(session, data, {"login_failed"}) + 1
        protective_events = count_recent_events(session, data, PROTECTIVE_LOGIN_EVENTS)
        multi_user_targets = recent_failed_login_user_count(session, data)
        admin_failures = recent_login_failures_for_admin(session, data) + 1

        if role == "ADMIN" and admin_failures >= 3:
            return "critical"

        if multi_user_targets >= 3:
            return "critical"

        if has_recent_sensitive_unauthorized(session, data):
            return "critical"

        if recent_failures >= 5 and protective_events == 0:
            mark_security_misconfiguration(data)

        return "warning"

    if event_type in PROTECTIVE_LOGIN_EVENTS:
        return "warning"

    if event_type == "slow_response" or data["response_time_ms"] >= 1000:
        return "warning"

    if event_type == "validation_error":
        return "warning"

    if source_severity in {"critical", "warning", "normal"}:
        return source_severity

    return "normal"


def serialize_ingested_log(row: IngestedLog) -> Dict[str, Any]:
    return {
        "id": row.id,
        "project_id": row.project_id,
        "timestamp": row.timestamp.isoformat() if row.timestamp else None,
        "source": row.source,
        "environment": row.environment,
        "event_type": row.event_type,
        "source_severity": row.source_severity,
        "final_severity": row.final_severity,
        "user_id": row.user_id,
        "role": row.role,
        "ip": row.ip,
        "method": row.method,
        "route": row.route,
        "status_code": row.status_code,
        "response_time_ms": row.response_time_ms,
        "message": row.message,
        "metadata_json": row.metadata_json,
        "ai_prediction": row.ai_prediction,
        "anomaly_probability": row.anomaly_probability,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


def create_ingested_log(
    session: Session,
    payload: IngestLogRequest,
    project_id: Optional[str] = None,
) -> IngestedLog:
    data = normalize_payload(payload)
    final_severity = compute_final_severity(session, data)

    row = IngestedLog(
        project_id=project_id,
        timestamp=data["timestamp"],
        source=data["source"],
        environment=data["environment"],
        event_type=data["event_type"],
        source_severity=data["source_severity"],
        final_severity=final_severity,
        user_id=data.get("user_id"),
        role=str(data["role"]).upper() if data.get("role") else None,
        ip=data["ip"],
        method=data["method"],
        route=data["route"],
        status_code=data["status_code"],
        response_time_ms=data["response_time_ms"],
        message=data["message"],
        metadata_json=data["metadata_json"],
        ai_prediction=None,
        anomaly_probability=None,
    )

    session.add(row)
    session.flush()

    return row


def ingestion_result(row: IngestedLog) -> Dict[str, Any]:
    return {
        "id": row.id,
        "source_severity": row.source_severity,
        "final_severity": row.final_severity,
    }


def attach_incident_generation_result(
    auto_analysis: Dict[str, Any],
    incident_result: Dict[str, Any],
) -> Dict[str, Any]:
    if incident_result.get("status") == "failed":
        auto_analysis["incident_generation_status"] = "failed"
        auto_analysis["incident_generation_error"] = incident_result.get("error")
        return auto_analysis

    auto_analysis["incidents_created"] = incident_result.get("incidents_created", 0)
    auto_analysis["incidents_updated"] = incident_result.get("incidents_updated", 0)

    return auto_analysis


def build_async_auto_analysis(queue_result: Dict[str, Any]) -> Dict[str, Any]:
    if queue_result.get("queued"):
        return {
            "status": "queued",
            "mode": "async",
            "task_id": queue_result["task_id"],
            "queue": queue_result["queue"],
            "entity_type": queue_result["entity_type"],
            "entity_id": queue_result["entity_id"],
        }

    return {
        "status": "queue_failed",
        "mode": "async",
        "queue": queue_result.get("queue", "celery"),
        "entity_type": queue_result.get("entity_type", "ip"),
        "entity_id": queue_result.get("entity_id", ""),
        "error": queue_result.get("error", "Redis/Celery unavailable"),
    }


def enqueue_auto_analysis_for_entity(
    entity_id: Optional[str],
    project_id: Optional[str] = None,
) -> Dict[str, Any]:
    queue_result = enqueue_ingested_entity_analysis(
        entity_type="ip",
        entity_id=entity_id,
        group_by="ip",
        project_id=project_id,
        track_usage=True,
    )

    return build_async_auto_analysis(queue_result)


def enqueue_auto_analysis_for_entities(
    entity_ids: List[str],
    project_id: Optional[str] = None,
) -> Dict[str, Any]:
    unique_entity_ids = sorted({str(entity_id) for entity_id in entity_ids if entity_id})
    task_results = [
        enqueue_ingested_entity_analysis(
            entity_type="ip",
            entity_id=entity_id,
            group_by="ip",
            project_id=project_id,
            track_usage=True,
        )
        for entity_id in unique_entity_ids
    ]
    queued_results = [result for result in task_results if result.get("queued")]
    failed_results = [result for result in task_results if not result.get("queued")]

    if failed_results and not queued_results:
        return {
            "status": "queue_failed",
            "mode": "async",
            "queue": "celery",
            "entities_checked": len(unique_entity_ids),
            "task_ids": [],
            "failed_entities": [
                {
                    "entity_type": result.get("entity_type", "ip"),
                    "entity_id": result.get("entity_id", ""),
                    "error": result.get("error", "Redis/Celery unavailable"),
                }
                for result in failed_results
            ],
        }

    return {
        "status": "queued" if not failed_results else "partial",
        "mode": "async",
        "queue": "celery",
        "entities_checked": len(unique_entity_ids),
        "task_ids": [result["task_id"] for result in queued_results],
        "queued_tasks": len(queued_results),
        "queue_failures": len(failed_results),
        "failed_entities": [
            {
                "entity_type": result.get("entity_type", "ip"),
                "entity_id": result.get("entity_id", ""),
                "error": result.get("error", "Redis/Celery unavailable"),
            }
            for result in failed_results
        ],
    }


def ingest_log(
    payload: IngestLogRequest,
    project_id: Optional[str] = None,
    enforce_usage_limits: bool = False,
    track_usage: bool = False,
) -> Dict[str, Any]:
    with get_db_session() as session:
        if project_id and enforce_usage_limits:
            enforce_plan_limit(
                db=session,
                project_id=project_id,
                metric="logs_ingested",
                quantity=1,
            )

        row = create_ingested_log(session, payload, project_id=project_id)
        if project_id and track_usage:
            increment_usage(
                db=session,
                project_id=project_id,
                metric="logs_ingested",
                quantity=1,
                metadata={"source": row.source, "route": row.route},
            )
        result = ingestion_result(row)
        entity_id = row.ip

    if is_async_analysis_enabled():
        result["auto_analysis"] = enqueue_auto_analysis_for_entity(
            entity_id,
            project_id=project_id,
        )
        return result

    result["auto_analysis"] = safe_analyze_recent_entity_after_ingestion(
        entity_id=entity_id,
        group_by="ip",
        project_id=project_id,
    )

    if result["auto_analysis"].get("anomalies_detected", 0) > 0:
        incident_result = safe_generate_real_incidents_for_entity(
            entity_type="ip",
            entity_id=entity_id,
            project_id=project_id,
        )
        result["auto_analysis"] = attach_incident_generation_result(
            auto_analysis=result["auto_analysis"],
            incident_result=incident_result,
        )

    return result


def ingest_batch(
    payload: IngestBatchRequest,
    project_id: Optional[str] = None,
    enforce_usage_limits: bool = False,
    track_usage: bool = False,
) -> Dict[str, Any]:
    with get_db_session() as session:
        results = []
        affected_ips = []

        if project_id and enforce_usage_limits:
            enforce_plan_limit(
                db=session,
                project_id=project_id,
                metric="batches_ingested",
                quantity=1,
            )
            enforce_plan_limit(
                db=session,
                project_id=project_id,
                metric="logs_ingested",
                quantity=len(payload.logs),
            )

        for log_payload in payload.logs:
            row = create_ingested_log(session, log_payload, project_id=project_id)
            results.append(ingestion_result(row))
            affected_ips.append(row.ip)

        if project_id and track_usage:
            increment_usage(
                db=session,
                project_id=project_id,
                metric="batches_ingested",
                quantity=1,
                metadata={"logs": len(payload.logs)},
            )
            increment_usage(
                db=session,
                project_id=project_id,
                metric="logs_ingested",
                quantity=len(payload.logs),
                metadata={"batch": True},
            )

    if is_async_analysis_enabled():
        return {
            "results": results,
            "auto_analysis": enqueue_auto_analysis_for_entities(
                affected_ips,
                project_id=project_id,
            ),
        }

    auto_analysis = safe_analyze_entities_after_ingestion(
        entity_ids=affected_ips,
        group_by="ip",
        project_id=project_id,
    )

    if auto_analysis.get("anomalies_detected", 0) > 0:
        incident_result = safe_generate_real_incidents_for_entities(
            entity_type="ip",
            entity_ids=affected_ips,
            project_id=project_id,
        )
        auto_analysis = attach_incident_generation_result(
            auto_analysis=auto_analysis,
            incident_result=incident_result,
        )

    return {
        "results": results,
        "auto_analysis": auto_analysis,
    }


def get_ingested_logs(
    limit: int = 50,
    source: Optional[str] = None,
    event_type: Optional[str] = None,
    final_severity: Optional[str] = None,
    ip: Optional[str] = None,
) -> List[Dict[str, Any]]:
    with get_db_session() as session:
        query = session.query(IngestedLog)

        if source:
            query = query.filter(IngestedLog.source == source)

        if event_type:
            query = query.filter(IngestedLog.event_type == event_type)

        if final_severity:
            query = query.filter(IngestedLog.final_severity == final_severity)

        if ip:
            query = query.filter(IngestedLog.ip == ip)

        rows = query.order_by(desc(IngestedLog.timestamp)).limit(limit).all()

        return [serialize_ingested_log(row) for row in rows]


def group_counts(session: Session, column, limit: int = 10) -> Dict[str, int]:
    rows = (
        session.query(column, func.count(IngestedLog.id))
        .group_by(column)
        .order_by(desc(func.count(IngestedLog.id)))
        .limit(limit)
        .all()
    )

    return {str(key): count for key, count in rows if key is not None}


def get_ingested_logs_summary() -> Dict[str, Any]:
    with get_db_session() as session:
        return {
            "total": session.query(func.count(IngestedLog.id)).scalar(),
            "logs_by_source": group_counts(session, IngestedLog.source),
            "logs_by_event_type": group_counts(session, IngestedLog.event_type),
            "logs_by_final_severity": group_counts(session, IngestedLog.final_severity),
            "logs_by_source_severity": group_counts(session, IngestedLog.source_severity),
            "top_ips": group_counts(session, IngestedLog.ip),
            "top_routes": group_counts(session, IngestedLog.route),
        }
