import json
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from backend.app.database import get_db_session
from backend.app.celery_app import app
from backend.app.services.notification_service import (
    get_notification_event,
    mark_notification_failed,
    mark_notification_sent,
    mark_notification_skipped,
    webhook_is_configured,
    webhook_timeout_seconds,
    webhook_url,
)
from backend.app.services.real_incident_service import generate_real_incidents
from backend.app.services.realtime_sequence_service import analyze_recent_entity_sequences
from backend.app.services.usage_service import increment_usage


@app.task(name="logguard.ping_worker")
def ping_worker(message: str = "ping"):
    return {
        "status": "ok",
        "message": message,
        "worker_time": datetime.now(timezone.utc).isoformat(),
    }


def truncate_text(value: Optional[str], limit: int = 1000) -> Optional[str]:
    if value is None:
        return None

    return str(value)[:limit]


def post_webhook_with_urllib(
    target: str,
    payload: Dict[str, Any],
    timeout: float,
) -> Dict[str, Any]:
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        target,
        data=data,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "LogGuard-AI",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", errors="replace")

            return {
                "status_code": response.status,
                "body": truncate_text(body),
            }
    except urllib.error.HTTPError as error:
        body = error.read().decode("utf-8", errors="replace")

        return {
            "status_code": error.code,
            "body": truncate_text(body),
        }


def post_webhook_json(
    target: str,
    payload: Dict[str, Any],
    timeout: float,
) -> Dict[str, Any]:
    try:
        import requests

        response = requests.post(target, json=payload, timeout=timeout)

        return {
            "status_code": response.status_code,
            "body": truncate_text(response.text),
        }
    except ModuleNotFoundError:
        return post_webhook_with_urllib(
            target=target,
            payload=payload,
            timeout=timeout,
        )


@app.task(name="logguard.send_webhook_notification")
def send_webhook_notification(notification_event_id: str):
    try:
        with get_db_session() as session:
            event = get_notification_event(session, notification_event_id)

            if event is None:
                return {
                    "status": "not_found",
                    "notification_event_id": notification_event_id,
                }

            if event.status == "sent":
                return {
                    "status": "already_sent",
                    "event_id": event.event_id,
                }

            if event.status == "skipped":
                return {
                    "status": "already_skipped",
                    "event_id": event.event_id,
                }

            event_id = event.event_id
            project_id = event.project_id
            target = event.target or webhook_url()
            payload = event.payload or {}

            if not webhook_is_configured() or not target:
                notification = mark_notification_skipped(
                    db=session,
                    notification_id=event_id,
                    reason="Webhook notifications are not configured.",
                )

                return {
                    "status": "skipped",
                    "event_id": event_id,
                    "notification_event": notification,
                }

        result = post_webhook_json(
            target=target,
            payload=payload,
            timeout=webhook_timeout_seconds(),
        )
        status_code = int(result["status_code"])
        response_body = result.get("body")

        with get_db_session() as session:
            if 200 <= status_code < 300:
                notification = mark_notification_sent(
                    db=session,
                    notification_id=event_id,
                    response_status_code=status_code,
                    response_body=response_body,
                )
                increment_usage(
                    db=session,
                    project_id=project_id,
                    metric="notifications_sent",
                    quantity=1,
                    metadata={"event_id": event_id, "status_code": status_code},
                )

                return {
                    "status": "sent",
                    "event_id": event_id,
                    "response_status_code": status_code,
                    "notification_event": notification,
                }

            notification = mark_notification_failed(
                db=session,
                notification_id=event_id,
                error_message=f"Webhook returned HTTP {status_code}.",
                response_status_code=status_code,
                response_body=response_body,
            )
            increment_usage(
                db=session,
                project_id=project_id,
                metric="notifications_failed",
                quantity=1,
                metadata={"event_id": event_id, "status_code": status_code},
            )

            return {
                "status": "failed",
                "event_id": event_id,
                "response_status_code": status_code,
                "notification_event": notification,
            }
    except Exception as error:
        error_message = str(error)[:500]

        try:
            with get_db_session() as session:
                notification = mark_notification_failed(
                    db=session,
                    notification_id=notification_event_id,
                    error_message=error_message,
                )
                if notification:
                    increment_usage(
                        db=session,
                        project_id=notification.get("project_id"),
                        metric="notifications_failed",
                        quantity=1,
                        metadata={"event_id": notification.get("event_id")},
                    )
        except Exception:
            notification = None

        return {
            "status": "failed",
            "notification_event_id": notification_event_id,
            "error": error_message,
            "notification_event": notification,
        }


def build_completed_result(
    entity_type: str,
    entity_id: str,
    analysis_result: Dict[str, Any],
    incident_result: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    skipped_insufficient_logs = 1 if analysis_result.get("status") == "insufficient_logs" else 0
    skipped_duplicates = 1 if analysis_result.get("status") == "duplicate" else 0
    incident_result = incident_result or {}

    return {
        "status": "completed",
        "entity_type": entity_type,
        "entity_id": str(entity_id),
        "sequences_analyzed": analysis_result.get("sequences_analyzed", 0),
        "anomalies_detected": analysis_result.get("anomalies_detected", 0),
        "incidents_created": incident_result.get("incidents_created", 0),
        "incidents_updated": incident_result.get("incidents_updated", 0),
        "skipped_insufficient_logs": skipped_insufficient_logs,
        "skipped_duplicates": skipped_duplicates,
    }


@app.task(name="logguard.analyze_ingested_entity")
def analyze_ingested_entity(
    entity_type: str = "ip",
    entity_id: str = "",
    window_size: int = 20,
    source: Optional[str] = None,
    group_by: str = "ip",
    project_id: Optional[str] = None,
):
    try:
        with get_db_session() as session:
            analysis_result = analyze_recent_entity_sequences(
                session=session,
                group_by=group_by or entity_type,
                entity_id=entity_id,
                window_size=window_size,
                source=source,
                project_id=project_id,
            )

        incident_result = None

        if analysis_result.get("anomalies_detected", 0) > 0:
            incident_result = generate_real_incidents(
                entity_type=entity_type,
                entity_id=str(entity_id),
                source=source,
                project_id=project_id,
            )

        return build_completed_result(
            entity_type=entity_type,
            entity_id=entity_id,
            analysis_result=analysis_result,
            incident_result=incident_result,
        )
    except Exception as error:
        return {
            "status": "failed",
            "entity_type": entity_type,
            "entity_id": str(entity_id),
            "error": str(error)[:250],
        }
