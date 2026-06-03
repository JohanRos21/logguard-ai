import os
import uuid
from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from backend.app.database import get_db_session
from backend.app.db_models import NotificationEvent, RealIncident


WEBHOOK_CHANNEL = "webhook"
NOTIFIABLE_EVENTS = {
    "incident.created",
    "incident.updated",
    "incident.resolved",
    "incident.reopened",
}


def utcnow() -> datetime:
    return datetime.utcnow()


def serialize_value(value):
    if isinstance(value, datetime):
        return value.isoformat()

    return value


def serialize_notification_event(row: NotificationEvent) -> Dict[str, Any]:
    data = {}

    for column in row.__table__.columns:
        value = getattr(row, column.name)
        data[column.name] = serialize_value(value)

    return data


def env_flag(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).strip().lower() in {"1", "true", "yes", "on"}


def webhook_url() -> str:
    return os.getenv("LOGGUARD_WEBHOOK_URL", "").strip()


def webhook_timeout_seconds() -> float:
    raw_value = os.getenv("LOGGUARD_WEBHOOK_TIMEOUT_SECONDS", "5")

    try:
        return max(1.0, float(raw_value))
    except ValueError:
        return 5.0


def webhook_is_configured() -> bool:
    return (
        env_flag("LOGGUARD_NOTIFICATIONS_ENABLED")
        and env_flag("LOGGUARD_WEBHOOK_ENABLED")
        and bool(webhook_url())
    )


def incident_value(incident, field_name: str, default=None):
    if isinstance(incident, dict):
        return incident.get(field_name, default)

    return getattr(incident, field_name, default)


def build_incident_notification_payload(incident, event_type: str) -> Dict[str, Any]:
    return {
        "source": "logguard-ai",
        "event_type": event_type,
        "incident": {
            "incident_id": incident_value(incident, "incident_id"),
            "title": incident_value(incident, "title"),
            "incident_type": incident_value(incident, "incident_type"),
            "severity": incident_value(incident, "severity"),
            "status": incident_value(incident, "status"),
            "entity_type": incident_value(incident, "entity_type"),
            "entity_id": incident_value(incident, "entity_id"),
            "max_anomaly_probability": incident_value(
                incident,
                "max_anomaly_probability",
            ),
            "recommendation": incident_value(incident, "recommendation"),
        },
        "timestamp": utcnow().isoformat(),
    }


def build_test_notification_payload(message: str) -> Dict[str, Any]:
    return {
        "source": "logguard-ai",
        "event_type": "webhook.test",
        "message": message,
        "timestamp": utcnow().isoformat(),
    }


def new_notification_event_id(session: Session) -> str:
    for _ in range(20):
        event_id = f"NOTIF-{uuid.uuid4().hex[:8].upper()}"
        exists = (
            session.query(NotificationEvent.id)
            .filter(NotificationEvent.event_id == event_id)
            .first()
        )

        if not exists:
            return event_id

    return f"NOTIF-{uuid.uuid4().hex[:12].upper()}"


def should_notify_incident(incident, event_type: str) -> bool:
    if event_type not in NOTIFIABLE_EVENTS:
        return False

    if not webhook_is_configured():
        return False

    severity = str(incident_value(incident, "severity", "") or "").lower()

    if event_type in {"incident.created", "incident.updated"}:
        return severity == "critical"

    return True


def has_pending_notification(
    session: Session,
    incident_id: Optional[str],
    event_type: str,
    channel: str = WEBHOOK_CHANNEL,
) -> bool:
    if not incident_id:
        return False

    row = (
        session.query(NotificationEvent.id)
        .filter(
            NotificationEvent.incident_id == incident_id,
            NotificationEvent.event_type == event_type,
            NotificationEvent.channel == channel,
            NotificationEvent.status == "pending",
        )
        .first()
    )

    return row is not None


def create_notification_event(
    db: Session,
    event_type: str,
    incident,
    channel: str = WEBHOOK_CHANNEL,
) -> NotificationEvent:
    target = webhook_url() if channel == WEBHOOK_CHANNEL else None
    event = NotificationEvent(
        event_id=new_notification_event_id(db),
        channel=channel,
        event_type=event_type,
        incident_id=incident_value(incident, "incident_id"),
        severity=incident_value(incident, "severity"),
        status="pending",
        target=target,
        payload=build_incident_notification_payload(incident, event_type),
    )

    db.add(event)
    db.flush()

    return event


def create_incident_notification_if_enabled(
    db: Session,
    incident,
    event_type: str,
) -> Optional[str]:
    if not should_notify_incident(incident, event_type):
        return None

    incident_id = incident_value(incident, "incident_id")

    if has_pending_notification(db, incident_id, event_type):
        return None

    event = create_notification_event(
        db=db,
        event_type=event_type,
        incident=incident,
    )

    return event.event_id


def create_custom_notification_event(
    db: Session,
    event_type: str,
    payload: Dict[str, Any],
    channel: str = WEBHOOK_CHANNEL,
    status: str = "pending",
    target: Optional[str] = None,
    incident_id: Optional[str] = None,
    severity: Optional[str] = None,
    error_message: Optional[str] = None,
) -> NotificationEvent:
    event = NotificationEvent(
        event_id=new_notification_event_id(db),
        channel=channel,
        event_type=event_type,
        incident_id=incident_id,
        severity=severity,
        status=status,
        target=target,
        payload=payload,
        error_message=error_message,
    )

    db.add(event)
    db.flush()

    return event


def get_notification_event(db: Session, notification_id) -> Optional[NotificationEvent]:
    query = db.query(NotificationEvent)

    if isinstance(notification_id, int):
        return query.filter(NotificationEvent.id == notification_id).first()

    return query.filter(NotificationEvent.event_id == str(notification_id)).first()


def mark_notification_sent(
    db: Session,
    notification_id,
    response_status_code: Optional[int],
    response_body: Optional[str],
) -> Optional[Dict[str, Any]]:
    event = get_notification_event(db, notification_id)

    if event is None:
        return None

    event.status = "sent"
    event.response_status_code = response_status_code
    event.response_body = response_body
    event.error_message = None
    event.sent_at = utcnow()
    db.flush()

    return serialize_notification_event(event)


def mark_notification_failed(
    db: Session,
    notification_id,
    error_message: str,
    response_status_code: Optional[int] = None,
    response_body: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    event = get_notification_event(db, notification_id)

    if event is None:
        return None

    event.status = "failed"
    event.response_status_code = response_status_code
    event.response_body = response_body
    event.error_message = error_message[:500]
    event.sent_at = utcnow()
    db.flush()

    return serialize_notification_event(event)


def mark_notification_skipped(
    db: Session,
    notification_id,
    reason: str,
) -> Optional[Dict[str, Any]]:
    event = get_notification_event(db, notification_id)

    if event is None:
        return None

    event.status = "skipped"
    event.error_message = reason[:500]
    db.flush()

    return serialize_notification_event(event)


def enqueue_notification_event(event_id: str) -> Dict[str, Any]:
    try:
        from backend.app.tasks import send_webhook_notification

        task = send_webhook_notification.delay(event_id)

        return {
            "queued": True,
            "task_id": task.id,
            "event_id": event_id,
        }
    except Exception as error:
        return {
            "queued": False,
            "event_id": event_id,
            "error": str(error)[:250],
        }


def enqueue_created_notification_events(event_ids: list[str]) -> Dict[str, Any]:
    queued = []
    failed = []

    for event_id in event_ids:
        result = enqueue_notification_event(event_id)

        if result.get("queued"):
            queued.append(result)
        else:
            failed.append(result)

    return {
        "queued": len(queued),
        "failed": len(failed),
        "tasks": queued,
        "errors": failed,
    }


def enqueue_incident_notification(incident_id: str, event_type: str) -> Dict[str, Any]:
    event_id = None
    serialized_event = None

    with get_db_session() as session:
        incident = (
            session.query(RealIncident)
            .filter(RealIncident.incident_id == incident_id)
            .first()
        )

        if incident is None:
            return {
                "queued": False,
                "status": "not_found",
                "incident_id": incident_id,
            }

        event_id = create_incident_notification_if_enabled(
            db=session,
            incident=incident,
            event_type=event_type,
        )

        if event_id:
            serialized_event = serialize_notification_event(
                get_notification_event(session, event_id)
            )

    if not event_id:
        return {
            "queued": False,
            "status": "skipped",
            "incident_id": incident_id,
            "event_type": event_type,
        }

    queue_result = enqueue_notification_event(event_id)

    return {
        "status": "queued" if queue_result.get("queued") else "queue_failed",
        "notification_event": serialized_event,
        **queue_result,
    }


def queue_test_webhook_notification(message: str) -> Dict[str, Any]:
    configured = webhook_is_configured()
    target = webhook_url() if configured else None
    status = "pending" if configured else "skipped"
    reason = None if configured else "Webhook notifications are not configured."

    with get_db_session() as session:
        event = create_custom_notification_event(
            db=session,
            event_type="webhook.test",
            payload=build_test_notification_payload(message),
            status=status,
            target=target,
            error_message=reason,
        )
        event_id = event.event_id
        serialized_event = serialize_notification_event(event)

    if not configured:
        return {
            "status": "skipped",
            "queued": False,
            "notification_event": serialized_event,
            "reason": reason,
        }

    queue_result = enqueue_notification_event(event_id)

    return {
        "status": "queued" if queue_result.get("queued") else "queue_failed",
        "notification_event": serialized_event,
        **queue_result,
    }


def list_notification_events(
    status: Optional[str] = None,
    channel: Optional[str] = None,
    event_type: Optional[str] = None,
    incident_id: Optional[str] = None,
    limit: int = 50,
) -> list[Dict[str, Any]]:
    with get_db_session() as session:
        query = session.query(NotificationEvent)

        if status:
            query = query.filter(NotificationEvent.status == status)

        if channel:
            query = query.filter(NotificationEvent.channel == channel)

        if event_type:
            query = query.filter(NotificationEvent.event_type == event_type)

        if incident_id:
            query = query.filter(NotificationEvent.incident_id == incident_id)

        rows = (
            query
            .order_by(desc(NotificationEvent.created_at), desc(NotificationEvent.id))
            .limit(limit)
            .all()
        )

        return [serialize_notification_event(row) for row in rows]


def notification_group_counts(session: Session, column) -> Dict[str, int]:
    rows = (
        session.query(column, func.count(NotificationEvent.id))
        .group_by(column)
        .order_by(desc(func.count(NotificationEvent.id)))
        .all()
    )

    return {str(key): count for key, count in rows if key is not None}


def count_notification_status(session: Session, status: str) -> int:
    return (
        session.query(func.count(NotificationEvent.id))
        .filter(NotificationEvent.status == status)
        .scalar()
        or 0
    )


def get_notifications_summary() -> Dict[str, Any]:
    with get_db_session() as session:
        total = session.query(func.count(NotificationEvent.id)).scalar() or 0

        return {
            "total": total,
            "pending": count_notification_status(session, "pending"),
            "sent": count_notification_status(session, "sent"),
            "failed": count_notification_status(session, "failed"),
            "skipped": count_notification_status(session, "skipped"),
            "by_event_type": notification_group_counts(
                session,
                NotificationEvent.event_type,
            ),
            "by_channel": notification_group_counts(session, NotificationEvent.channel),
        }
