from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy import desc, func

from backend.app.database import get_db_session
from backend.app.db_models import RealIncident
from backend.app.services.notification_service import (
    create_incident_notification_if_enabled,
    enqueue_notification_event,
)
from backend.app.services.real_incident_service import serialize_incident


VALID_STATUSES = {"open", "acknowledged", "resolved"}


class IncidentNotFoundError(Exception):
    pass


class InvalidIncidentTransitionError(Exception):
    pass


def utcnow() -> datetime:
    return datetime.utcnow()


def append_lifecycle_note(
    current_note: Optional[str],
    action: str,
    actor: Optional[str],
    note: Optional[str],
) -> Optional[str]:
    if not note:
        return current_note

    actor_text = actor or "system"
    entry = f"[{utcnow().isoformat()}] {action} by {actor_text}: {note}"

    if current_note:
        return f"{current_note}\n{entry}"

    return entry


def get_incident_or_raise(session, incident_id: str) -> RealIncident:
    incident = (
        session.query(RealIncident)
        .filter(RealIncident.incident_id == incident_id)
        .first()
    )

    if incident is None:
        raise IncidentNotFoundError(f"No se encontro el incidente: {incident_id}")

    return incident


def acknowledge_incident(
    incident_id: str,
    acknowledged_by: Optional[str] = None,
    note: Optional[str] = None,
) -> Dict[str, Any]:
    with get_db_session() as session:
        incident = get_incident_or_raise(session, incident_id)

        if incident.status != "open":
            raise InvalidIncidentTransitionError(
                "Solo se pueden reconocer incidentes en estado open."
            )

        incident.status = "acknowledged"
        incident.acknowledged_at = utcnow()
        incident.acknowledged_by = acknowledged_by
        incident.resolution_note = append_lifecycle_note(
            current_note=incident.resolution_note,
            action="acknowledged",
            actor=acknowledged_by,
            note=note,
        )
        incident.updated_at = utcnow()
        session.flush()

        return serialize_incident(incident)


def resolve_incident(
    incident_id: str,
    resolved_by: Optional[str] = None,
    resolution_note: Optional[str] = None,
) -> Dict[str, Any]:
    notification_event_id = None

    with get_db_session() as session:
        incident = get_incident_or_raise(session, incident_id)

        if incident.status not in {"open", "acknowledged"}:
            raise InvalidIncidentTransitionError(
                "Solo se pueden resolver incidentes en estado open o acknowledged."
            )

        incident.status = "resolved"
        incident.resolved_at = utcnow()
        incident.resolved_by = resolved_by
        incident.resolution_note = append_lifecycle_note(
            current_note=incident.resolution_note,
            action="resolved",
            actor=resolved_by,
            note=resolution_note,
        )
        incident.updated_at = utcnow()
        notification_event_id = create_incident_notification_if_enabled(
            db=session,
            incident=incident,
            event_type="incident.resolved",
        )
        session.flush()

        serialized_incident = serialize_incident(incident)

    if notification_event_id:
        enqueue_notification_event(notification_event_id)

    return serialized_incident


def reopen_incident(
    incident_id: str,
    reopened_by: Optional[str] = None,
    note: Optional[str] = None,
) -> Dict[str, Any]:
    notification_event_id = None

    with get_db_session() as session:
        incident = get_incident_or_raise(session, incident_id)
        previous_status = incident.status

        if previous_status not in {"resolved", "acknowledged"}:
            raise InvalidIncidentTransitionError(
                "Solo se pueden reabrir incidentes en estado resolved o acknowledged."
            )

        incident.status = "open"
        incident.resolved_at = None
        incident.resolved_by = None

        if previous_status == "acknowledged":
            incident.acknowledged_at = None
            incident.acknowledged_by = None

        incident.resolution_note = append_lifecycle_note(
            current_note=incident.resolution_note,
            action="reopened",
            actor=reopened_by,
            note=note,
        )
        incident.updated_at = utcnow()
        notification_event_id = create_incident_notification_if_enabled(
            db=session,
            incident=incident,
            event_type="incident.reopened",
        )
        session.flush()

        serialized_incident = serialize_incident(incident)

    if notification_event_id:
        enqueue_notification_event(notification_event_id)

    return serialized_incident


def list_incidents_by_status(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    incident_type: Optional[str] = None,
    entity_id: Optional[str] = None,
    project_id: Optional[str] = None,
    limit: int = 50,
) -> list[Dict[str, Any]]:
    with get_db_session() as session:
        query = session.query(RealIncident)

        if status:
            if status not in VALID_STATUSES:
                raise InvalidIncidentTransitionError(
                    "status debe ser open, acknowledged o resolved."
                )
            query = query.filter(RealIncident.status == status)

        if severity:
            query = query.filter(RealIncident.severity == severity)

        if incident_type:
            query = query.filter(RealIncident.incident_type == incident_type)

        if entity_id:
            query = query.filter(RealIncident.entity_id == entity_id)

        if project_id:
            query = query.filter(RealIncident.project_id == project_id)

        rows = (
            query
            .order_by(desc(RealIncident.last_seen), desc(RealIncident.updated_at))
            .limit(limit)
            .all()
        )

        return [serialize_incident(row) for row in rows]


def group_counts(session, column) -> Dict[str, int]:
    rows = (
        session.query(column, func.count(RealIncident.id))
        .group_by(column)
        .order_by(desc(func.count(RealIncident.id)))
        .all()
    )

    return {str(key): count for key, count in rows if key is not None}


def count_status(session, status: str, severity: Optional[str] = None) -> int:
    query = session.query(func.count(RealIncident.id)).filter(RealIncident.status == status)

    if severity:
        query = query.filter(RealIncident.severity == severity)

    return query.scalar() or 0


def get_incident_lifecycle_summary() -> Dict[str, Any]:
    with get_db_session() as session:
        total = session.query(func.count(RealIncident.id)).scalar() or 0

        return {
            "total": total,
            "open": count_status(session, "open"),
            "acknowledged": count_status(session, "acknowledged"),
            "resolved": count_status(session, "resolved"),
            "critical_open": count_status(session, "open", severity="critical"),
            "critical_acknowledged": count_status(
                session,
                "acknowledged",
                severity="critical",
            ),
            "by_status": group_counts(session, RealIncident.status),
            "by_severity": group_counts(session, RealIncident.severity),
        }
