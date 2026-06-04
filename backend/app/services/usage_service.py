import secrets
from datetime import date, datetime
from typing import Any, Dict, Optional

from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from backend.app.database import get_db_session
from backend.app.db_models import Project, ProjectUsageDaily, ProjectUsageEvent


ENTERPRISE_LIMIT = 10**12

PLAN_LIMITS = {
    "free": {
        "logs_per_day": 1000,
        "batches_per_day": 100,
        "async_tasks_per_day": 100,
        "notifications_per_day": 100,
    },
    "pro": {
        "logs_per_day": 100000,
        "batches_per_day": 5000,
        "async_tasks_per_day": 5000,
        "notifications_per_day": 5000,
    },
    "enterprise": {
        "logs_per_day": ENTERPRISE_LIMIT,
        "batches_per_day": ENTERPRISE_LIMIT,
        "async_tasks_per_day": ENTERPRISE_LIMIT,
        "notifications_per_day": ENTERPRISE_LIMIT,
    },
}

LIMIT_METRIC_MAP = {
    "logs_ingested": "logs_per_day",
    "batches_ingested": "batches_per_day",
    "async_tasks_created": "async_tasks_per_day",
    "notifications_sent": "notifications_per_day",
    "notifications_failed": "notifications_per_day",
}

USAGE_EVENT_TYPES = {
    "logs_ingested": "log.ingested",
    "batches_ingested": "batch.ingested",
    "async_tasks_created": "async_task.created",
    "predictions_created": "prediction.created",
    "incidents_created": "incident.created",
    "notifications_sent": "notification.sent",
    "notifications_failed": "notification.failed",
}

USAGE_METRICS = set(USAGE_EVENT_TYPES)


class UsageServiceError(Exception):
    pass


class PlanLimitExceededError(UsageServiceError):
    def __init__(
        self,
        project_id: str,
        plan: str,
        metric: str,
        limit: int,
        current: int,
        requested: int,
    ):
        self.project_id = project_id
        self.plan = plan
        self.metric = metric
        self.limit = limit
        self.current = current
        self.requested = requested
        super().__init__(
            f"Plan limit exceeded for {metric}: {current} + {requested} > {limit}."
        )


def utcnow() -> datetime:
    return datetime.utcnow()


def today_utc() -> date:
    return utcnow().date()


def serialize_value(value):
    if isinstance(value, (datetime, date)):
        return value.isoformat()

    return value


def serialize_daily_usage(row: ProjectUsageDaily) -> Dict[str, Any]:
    data = {}

    for column in row.__table__.columns:
        value = getattr(row, column.name)
        data[column.name] = serialize_value(value)

    return data


def get_plan_limits(plan: str) -> Dict[str, int]:
    return PLAN_LIMITS.get(str(plan or "free").lower(), PLAN_LIMITS["free"]).copy()


def get_plans() -> Dict[str, Dict[str, int]]:
    return {plan: limits.copy() for plan, limits in PLAN_LIMITS.items()}


def usage_event_id(session: Session) -> str:
    for _ in range(20):
        candidate = f"USE-{secrets.token_hex(4).upper()}"
        exists = (
            session.query(ProjectUsageEvent.id)
            .filter(ProjectUsageEvent.event_id == candidate)
            .first()
        )

        if not exists:
            return candidate

    return f"USE-{secrets.token_hex(6).upper()}"


def get_project_plan(session: Session, project_id: str) -> str:
    plan = (
        session.query(Project.plan)
        .filter(Project.project_id == project_id)
        .scalar()
    )

    return str(plan or "free").lower()


def validate_metric(metric: str) -> str:
    if metric not in USAGE_METRICS:
        raise UsageServiceError(f"Unknown usage metric: {metric}")

    return metric


def get_or_create_daily_usage(
    db: Session,
    project_id: str,
    usage_date: Optional[date] = None,
) -> ProjectUsageDaily:
    usage_date = usage_date or today_utc()
    usage = (
        db.query(ProjectUsageDaily)
        .filter(
            ProjectUsageDaily.project_id == project_id,
            ProjectUsageDaily.date == usage_date,
        )
        .first()
    )

    if usage:
        return usage

    usage = ProjectUsageDaily(
        project_id=project_id,
        date=usage_date,
        plan=get_project_plan(db, project_id),
        logs_ingested=0,
        batches_ingested=0,
        async_tasks_created=0,
        predictions_created=0,
        incidents_created=0,
        notifications_sent=0,
        notifications_failed=0,
    )
    db.add(usage)
    db.flush()

    return usage


def check_plan_limit(
    db: Session,
    project_id: Optional[str],
    metric: str,
    quantity: int = 1,
) -> Dict[str, Any]:
    if not project_id:
        return {
            "allowed": True,
            "limited": False,
        }

    metric = validate_metric(metric)

    if metric not in LIMIT_METRIC_MAP:
        return {
            "allowed": True,
            "limited": False,
        }

    usage = get_or_create_daily_usage(db, project_id)
    plan = get_project_plan(db, project_id)
    limit_name = LIMIT_METRIC_MAP[metric]
    limit = get_plan_limits(plan)[limit_name]
    current = int(getattr(usage, metric) or 0)
    requested = int(quantity or 0)

    return {
        "allowed": current + requested <= limit,
        "limited": True,
        "project_id": project_id,
        "plan": plan,
        "metric": metric,
        "limit_name": limit_name,
        "limit": limit,
        "current": current,
        "requested": requested,
    }


def enforce_plan_limit(
    db: Session,
    project_id: Optional[str],
    metric: str,
    quantity: int = 1,
) -> None:
    check = check_plan_limit(
        db=db,
        project_id=project_id,
        metric=metric,
        quantity=quantity,
    )

    if check.get("allowed"):
        return

    raise PlanLimitExceededError(
        project_id=check["project_id"],
        plan=check["plan"],
        metric=check["metric"],
        limit=check["limit"],
        current=check["current"],
        requested=check["requested"],
    )


def increment_usage(
    db: Session,
    project_id: Optional[str],
    metric: str,
    quantity: int = 1,
    metadata: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    if not project_id:
        return None

    metric = validate_metric(metric)
    quantity = int(quantity or 0)

    if quantity <= 0:
        return None

    usage = get_or_create_daily_usage(db, project_id)
    usage.plan = get_project_plan(db, project_id)
    setattr(usage, metric, int(getattr(usage, metric) or 0) + quantity)
    usage.updated_at = utcnow()

    event = ProjectUsageEvent(
        event_id=usage_event_id(db),
        project_id=project_id,
        event_type=USAGE_EVENT_TYPES[metric],
        quantity=quantity,
        metadata_json=metadata or {},
    )
    db.add(event)
    db.flush()

    return serialize_daily_usage(usage)


def record_usage_event(
    db: Session,
    project_id: Optional[str],
    event_type: str,
    quantity: int = 1,
    metadata: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    if not project_id:
        return None

    quantity = int(quantity or 0)

    if quantity <= 0:
        return None

    event = ProjectUsageEvent(
        event_id=usage_event_id(db),
        project_id=project_id,
        event_type=str(event_type or "").strip(),
        quantity=quantity,
        metadata_json=metadata or {},
    )
    db.add(event)
    db.flush()

    return {
        "event_id": event.event_id,
        "project_id": event.project_id,
        "event_type": event.event_type,
        "quantity": event.quantity,
        "created_at": serialize_value(event.created_at),
    }


def get_usage_summary(
    project_id: str,
    date_from: Optional[date] = None,
    date_to: Optional[date] = None,
) -> Dict[str, Any]:
    with get_db_session() as session:
        query = session.query(ProjectUsageDaily).filter(ProjectUsageDaily.project_id == project_id)

        if date_from:
            query = query.filter(ProjectUsageDaily.date >= date_from)

        if date_to:
            query = query.filter(ProjectUsageDaily.date <= date_to)

        rows = query.order_by(ProjectUsageDaily.date.asc()).all()
        totals = {
            "logs_ingested": 0,
            "batches_ingested": 0,
            "async_tasks_created": 0,
            "predictions_created": 0,
            "incidents_created": 0,
            "notifications_sent": 0,
            "notifications_failed": 0,
        }

        for row in rows:
            for metric in totals:
                totals[metric] += int(getattr(row, metric) or 0)

        plan = get_project_plan(session, project_id)

        return {
            "project_id": project_id,
            "plan": plan,
            "limits": get_plan_limits(plan),
            "date_from": serialize_value(date_from),
            "date_to": serialize_value(date_to),
            "totals": totals,
            "days": len(rows),
        }


def list_daily_usage(
    project_id: str,
    date_from: Optional[date] = None,
    date_to: Optional[date] = None,
    limit: int = 90,
) -> list[Dict[str, Any]]:
    with get_db_session() as session:
        query = session.query(ProjectUsageDaily).filter(ProjectUsageDaily.project_id == project_id)

        if date_from:
            query = query.filter(ProjectUsageDaily.date >= date_from)

        if date_to:
            query = query.filter(ProjectUsageDaily.date <= date_to)

        rows = (
            query
            .order_by(desc(ProjectUsageDaily.date))
            .limit(limit)
            .all()
        )

        return [serialize_daily_usage(row) for row in rows]


def increment_usage_safe(
    project_id: Optional[str],
    metric: str,
    quantity: int = 1,
    metadata: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    try:
        with get_db_session() as session:
            return increment_usage(
                db=session,
                project_id=project_id,
                metric=metric,
                quantity=quantity,
                metadata=metadata,
            )
    except Exception:
        return None


def record_usage_event_safe(
    project_id: Optional[str],
    event_type: str,
    quantity: int = 1,
    metadata: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    try:
        with get_db_session() as session:
            return record_usage_event(
                db=session,
                project_id=project_id,
                event_type=event_type,
                quantity=quantity,
                metadata=metadata,
            )
    except Exception:
        return None


def count_usage_events(
    project_id: str,
    event_type: Optional[str] = None,
) -> int:
    with get_db_session() as session:
        query = session.query(func.count(ProjectUsageEvent.id)).filter(
            ProjectUsageEvent.project_id == project_id
        )

        if event_type:
            query = query.filter(ProjectUsageEvent.event_type == event_type)

        return query.scalar() or 0
