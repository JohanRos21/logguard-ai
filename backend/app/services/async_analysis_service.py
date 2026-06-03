from typing import Any, Dict, Optional

from kombu.exceptions import KombuError

from backend.app.database import get_db_session
from backend.app.tasks import analyze_ingested_entity
from backend.app.services.usage_service import enforce_plan_limit, increment_usage


def enqueue_ingested_entity_analysis(
    entity_type: str = "ip",
    entity_id: Optional[str] = None,
    window_size: int = 20,
    source: Optional[str] = None,
    group_by: str = "ip",
    project_id: Optional[str] = None,
    enforce_usage_limits: bool = False,
    track_usage: bool = False,
) -> Dict[str, Any]:
    if not entity_id:
        return {
            "queued": False,
            "queue": "celery",
            "entity_type": entity_type,
            "entity_id": "",
            "error": "Missing entity_id.",
        }

    try:
        if project_id and enforce_usage_limits:
            with get_db_session() as session:
                enforce_plan_limit(
                    db=session,
                    project_id=project_id,
                    metric="async_tasks_created",
                    quantity=1,
                )

        task = analyze_ingested_entity.apply_async(
            kwargs={
                "entity_type": entity_type,
                "entity_id": str(entity_id),
                "window_size": window_size,
                "source": source,
                "group_by": group_by,
                "project_id": project_id,
            }
        )

        if project_id and track_usage:
            with get_db_session() as session:
                increment_usage(
                    db=session,
                    project_id=project_id,
                    metric="async_tasks_created",
                    quantity=1,
                    metadata={
                        "entity_type": entity_type,
                        "entity_id": str(entity_id),
                        "source": source,
                    },
                )

        return {
            "queued": True,
            "task_id": task.id,
            "queue": "celery",
            "entity_type": entity_type,
            "entity_id": str(entity_id),
            "project_id": project_id,
        }
    except (KombuError, OSError, RuntimeError) as error:
        return {
            "queued": False,
            "queue": "celery",
            "entity_type": entity_type,
            "entity_id": str(entity_id),
            "error": str(error)[:250],
        }
