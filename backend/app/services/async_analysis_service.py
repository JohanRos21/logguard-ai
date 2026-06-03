from typing import Any, Dict, Optional

from kombu.exceptions import KombuError

from backend.app.tasks import analyze_ingested_entity


def enqueue_ingested_entity_analysis(
    entity_type: str = "ip",
    entity_id: Optional[str] = None,
    window_size: int = 20,
    source: Optional[str] = None,
    group_by: str = "ip",
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
        task = analyze_ingested_entity.apply_async(
            kwargs={
                "entity_type": entity_type,
                "entity_id": str(entity_id),
                "window_size": window_size,
                "source": source,
                "group_by": group_by,
            }
        )

        return {
            "queued": True,
            "task_id": task.id,
            "queue": "celery",
            "entity_type": entity_type,
            "entity_id": str(entity_id),
        }
    except (KombuError, OSError, RuntimeError) as error:
        return {
            "queued": False,
            "queue": "celery",
            "entity_type": entity_type,
            "entity_id": str(entity_id),
            "error": str(error)[:250],
        }
