from datetime import datetime, timezone
from typing import Any, Dict, Optional

from backend.app.database import get_db_session
from backend.app.celery_app import app
from backend.app.services.real_incident_service import generate_real_incidents
from backend.app.services.realtime_sequence_service import analyze_recent_entity_sequences


@app.task(name="logguard.ping_worker")
def ping_worker(message: str = "ping"):
    return {
        "status": "ok",
        "message": message,
        "worker_time": datetime.now(timezone.utc).isoformat(),
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
):
    try:
        with get_db_session() as session:
            analysis_result = analyze_recent_entity_sequences(
                session=session,
                group_by=group_by or entity_type,
                entity_id=entity_id,
                window_size=window_size,
                source=source,
            )

        incident_result = None

        if analysis_result.get("anomalies_detected", 0) > 0:
            incident_result = generate_real_incidents(
                entity_type=entity_type,
                entity_id=str(entity_id),
                source=source,
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
