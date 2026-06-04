import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


PROJECT_ROOT = Path(__file__).resolve().parents[3]
RETRAINING_DATA_DIR = PROJECT_ROOT / "data" / "retraining"
TRAINING_ENTRYPOINT = PROJECT_ROOT / "backend" / "app" / "ml" / "train_sequence_transformer.py"
MODEL_NAME = "sequence_transformer"


def utcnow() -> datetime:
    return datetime.utcnow()


def serialize_value(value):
    if isinstance(value, datetime):
        return value.isoformat()

    return value


def relative_project_path(path: Path) -> str:
    return path.relative_to(PROJECT_ROOT).as_posix()


def actual_training_enabled() -> bool:
    return str(os.getenv("LOGGUARD_RETRAINING_ACTUAL_ENABLED", "false")).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def read_jsonl(path: Path) -> List[Dict[str, Any]]:
    records = []

    if not path.exists():
        return records

    with path.open("r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                continue

            if isinstance(parsed, dict):
                records.append(parsed)

    return records


def feedback_label_to_training_label(label: str) -> Optional[str]:
    normalized = str(label or "").strip().lower()

    if normalized == "confirmed_anomaly":
        return "anomaly"

    if normalized in {"false_positive", "normal_behavior"}:
        return "normal"

    return None


def build_candidate_training_record(record: Dict[str, Any]) -> Dict[str, Any]:
    prediction = record.get("prediction") or {}
    incident = record.get("incident") or {}
    training_label = feedback_label_to_training_label(record.get("label"))

    return {
        "project_id": record.get("project_id"),
        "feedback_id": record.get("feedback_id"),
        "incident_id": record.get("incident_id"),
        "prediction_id": record.get("prediction_id"),
        "feedback_label": record.get("label"),
        "label": training_label,
        "confidence": record.get("confidence"),
        "event_sequence": prediction.get("event_sequence"),
        "route_sequence": prediction.get("route_sequence"),
        "status_sequence": prediction.get("status_sequence"),
        "method_sequence": prediction.get("method_sequence"),
        "incident_type": incident.get("incident_type"),
        "severity": incident.get("severity"),
        "source": incident.get("source") or prediction.get("source"),
        "created_at": record.get("created_at"),
    }


def write_jsonl(path: Path, records: List[Dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as file:
        for record in records:
            file.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def training_entrypoint_supports_safe_custom_io() -> bool:
    if not TRAINING_ENTRYPOINT.exists():
        return False

    try:
        content = TRAINING_ENTRYPOINT.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False

    return all(
        token in content
        for token in (
            "LOGGUARD_TRAINING_INPUT_PATH",
            "LOGGUARD_TRAINING_OUTPUT_DIR",
        )
    )


def prepare_candidate_model(
    job_id: str,
    project_id: Optional[str],
    scope: str,
    dataset_path: str,
    metrics: Dict[str, Any],
    actual_training_requested: bool = False,
) -> Dict[str, Any]:
    job_dir = RETRAINING_DATA_DIR / job_id
    candidate_model_dir = job_dir / "candidate_model"
    candidate_model_dir.mkdir(parents=True, exist_ok=True)

    absolute_dataset_path = PROJECT_ROOT / dataset_path
    feedback_records = read_jsonl(absolute_dataset_path)
    candidate_records = [
        build_candidate_training_record(record)
        for record in feedback_records
    ]
    candidate_records = [
        record
        for record in candidate_records
        if record.get("label") in {"anomaly", "normal"}
    ]

    candidate_dataset_path = candidate_model_dir / "candidate_training_dataset.jsonl"
    metadata_path = job_dir / "candidate_model_metadata.json"
    write_jsonl(candidate_dataset_path, candidate_records)

    enabled = actual_training_enabled()
    safe_entrypoint = training_entrypoint_supports_safe_custom_io()
    actual_training_executed = False
    training_skipped_reason = None

    if not actual_training_requested:
        training_skipped_reason = "actual training not requested"
    elif not enabled:
        training_skipped_reason = "actual training disabled"
    elif not safe_entrypoint:
        training_skipped_reason = "training entrypoint does not support safe custom input/output"
    else:
        training_skipped_reason = "safe custom training execution is not enabled in this bridge"

    bridge_metrics = {
        **metrics,
        "scope": scope,
        "project_id": project_id,
        "candidate_dataset_size": len(candidate_records),
        "candidate_dataset_path": relative_project_path(candidate_dataset_path),
        "candidate_model_dir": relative_project_path(candidate_model_dir),
        "training_entrypoint": relative_project_path(TRAINING_ENTRYPOINT),
        "training_entrypoint_supports_safe_custom_io": safe_entrypoint,
        "actual_training_requested": bool(actual_training_requested),
        "training_actual_enabled": enabled,
        "actual_training_executed": actual_training_executed,
        "training_skipped_reason": training_skipped_reason,
        "active_model_replaced": False,
    }

    metadata = {
        "model_name": MODEL_NAME,
        "project_id": project_id,
        "scope": scope,
        "source_job_id": job_id,
        "feedback_dataset_path": dataset_path,
        "candidate_dataset_path": relative_project_path(candidate_dataset_path),
        "candidate_model_dir": relative_project_path(candidate_model_dir),
        "metrics": bridge_metrics,
        "created_at": serialize_value(utcnow()),
        "actual_training_requested": bool(actual_training_requested),
        "actual_training_executed": actual_training_executed,
        "active_model_replaced": False,
        "note": (
            "Candidate metadata only. This bridge never writes to "
            "models/sequence_transformer and never activates a model automatically."
        ),
    }

    metadata_path.write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    return {
        "artifact_path": relative_project_path(metadata_path),
        "candidate_model_dir": relative_project_path(candidate_model_dir),
        "candidate_dataset_path": relative_project_path(candidate_dataset_path),
        "metrics": bridge_metrics,
        "actual_training_requested": bool(actual_training_requested),
        "actual_training_executed": actual_training_executed,
        "active_model_replaced": False,
        "training_skipped_reason": training_skipped_reason,
    }
