import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

from sqlalchemy import desc
from sqlalchemy.orm import Session

from backend.app.database import get_db_session
from backend.app.db_models import ModelVersion


PROJECT_ROOT = Path(__file__).resolve().parents[3]
FALLBACK_SEQUENCE_TRANSFORMER_PATH = "models/sequence_transformer"
MODEL_NAME = "sequence_transformer"
VALID_SCOPES = {"global", "project"}


class ModelRegistryError(Exception):
    pass


class ModelRegistryNotFoundError(ModelRegistryError):
    pass


class ModelRegistryValidationError(ModelRegistryError):
    pass


def utcnow() -> datetime:
    return datetime.utcnow()


def serialize_value(value):
    if isinstance(value, datetime):
        return value.isoformat()

    return value


def json_loads(value: Optional[str]) -> Dict[str, Any]:
    if not value:
        return {}

    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return {}

    return parsed if isinstance(parsed, dict) else {}


def activation_copy_enabled() -> bool:
    return str(os.getenv("LOGGUARD_MODEL_ACTIVATION_COPY_ENABLED", "false")).strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def validate_scope(scope: str) -> str:
    value = str(scope or "global").strip().lower()

    if value not in VALID_SCOPES:
        raise ModelRegistryValidationError("scope debe ser global o project.")

    return value


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


def get_model_version_or_raise(session: Session, model_version_id: str) -> ModelVersion:
    model_version = (
        session.query(ModelVersion)
        .filter(ModelVersion.model_version_id == model_version_id)
        .first()
    )

    if model_version is None:
        raise ModelRegistryNotFoundError(f"No se encontro model version: {model_version_id}")

    return model_version


def active_query(session: Session, scope: str, project_id: Optional[str] = None):
    query = session.query(ModelVersion).filter(
        ModelVersion.model_name == MODEL_NAME,
        ModelVersion.scope == validate_scope(scope),
        ModelVersion.status == "active",
    )

    if scope == "project":
        query = query.filter(ModelVersion.project_id == project_id)
    else:
        query = query.filter(ModelVersion.project_id.is_(None))

    return query.order_by(desc(ModelVersion.activated_at), desc(ModelVersion.created_at))


def get_active_global_model() -> Optional[Dict[str, Any]]:
    with get_db_session() as session:
        row = active_query(session, "global").first()

        return serialize_model_version(row) if row else None


def get_active_project_model(project_id: str) -> Optional[Dict[str, Any]]:
    with get_db_session() as session:
        row = active_query(session, "project", project_id=project_id).first()

        return serialize_model_version(row) if row else None


def archive_previous_active_model(
    session: Session,
    scope: str,
    project_id: Optional[str] = None,
    exclude_model_version_id: Optional[str] = None,
) -> int:
    scope = validate_scope(scope)
    now = utcnow()
    query = session.query(ModelVersion).filter(
        ModelVersion.model_name == MODEL_NAME,
        ModelVersion.scope == scope,
        ModelVersion.status == "active",
    )

    if scope == "project":
        query = query.filter(ModelVersion.project_id == project_id)
    else:
        query = query.filter(ModelVersion.project_id.is_(None))

    if exclude_model_version_id:
        query = query.filter(ModelVersion.model_version_id != exclude_model_version_id)

    rows = query.all()

    for row in rows:
        row.status = "archived"
        row.is_default = False
        row.archived_at = now

    return len(rows)


def activate_model_version(
    model_version_id: str,
    activated_by: Optional[str] = None,
    note: Optional[str] = None,
) -> Dict[str, Any]:
    with get_db_session() as session:
        model_version = get_model_version_or_raise(session, model_version_id)

        if model_version.status == "failed":
            raise ModelRegistryValidationError("No se puede activar una version failed.")

        scope = validate_scope(model_version.scope)

        if scope == "project" and not model_version.project_id:
            raise ModelRegistryValidationError("Un modelo project requiere project_id.")

        if scope == "global":
            model_version.project_id = None

        archived_count = archive_previous_active_model(
            session=session,
            scope=scope,
            project_id=model_version.project_id,
            exclude_model_version_id=model_version.model_version_id,
        )

        now = utcnow()
        model_version.status = "active"
        model_version.is_default = scope == "global"
        model_version.activated_at = now
        model_version.archived_at = None
        model_version.activated_by = activated_by
        model_version.activation_note = note
        session.flush()

        copy_enabled = activation_copy_enabled()

        return {
            "model_version": serialize_model_version(model_version),
            "archived_previous_versions": archived_count,
            "activation_copy_enabled": copy_enabled,
            "active_model_artifact_replaced": False,
            "note": (
                "Activacion registrada en DB; no se reemplazo el artefacto activo."
                if not copy_enabled
                else "Copia fisica protegida por env no esta implementada de forma segura; no se reemplazo el artefacto activo."
            ),
        }


def resolve_model_for_project(project_id: Optional[str] = None) -> Dict[str, Any]:
    if project_id:
        project_model = get_active_project_model(project_id)

        if project_model:
            return {
                "project_id": project_id,
                "resolved_scope": "project",
                "project_model_used": True,
                "global_model_used": False,
                "fallback_used": False,
                "model_version_id": project_model["model_version_id"],
                "artifact_path": project_model["artifact_path"],
                "status": project_model["status"],
                "model_version": project_model,
            }

    global_model = get_active_global_model()

    if global_model:
        return {
            "project_id": project_id,
            "resolved_scope": "global",
            "project_model_used": False,
            "global_model_used": True,
            "fallback_used": False,
            "model_version_id": global_model["model_version_id"],
            "artifact_path": global_model["artifact_path"],
            "status": global_model["status"],
            "model_version": global_model,
        }

    fallback_path = PROJECT_ROOT / FALLBACK_SEQUENCE_TRANSFORMER_PATH

    return {
        "project_id": project_id,
        "resolved_scope": "filesystem",
        "project_model_used": False,
        "global_model_used": False,
        "fallback_used": True,
        "model_version_id": None,
        "artifact_path": FALLBACK_SEQUENCE_TRANSFORMER_PATH,
        "status": "filesystem_fallback" if fallback_path.exists() else "missing",
        "model_version": None,
    }


def get_active_models(project_id: Optional[str] = None) -> Dict[str, Any]:
    active_global = get_active_global_model()
    active_project = get_active_project_model(project_id) if project_id else None

    return {
        "project_id": project_id,
        "active_global_model": active_global,
        "active_project_model": active_project,
        "resolved_model": resolve_model_for_project(project_id),
    }
