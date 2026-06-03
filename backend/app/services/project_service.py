import hashlib
import hmac
import os
import re
import secrets
from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy import desc

from backend.app.database import get_db_session
from backend.app.db_models import Project, ProjectApiKey


VALID_PROJECT_STATUSES = {"active", "disabled"}
VALID_KEY_STATUSES = {"active", "disabled", "revoked"}
VALID_PLANS = {"free", "pro", "enterprise"}


class ProjectServiceError(Exception):
    pass


class ProjectNotFoundError(ProjectServiceError):
    pass


class ProjectConflictError(ProjectServiceError):
    pass


class ProjectValidationError(ProjectServiceError):
    pass


class ProjectApiKeyNotFoundError(ProjectServiceError):
    pass


def utcnow() -> datetime:
    return datetime.utcnow()


def serialize_value(value):
    if isinstance(value, datetime):
        return value.isoformat()

    return value


def serialize_project(project: Project) -> Dict[str, Any]:
    data = {}

    for column in project.__table__.columns:
        value = getattr(project, column.name)
        data[column.name] = serialize_value(value)

    return data


def serialize_project_api_key(row: ProjectApiKey) -> Dict[str, Any]:
    return {
        "id": row.id,
        "key_id": row.key_id,
        "project_id": row.project_id,
        "name": row.name,
        "key_prefix": row.key_prefix,
        "key_last4": row.key_last4,
        "status": row.status,
        "created_at": serialize_value(row.created_at),
        "last_used_at": serialize_value(row.last_used_at),
        "revoked_at": serialize_value(row.revoked_at),
    }


def normalize_slug(slug: str) -> str:
    normalized = re.sub(r"[^a-z0-9-]+", "-", str(slug or "").strip().lower())
    normalized = re.sub(r"-+", "-", normalized).strip("-")

    if not normalized:
        raise ProjectValidationError("slug es requerido.")

    if len(normalized) > 150:
        raise ProjectValidationError("slug no puede superar 150 caracteres.")

    return normalized


def validate_plan(plan: Optional[str]) -> str:
    value = str(plan or "free").strip().lower()

    if value not in VALID_PLANS:
        raise ProjectValidationError("plan debe ser free, pro o enterprise.")

    return value


def validate_project_status(status: Optional[str]) -> str:
    value = str(status or "active").strip().lower()

    if value not in VALID_PROJECT_STATUSES:
        raise ProjectValidationError("status debe ser active o disabled.")

    return value


def generate_id(prefix: str, session, model, field_name: str) -> str:
    for _ in range(20):
        candidate = f"{prefix}-{secrets.token_hex(4).upper()}"
        exists = (
            session.query(model.id)
            .filter(getattr(model, field_name) == candidate)
            .first()
        )

        if not exists:
            return candidate

    return f"{prefix}-{secrets.token_hex(6).upper()}"


def hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def generate_raw_project_api_key() -> str:
    return f"lgp_{secrets.token_urlsafe(32)}"


def get_master_api_key() -> str:
    return os.getenv("LOGGUARD_API_KEY", "change-me")


def token_matches_master(token: str) -> bool:
    expected = get_master_api_key()

    return bool(token) and hmac.compare_digest(str(token), str(expected))


def get_project_or_raise(session, project_id: str) -> Project:
    project = (
        session.query(Project)
        .filter(Project.project_id == project_id)
        .first()
    )

    if project is None:
        raise ProjectNotFoundError(f"No se encontro el proyecto: {project_id}")

    return project


def get_project_api_key_or_raise(
    session,
    project_id: str,
    key_id: str,
) -> ProjectApiKey:
    api_key = (
        session.query(ProjectApiKey)
        .filter(
            ProjectApiKey.project_id == project_id,
            ProjectApiKey.key_id == key_id,
        )
        .first()
    )

    if api_key is None:
        raise ProjectApiKeyNotFoundError(f"No se encontro la API key: {key_id}")

    return api_key


def create_project(
    name: str,
    slug: str,
    description: Optional[str] = None,
    plan: str = "free",
) -> Dict[str, Any]:
    normalized_slug = normalize_slug(slug)
    normalized_plan = validate_plan(plan)

    if not str(name or "").strip():
        raise ProjectValidationError("name es requerido.")

    with get_db_session() as session:
        existing = (
            session.query(Project.id)
            .filter(Project.slug == normalized_slug)
            .first()
        )

        if existing:
            raise ProjectConflictError(f"Ya existe un proyecto con slug: {normalized_slug}")

        project = Project(
            project_id=generate_id("PROJ", session, Project, "project_id"),
            name=str(name).strip(),
            slug=normalized_slug,
            description=description,
            status="active",
            plan=normalized_plan,
        )
        session.add(project)
        session.flush()

        return serialize_project(project)


def list_projects(
    status: Optional[str] = None,
    plan: Optional[str] = None,
    limit: int = 50,
) -> list[Dict[str, Any]]:
    with get_db_session() as session:
        query = session.query(Project)

        if status:
            query = query.filter(Project.status == validate_project_status(status))

        if plan:
            query = query.filter(Project.plan == validate_plan(plan))

        rows = (
            query
            .order_by(desc(Project.created_at), desc(Project.id))
            .limit(limit)
            .all()
        )

        return [serialize_project(row) for row in rows]


def get_project_by_project_id(project_id: str) -> Dict[str, Any]:
    with get_db_session() as session:
        project = get_project_or_raise(session, project_id)

        return serialize_project(project)


def update_project(
    project_id: str,
    name: Optional[str] = None,
    slug: Optional[str] = None,
    description: Optional[str] = None,
    status: Optional[str] = None,
    plan: Optional[str] = None,
) -> Dict[str, Any]:
    with get_db_session() as session:
        project = get_project_or_raise(session, project_id)

        if name is not None:
            if not name.strip():
                raise ProjectValidationError("name no puede estar vacio.")
            project.name = name.strip()

        if slug is not None:
            normalized_slug = normalize_slug(slug)
            existing = (
                session.query(Project.id)
                .filter(
                    Project.slug == normalized_slug,
                    Project.project_id != project_id,
                )
                .first()
            )

            if existing:
                raise ProjectConflictError(
                    f"Ya existe otro proyecto con slug: {normalized_slug}"
                )

            project.slug = normalized_slug

        if description is not None:
            project.description = description

        if status is not None:
            project.status = validate_project_status(status)

        if plan is not None:
            project.plan = validate_plan(plan)

        project.updated_at = utcnow()
        session.flush()

        return serialize_project(project)


def disable_project(project_id: str) -> Dict[str, Any]:
    return update_project(project_id=project_id, status="disabled")


def generate_project_api_key(
    project_id: str,
    name: Optional[str] = None,
) -> Dict[str, Any]:
    with get_db_session() as session:
        project = get_project_or_raise(session, project_id)

        if project.status != "active":
            raise ProjectValidationError("No se pueden crear keys para un proyecto disabled.")

        raw_api_key = generate_raw_project_api_key()
        api_key = ProjectApiKey(
            key_id=generate_id("KEY", session, ProjectApiKey, "key_id"),
            project_id=project.project_id,
            name=name,
            key_prefix=raw_api_key[:12],
            key_last4=raw_api_key[-4:],
            key_hash=hash_api_key(raw_api_key),
            status="active",
        )
        session.add(api_key)
        session.flush()

        serialized = serialize_project_api_key(api_key)
        serialized["api_key"] = raw_api_key

        return serialized


def list_project_api_keys(
    project_id: str,
    status: Optional[str] = None,
    limit: int = 50,
) -> list[Dict[str, Any]]:
    with get_db_session() as session:
        get_project_or_raise(session, project_id)
        query = session.query(ProjectApiKey).filter(ProjectApiKey.project_id == project_id)

        if status:
            normalized_status = str(status).strip().lower()

            if normalized_status not in VALID_KEY_STATUSES:
                raise ProjectValidationError("status debe ser active, disabled o revoked.")

            query = query.filter(ProjectApiKey.status == normalized_status)

        rows = (
            query
            .order_by(desc(ProjectApiKey.created_at), desc(ProjectApiKey.id))
            .limit(limit)
            .all()
        )

        return [serialize_project_api_key(row) for row in rows]


def disable_project_api_key(
    project_id: str,
    key_id: str,
) -> Dict[str, Any]:
    with get_db_session() as session:
        get_project_or_raise(session, project_id)
        api_key = get_project_api_key_or_raise(session, project_id, key_id)

        if api_key.status == "active":
            api_key.status = "disabled"
            api_key.revoked_at = utcnow()

        session.flush()

        return serialize_project_api_key(api_key)


def rotate_project_api_key(
    project_id: str,
    name: Optional[str] = None,
) -> Dict[str, Any]:
    with get_db_session() as session:
        project = get_project_or_raise(session, project_id)

        if project.status != "active":
            raise ProjectValidationError("No se pueden rotar keys de un proyecto disabled.")

        revoked_count = (
            session.query(ProjectApiKey)
            .filter(
                ProjectApiKey.project_id == project_id,
                ProjectApiKey.status == "active",
            )
            .update(
                {
                    ProjectApiKey.status: "revoked",
                    ProjectApiKey.revoked_at: utcnow(),
                },
                synchronize_session=False,
            )
        )

        raw_api_key = generate_raw_project_api_key()
        api_key = ProjectApiKey(
            key_id=generate_id("KEY", session, ProjectApiKey, "key_id"),
            project_id=project.project_id,
            name=name,
            key_prefix=raw_api_key[:12],
            key_last4=raw_api_key[-4:],
            key_hash=hash_api_key(raw_api_key),
            status="active",
        )
        session.add(api_key)
        session.flush()

        serialized = serialize_project_api_key(api_key)
        serialized["api_key"] = raw_api_key
        serialized["revoked_active_keys"] = int(revoked_count or 0)

        return serialized


def verify_project_api_key(
    token: str,
    update_last_used: bool = True,
) -> Optional[Dict[str, Any]]:
    if not token or not token.startswith("lgp_"):
        return None

    token_hash = hash_api_key(token)

    with get_db_session() as session:
        api_key = (
            session.query(ProjectApiKey)
            .filter(ProjectApiKey.key_hash == token_hash)
            .first()
        )

        if api_key is None:
            return None

        if not hmac.compare_digest(str(api_key.key_hash), token_hash):
            return None

        if api_key.status != "active":
            return None

        project = (
            session.query(Project)
            .filter(Project.project_id == api_key.project_id)
            .first()
        )

        if project is None or project.status != "active":
            return None

        if update_last_used:
            now = utcnow()
            api_key.last_used_at = now
            project.last_used_at = now
            session.flush()

        return {
            "auth_type": "project",
            "project_id": project.project_id,
            "project_status": project.status,
            "plan": project.plan,
        }


def get_auth_context_from_token(
    token: str,
    update_last_used: bool = True,
) -> Optional[Dict[str, Any]]:
    if token_matches_master(token):
        return {
            "auth_type": "master",
            "project_id": None,
            "project_status": None,
            "plan": None,
        }

    return verify_project_api_key(
        token=token,
        update_last_used=update_last_used,
    )
