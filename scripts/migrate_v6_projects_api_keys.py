import sys
from pathlib import Path

from sqlalchemy import text


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.database import engine


TABLES = {
    "projects": {
        "columns": [
            ("project_id", "VARCHAR(50)"),
            ("name", "VARCHAR(150)"),
            ("slug", "VARCHAR(150)"),
            ("description", "TEXT NULL"),
            ("status", "VARCHAR(50) DEFAULT 'active'"),
            ("plan", "VARCHAR(50) DEFAULT 'free'"),
            ("created_at", "TIMESTAMP DEFAULT NOW()"),
            ("updated_at", "TIMESTAMP NULL"),
            ("last_used_at", "TIMESTAMP NULL"),
        ],
        "indexes": [
            ("ix_projects_project_id", "project_id", False),
            ("ux_projects_project_id", "project_id", True),
            ("ix_projects_name", "name", False),
            ("ix_projects_slug", "slug", False),
            ("ux_projects_slug", "slug", True),
            ("ix_projects_status", "status", False),
            ("ix_projects_plan", "plan", False),
            ("ix_projects_created_at", "created_at", False),
        ],
    },
    "project_api_keys": {
        "columns": [
            ("key_id", "VARCHAR(50)"),
            ("project_id", "VARCHAR(50)"),
            ("name", "VARCHAR(150) NULL"),
            ("key_prefix", "VARCHAR(32)"),
            ("key_last4", "VARCHAR(4)"),
            ("key_hash", "VARCHAR(64)"),
            ("status", "VARCHAR(50) DEFAULT 'active'"),
            ("created_at", "TIMESTAMP DEFAULT NOW()"),
            ("last_used_at", "TIMESTAMP NULL"),
            ("revoked_at", "TIMESTAMP NULL"),
        ],
        "indexes": [
            ("ix_project_api_keys_key_id", "key_id", False),
            ("ux_project_api_keys_key_id", "key_id", True),
            ("ix_project_api_keys_project_id", "project_id", False),
            ("ix_project_api_keys_key_prefix", "key_prefix", False),
            ("ix_project_api_keys_key_hash", "key_hash", False),
            ("ux_project_api_keys_key_hash", "key_hash", True),
            ("ix_project_api_keys_status", "status", False),
            ("ix_project_api_keys_created_at", "created_at", False),
        ],
    },
}


def table_exists(connection, table_name: str) -> bool:
    result = connection.execute(
        text(
            """
            SELECT 1
            FROM information_schema.tables
            WHERE table_name = :table_name
            """
        ),
        {"table_name": table_name},
    )

    return result.first() is not None


def column_exists(connection, table_name: str, column_name: str) -> bool:
    result = connection.execute(
        text(
            """
            SELECT 1
            FROM information_schema.columns
            WHERE table_name = :table_name
              AND column_name = :column_name
            """
        ),
        {"table_name": table_name, "column_name": column_name},
    )

    return result.first() is not None


def index_exists(connection, table_name: str, index_name: str) -> bool:
    result = connection.execute(
        text(
            """
            SELECT 1
            FROM pg_indexes
            WHERE tablename = :table_name
              AND indexname = :index_name
            """
        ),
        {"table_name": table_name, "index_name": index_name},
    )

    return result.first() is not None


def ensure_table(connection, table_name: str) -> bool:
    existed_before = table_exists(connection, table_name)

    connection.execute(
        text(
            f"""
            CREATE TABLE IF NOT EXISTS {table_name} (
                id SERIAL PRIMARY KEY
            )
            """
        )
    )
    
    return existed_before


def ensure_columns(connection, table_name: str, columns):
    added = []
    existing = []

    for column_name, column_type in columns:
        existed_column = column_exists(connection, table_name, column_name)

        connection.execute(
            text(
                f"""
                ALTER TABLE {table_name}
                ADD COLUMN IF NOT EXISTS {column_name} {column_type}
                """
            )
        )

        if existed_column:
            existing.append(column_name)
        else:
            added.append(column_name)

    return added, existing


def ensure_indexes(connection, table_name: str, indexes):
    created = []
    existing = []

    for index_name, column_name, is_unique in indexes:
        existed_index = index_exists(connection, table_name, index_name)
        unique_sql = "UNIQUE" if is_unique else ""

        connection.execute(
            text(
                f"""
                CREATE {unique_sql} INDEX IF NOT EXISTS {index_name}
                ON {table_name} ({column_name})
                """
            )
        )

        if existed_index:
            existing.append(index_name)
        else:
            created.append(index_name)

    return created, existing


def normalize_defaults(connection):
    connection.execute(
        text(
            """
            UPDATE projects
            SET status = 'active'
            WHERE status IS NULL
            """
        )
    )
    connection.execute(
        text(
            """
            UPDATE projects
            SET plan = 'free'
            WHERE plan IS NULL
            """
        )
    )
    connection.execute(
        text(
            """
            UPDATE project_api_keys
            SET status = 'active'
            WHERE status IS NULL
            """
        )
    )


def main():
    summary = {}

    with engine.begin() as connection:
        for table_name, config in TABLES.items():
            existed_before = ensure_table(connection, table_name)
            added_columns, existing_columns = ensure_columns(
                connection,
                table_name,
                config["columns"],
            )
            created_indexes, existing_indexes = ensure_indexes(
                connection,
                table_name,
                config["indexes"],
            )
            summary[table_name] = {
                "existed_before": existed_before,
                "added_columns": added_columns,
                "existing_columns": existing_columns,
                "created_indexes": created_indexes,
                "existing_indexes": existing_indexes,
            }

        normalize_defaults(connection)

    print("Migracion V6 projects/api keys completada.")

    for table_name, info in summary.items():
        print(f"- tabla {table_name} existia: {'si' if info['existed_before'] else 'no'}")
        print(
            "  columnas agregadas: "
            f"{', '.join(info['added_columns']) if info['added_columns'] else 'ninguna'}"
        )
        print(
            "  columnas ya existentes: "
            f"{', '.join(info['existing_columns']) if info['existing_columns'] else 'ninguna'}"
        )
        print(
            "  indices creados: "
            f"{', '.join(info['created_indexes']) if info['created_indexes'] else 'ninguno'}"
        )
        print(
            "  indices ya existentes: "
            f"{', '.join(info['existing_indexes']) if info['existing_indexes'] else 'ninguno'}"
        )


if __name__ == "__main__":
    main()
