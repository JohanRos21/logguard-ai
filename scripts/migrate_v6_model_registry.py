import sys
from pathlib import Path

from sqlalchemy import text


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.database import engine


TABLES = {
    "retraining_jobs": {
        "columns": [
            ("scope", "VARCHAR(50) DEFAULT 'global'"),
            ("actual_training_requested", "BOOLEAN DEFAULT FALSE"),
            ("actual_training_executed", "BOOLEAN DEFAULT FALSE"),
            ("active_model_replaced", "BOOLEAN DEFAULT FALSE"),
        ],
        "indexes": [
            ("ix_retraining_jobs_scope", "scope", False),
        ],
    },
    "model_versions": {
        "columns": [
            ("scope", "VARCHAR(50) DEFAULT 'global'"),
            ("is_default", "BOOLEAN DEFAULT FALSE"),
            ("activated_by", "VARCHAR(150) NULL"),
            ("activation_note", "TEXT NULL"),
        ],
        "indexes": [
            ("ix_model_versions_scope", "scope", False),
            ("ix_model_versions_is_default", "is_default", False),
        ],
    },
}


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


def ensure_column(connection, table_name: str, column_name: str, column_type: str) -> bool:
    existed_before = column_exists(connection, table_name, column_name)

    connection.execute(
        text(
            f"""
            ALTER TABLE {table_name}
            ADD COLUMN IF NOT EXISTS {column_name} {column_type}
            """
        )
    )

    return existed_before


def ensure_index(connection, table_name: str, index_name: str, column_sql: str, unique: bool) -> bool:
    existed_before = index_exists(connection, table_name, index_name)
    unique_sql = "UNIQUE" if unique else ""

    connection.execute(
        text(
            f"""
            CREATE {unique_sql} INDEX IF NOT EXISTS {index_name}
            ON {table_name} ({column_sql})
            """
        )
    )

    return existed_before


def ensure_registry_columns(connection):
    summary = {}

    for table_name, config in TABLES.items():
        added_columns = []
        existing_columns = []
        created_indexes = []
        existing_indexes = []

        for column_name, column_type in config["columns"]:
            existed_column = ensure_column(connection, table_name, column_name, column_type)

            if existed_column:
                existing_columns.append(column_name)
            else:
                added_columns.append(column_name)

        for index_name, column_sql, unique in config["indexes"]:
            existed_index = ensure_index(connection, table_name, index_name, column_sql, unique)

            if existed_index:
                existing_indexes.append(index_name)
            else:
                created_indexes.append(index_name)

        summary[table_name] = {
            "added_columns": added_columns,
            "existing_columns": existing_columns,
            "created_indexes": created_indexes,
            "existing_indexes": existing_indexes,
        }

    return summary


def normalize_defaults(connection):
    connection.execute(
        text(
            """
            UPDATE retraining_jobs
            SET scope = CASE
                WHEN project_id IS NULL THEN 'global'
                ELSE 'project'
            END
            WHERE scope IS NULL
            """
        )
    )
    connection.execute(
        text(
            """
            UPDATE model_versions
            SET scope = CASE
                WHEN project_id IS NULL THEN 'global'
                ELSE 'project'
            END
            WHERE scope IS NULL
            """
        )
    )

    for column_name in (
        "actual_training_requested",
        "actual_training_executed",
        "active_model_replaced",
    ):
        connection.execute(
            text(
                f"""
                UPDATE retraining_jobs
                SET {column_name} = FALSE
                WHERE {column_name} IS NULL
                """
            )
        )

    connection.execute(
        text(
            """
            UPDATE model_versions
            SET is_default = FALSE
            WHERE is_default IS NULL
            """
        )
    )


def main():
    with engine.begin() as connection:
        summary = ensure_registry_columns(connection)
        normalize_defaults(connection)

    print("Migracion V6 model registry completada.")

    for table_name, info in summary.items():
        print(f"- tabla {table_name}")
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
