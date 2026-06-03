import sys
from pathlib import Path

from sqlalchemy import text


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.database import engine


PROJECT_ID_TABLES = [
    "ingested_logs",
    "ingested_sequence_predictions",
    "real_incidents",
    "notification_events",
]

USAGE_TABLES = {
    "project_usage_daily": {
        "columns": [
            ("project_id", "VARCHAR(50)"),
            ("date", "DATE"),
            ("plan", "VARCHAR(50)"),
            ("logs_ingested", "INTEGER DEFAULT 0"),
            ("batches_ingested", "INTEGER DEFAULT 0"),
            ("async_tasks_created", "INTEGER DEFAULT 0"),
            ("predictions_created", "INTEGER DEFAULT 0"),
            ("incidents_created", "INTEGER DEFAULT 0"),
            ("notifications_sent", "INTEGER DEFAULT 0"),
            ("notifications_failed", "INTEGER DEFAULT 0"),
            ("created_at", "TIMESTAMP DEFAULT NOW()"),
            ("updated_at", "TIMESTAMP NULL"),
        ],
        "indexes": [
            ("ix_project_usage_daily_project_id", "project_id", False),
            ("ix_project_usage_daily_date", "date", False),
            ("ix_project_usage_daily_plan", "plan", False),
            ("ix_project_usage_daily_created_at", "created_at", False),
            ("uq_project_usage_daily_project_date", "project_id, date", True),
        ],
    },
    "project_usage_events": {
        "columns": [
            ("event_id", "VARCHAR(50)"),
            ("project_id", "VARCHAR(50)"),
            ("event_type", "VARCHAR(100)"),
            ("quantity", "INTEGER DEFAULT 1"),
            ("metadata_json", "JSON NULL"),
            ("created_at", "TIMESTAMP DEFAULT NOW()"),
        ],
        "indexes": [
            ("ix_project_usage_events_event_id", "event_id", False),
            ("ux_project_usage_events_event_id", "event_id", True),
            ("ix_project_usage_events_project_id", "project_id", False),
            ("ix_project_usage_events_event_type", "event_type", False),
            ("ix_project_usage_events_created_at", "created_at", False),
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


def ensure_project_id_columns(connection):
    added = []
    existing = []

    for table_name in PROJECT_ID_TABLES:
        existed_column = ensure_column(connection, table_name, "project_id", "VARCHAR(50) NULL")
        existed_index = ensure_index(
            connection,
            table_name,
            f"ix_{table_name}_project_id",
            "project_id",
            False,
        )

        if existed_column:
            existing.append(table_name)
        else:
            added.append(table_name)

    return {
        "added": added,
        "existing": existing,
    }


def ensure_usage_tables(connection):
    summary = {}

    for table_name, config in USAGE_TABLES.items():
        existed_before = ensure_table(connection, table_name)
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
            existed_index = ensure_index(
                connection,
                table_name,
                index_name,
                column_sql,
                unique,
            )

            if existed_index:
                existing_indexes.append(index_name)
            else:
                created_indexes.append(index_name)

        summary[table_name] = {
            "existed_before": existed_before,
            "added_columns": added_columns,
            "existing_columns": existing_columns,
            "created_indexes": created_indexes,
            "existing_indexes": existing_indexes,
        }

    return summary


def normalize_defaults(connection):
    for column_name in (
        "logs_ingested",
        "batches_ingested",
        "async_tasks_created",
        "predictions_created",
        "incidents_created",
        "notifications_sent",
        "notifications_failed",
    ):
        connection.execute(
            text(
                f"""
                UPDATE project_usage_daily
                SET {column_name} = 0
                WHERE {column_name} IS NULL
                """
            )
        )

    connection.execute(
        text(
            """
            UPDATE project_usage_events
            SET quantity = 1
            WHERE quantity IS NULL
            """
        )
    )


def main():
    with engine.begin() as connection:
        project_id_summary = ensure_project_id_columns(connection)
        table_summary = ensure_usage_tables(connection)
        normalize_defaults(connection)

    print("Migracion V6 usage tracking completada.")
    print(
        "- project_id agregado en tablas: "
        f"{', '.join(project_id_summary['added']) if project_id_summary['added'] else 'ninguna'}"
    )
    print(
        "- project_id ya existente en tablas: "
        f"{', '.join(project_id_summary['existing']) if project_id_summary['existing'] else 'ninguna'}"
    )

    for table_name, info in table_summary.items():
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
