import sys
from pathlib import Path

from sqlalchemy import text


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.database import engine


COLUMNS = [
    ("event_id", "VARCHAR(50) UNIQUE"),
    ("channel", "VARCHAR(50) DEFAULT 'webhook'"),
    ("event_type", "VARCHAR(100)"),
    ("incident_id", "VARCHAR(80) NULL"),
    ("severity", "VARCHAR(50) NULL"),
    ("status", "VARCHAR(50) DEFAULT 'pending'"),
    ("target", "TEXT NULL"),
    ("payload", "JSON NULL"),
    ("response_status_code", "INTEGER NULL"),
    ("response_body", "TEXT NULL"),
    ("error_message", "TEXT NULL"),
    ("created_at", "TIMESTAMP DEFAULT NOW()"),
    ("sent_at", "TIMESTAMP NULL"),
]

INDEXES = [
    ("ix_notification_events_event_id", "event_id"),
    ("ix_notification_events_status", "status"),
    ("ix_notification_events_channel", "channel"),
    ("ix_notification_events_event_type", "event_type"),
    ("ix_notification_events_incident_id", "incident_id"),
    ("ix_notification_events_severity", "severity"),
    ("ix_notification_events_created_at", "created_at"),
]


def table_exists(connection) -> bool:
    result = connection.execute(
        text(
            """
            SELECT 1
            FROM information_schema.tables
            WHERE table_name = 'notification_events'
            """
        )
    )

    return result.first() is not None


def column_exists(connection, column_name: str) -> bool:
    result = connection.execute(
        text(
            """
            SELECT 1
            FROM information_schema.columns
            WHERE table_name = 'notification_events'
              AND column_name = :column_name
            """
        ),
        {"column_name": column_name},
    )

    return result.first() is not None


def index_exists(connection, index_name: str) -> bool:
    result = connection.execute(
        text(
            """
            SELECT 1
            FROM pg_indexes
            WHERE tablename = 'notification_events'
              AND indexname = :index_name
            """
        ),
        {"index_name": index_name},
    )

    return result.first() is not None


def main():
    added_columns = []
    existing_columns = []
    created_indexes = []
    existing_indexes = []

    with engine.begin() as connection:
        existed_before = table_exists(connection)

        connection.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS notification_events (
                    id SERIAL PRIMARY KEY
                )
                """
            )
        )

        for column_name, column_type in COLUMNS:
            existed_column = column_exists(connection, column_name)

            connection.execute(
                text(
                    f"""
                    ALTER TABLE notification_events
                    ADD COLUMN IF NOT EXISTS {column_name} {column_type}
                    """
                )
            )

            if existed_column:
                existing_columns.append(column_name)
            else:
                added_columns.append(column_name)

        connection.execute(
            text(
                """
                UPDATE notification_events
                SET channel = 'webhook'
                WHERE channel IS NULL
                """
            )
        )
        connection.execute(
            text(
                """
                UPDATE notification_events
                SET status = 'pending'
                WHERE status IS NULL
                """
            )
        )

        for index_name, column_name in INDEXES:
            existed_index = index_exists(connection, index_name)

            connection.execute(
                text(
                    f"""
                    CREATE INDEX IF NOT EXISTS {index_name}
                    ON notification_events ({column_name})
                    """
                )
            )

            if existed_index:
                existing_indexes.append(index_name)
            else:
                created_indexes.append(index_name)

    print("Migracion notification_events completada.")
    print(f"- tabla existia: {'si' if existed_before else 'no'}")
    print(f"- columnas agregadas: {', '.join(added_columns) if added_columns else 'ninguna'}")
    print(f"- columnas ya existentes: {', '.join(existing_columns) if existing_columns else 'ninguna'}")
    print(f"- indices creados: {', '.join(created_indexes) if created_indexes else 'ninguno'}")
    print(f"- indices ya existentes: {', '.join(existing_indexes) if existing_indexes else 'ninguno'}")


if __name__ == "__main__":
    main()
