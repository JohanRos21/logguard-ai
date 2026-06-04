import sys
from pathlib import Path

from sqlalchemy import text


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.database import engine


TABLES = {
    "incident_feedback": {
        "columns": [
            ("feedback_id", "VARCHAR(50)"),
            ("project_id", "VARCHAR(50) NULL"),
            ("incident_id", "VARCHAR(80)"),
            ("prediction_id", "VARCHAR(80) NULL"),
            ("label", "VARCHAR(50)"),
            ("confidence", "FLOAT NULL"),
            ("reviewer", "VARCHAR(150) NULL"),
            ("note", "TEXT NULL"),
            ("source", "VARCHAR(50) DEFAULT 'manual'"),
            ("created_at", "TIMESTAMP DEFAULT NOW()"),
            ("updated_at", "TIMESTAMP NULL"),
        ],
        "indexes": [
            ("ix_incident_feedback_feedback_id", "feedback_id", False),
            ("ux_incident_feedback_feedback_id", "feedback_id", True),
            ("ix_incident_feedback_project_id", "project_id", False),
            ("ix_incident_feedback_incident_id", "incident_id", False),
            ("ix_incident_feedback_prediction_id", "prediction_id", False),
            ("ix_incident_feedback_label", "label", False),
            ("ix_incident_feedback_source", "source", False),
            ("ix_incident_feedback_created_at", "created_at", False),
        ],
    },
    "retraining_jobs": {
        "columns": [
            ("job_id", "VARCHAR(50)"),
            ("project_id", "VARCHAR(50) NULL"),
            ("status", "VARCHAR(50) DEFAULT 'pending'"),
            ("mode", "VARCHAR(50) DEFAULT 'dataset_only'"),
            ("requested_by", "VARCHAR(150) NULL"),
            ("feedback_count", "INTEGER DEFAULT 0"),
            ("dataset_size", "INTEGER DEFAULT 0"),
            ("parameters_json", "TEXT NULL"),
            ("metrics_json", "TEXT NULL"),
            ("output_dataset_path", "TEXT NULL"),
            ("output_artifact_path", "TEXT NULL"),
            ("error_message", "TEXT NULL"),
            ("created_at", "TIMESTAMP DEFAULT NOW()"),
            ("started_at", "TIMESTAMP NULL"),
            ("completed_at", "TIMESTAMP NULL"),
        ],
        "indexes": [
            ("ix_retraining_jobs_job_id", "job_id", False),
            ("ux_retraining_jobs_job_id", "job_id", True),
            ("ix_retraining_jobs_project_id", "project_id", False),
            ("ix_retraining_jobs_status", "status", False),
            ("ix_retraining_jobs_mode", "mode", False),
            ("ix_retraining_jobs_created_at", "created_at", False),
        ],
    },
    "model_versions": {
        "columns": [
            ("model_version_id", "VARCHAR(50)"),
            ("project_id", "VARCHAR(50) NULL"),
            ("model_name", "VARCHAR(150) DEFAULT 'sequence_transformer'"),
            ("version_tag", "VARCHAR(150)"),
            ("status", "VARCHAR(50) DEFAULT 'candidate'"),
            ("source_job_id", "VARCHAR(50) NULL"),
            ("artifact_path", "TEXT NULL"),
            ("metrics_json", "TEXT NULL"),
            ("created_at", "TIMESTAMP DEFAULT NOW()"),
            ("activated_at", "TIMESTAMP NULL"),
            ("archived_at", "TIMESTAMP NULL"),
        ],
        "indexes": [
            ("ix_model_versions_model_version_id", "model_version_id", False),
            ("ux_model_versions_model_version_id", "model_version_id", True),
            ("ix_model_versions_project_id", "project_id", False),
            ("ix_model_versions_model_name", "model_name", False),
            ("ix_model_versions_version_tag", "version_tag", False),
            ("ix_model_versions_status", "status", False),
            ("ix_model_versions_source_job_id", "source_job_id", False),
            ("ix_model_versions_created_at", "created_at", False),
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


def ensure_tables(connection):
    summary = {}

    for table_name, config in TABLES.items():
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
    connection.execute(
        text(
            """
            UPDATE incident_feedback
            SET source = 'manual'
            WHERE source IS NULL
            """
        )
    )

    for table_name, column_name, value in (
        ("retraining_jobs", "status", "pending"),
        ("retraining_jobs", "mode", "dataset_only"),
        ("model_versions", "model_name", "sequence_transformer"),
        ("model_versions", "status", "candidate"),
    ):
        connection.execute(
            text(
                f"""
                UPDATE {table_name}
                SET {column_name} = :value
                WHERE {column_name} IS NULL
                """
            ),
            {"value": value},
        )

    for column_name in ("feedback_count", "dataset_size"):
        connection.execute(
            text(
                f"""
                UPDATE retraining_jobs
                SET {column_name} = 0
                WHERE {column_name} IS NULL
                """
            )
        )


def main():
    with engine.begin() as connection:
        table_summary = ensure_tables(connection)
        normalize_defaults(connection)

    print("Migracion V6 retraining completada.")

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
