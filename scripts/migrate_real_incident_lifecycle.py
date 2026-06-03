import sys
from pathlib import Path

from sqlalchemy import text


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.database import engine


COLUMNS = [
    ("status", "VARCHAR(50) DEFAULT 'open'"),
    ("acknowledged_at", "TIMESTAMP NULL"),
    ("acknowledged_by", "VARCHAR(100) NULL"),
    ("resolved_at", "TIMESTAMP NULL"),
    ("resolved_by", "VARCHAR(100) NULL"),
    ("resolution_note", "TEXT NULL"),
    ("updated_at", "TIMESTAMP NULL DEFAULT NOW()"),
    ("assignee", "VARCHAR(100) NULL"),
]


def column_exists(connection, column_name: str) -> bool:
    result = connection.execute(
        text(
            """
            SELECT 1
            FROM information_schema.columns
            WHERE table_name = 'real_incidents'
              AND column_name = :column_name
            """
        ),
        {"column_name": column_name},
    )

    return result.first() is not None


def main():
    checked = 0
    added = []
    existing = []

    with engine.begin() as connection:
        for column_name, column_type in COLUMNS:
            checked += 1
            existed_before = column_exists(connection, column_name)

            connection.execute(
                text(
                    f"""
                    ALTER TABLE real_incidents
                    ADD COLUMN IF NOT EXISTS {column_name} {column_type}
                    """
                )
            )

            if existed_before:
                existing.append(column_name)
            else:
                added.append(column_name)

        connection.execute(
            text(
                """
                UPDATE real_incidents
                SET status = 'open'
                WHERE status IS NULL
                """
            )
        )

    print("Migracion real_incidents lifecycle completada.")
    print(f"- columnas revisadas: {checked}")
    print(f"- columnas agregadas: {', '.join(added) if added else 'ninguna'}")
    print(f"- columnas ya existentes: {', '.join(existing) if existing else 'ninguna'}")


if __name__ == "__main__":
    main()
