import sys
from pathlib import Path

from sqlalchemy import text


PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.app.database import engine  # noqa: E402


TABLES_TO_CLEAR = [
    "real_incidents",
    "ingested_sequence_predictions",
    "ingested_logs",
]

PROTECTED_TABLES = [
    "processed_logs",
    "log_sequences",
    "sequence_predictions",
    "model_metrics",
    "final_incidents",
]


def count_rows(connection, table_name: str) -> int:
    result = connection.execute(text(f"SELECT COUNT(*) FROM {table_name}"))
    return int(result.scalar() or 0)


def main():
    print("LogGuard AI - Clear Real Monitoring Data")
    print("=" * 48)
    print()
    print("Este script borrará SOLO datos de monitoreo real:")
    for table in TABLES_TO_CLEAR:
        print(f"- {table}")

    print()
    print("NO borrará datos de entrenamiento, métricas ni reportes históricos:")
    for table in PROTECTED_TABLES:
        print(f"- {table}")

    print()
    confirmation = input("Escribe CLEAR_REAL_MONITORING para continuar: ").strip()

    if confirmation != "CLEAR_REAL_MONITORING":
        print("Operación cancelada. No se borró nada.")
        return

    with engine.begin() as connection:
        print()
        print("Registros antes de limpiar:")

        before_counts = {}

        for table in TABLES_TO_CLEAR:
            before_counts[table] = count_rows(connection, table)
            print(f"- {table}: {before_counts[table]}")

        # El orden importa: primero incidentes, luego predicciones, luego logs base.
        for table in TABLES_TO_CLEAR:
            connection.execute(text(f"DELETE FROM {table}"))

        print()
        print("Registros después de limpiar:")

        for table in TABLES_TO_CLEAR:
            after_count = count_rows(connection, table)
            print(f"- {table}: {after_count}")

    print()
    print("Limpieza completada correctamente.")


if __name__ == "__main__":
    main()