from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]


COMMANDS: list[tuple[str, list[str]]] = [
    (
        "Create base database tables",
        [sys.executable, "-m", "backend.app.database"],
    ),
    (
        "Apply real incident lifecycle migration",
        [sys.executable, str(ROOT_DIR / "scripts" / "migrate_real_incident_lifecycle.py")],
    ),
    (
        "Apply notification events migration",
        [sys.executable, str(ROOT_DIR / "scripts" / "migrate_notification_events.py")],
    ),
    (
        "Apply V6 projects and API keys migration",
        [sys.executable, str(ROOT_DIR / "scripts" / "migrate_v6_projects_api_keys.py")],
    ),
    (
        "Apply V6 usage tracking migration",
        [sys.executable, str(ROOT_DIR / "scripts" / "migrate_v6_usage_tracking.py")],
    ),
    (
        "Apply V6 retraining migration",
        [sys.executable, str(ROOT_DIR / "scripts" / "migrate_v6_retraining.py")],
    ),
    (
        "Apply V6 model registry migration",
        [sys.executable, str(ROOT_DIR / "scripts" / "migrate_v6_model_registry.py")],
    ),
]


def run_step(label: str, command: list[str]) -> None:
    print(f"\n[LogGuard Migration] {label}")
    print("[LogGuard Migration] Command:", " ".join(command))

    result = subprocess.run(command, cwd=ROOT_DIR)

    if result.returncode != 0:
        raise SystemExit(
            f"[LogGuard Migration] Failed: {label} "
            f"(exit code {result.returncode})"
        )

    print(f"[LogGuard Migration] OK: {label}")


def main() -> None:
    print("[LogGuard Migration] Starting all migrations...")

    for label, command in COMMANDS:
        run_step(label, command)

    print("\n[LogGuard Migration] All migrations completed successfully.")


if __name__ == "__main__":
    main()
