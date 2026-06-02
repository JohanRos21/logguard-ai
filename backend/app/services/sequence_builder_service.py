import os
import json
import pandas as pd


INPUT_PATH = "data/processed/logs_processed.csv"
OUTPUT_PATH = "data/processed/log_sequences.csv"
REPORT_PATH = "reports/sequence_dataset_report.json"

# Para Transformer conviene una ventana más larga que en V1.
# Con 20 eventos, el modelo puede ver patrones como:
# login_failed repetidos → login_success
# o payment_failed → server_error → database_timeout.
WINDOW_SIZE = 20
STRIDE = 5
GROUP_BY_COLUMN = "ip"


REQUIRED_COLUMNS = [
    "timestamp",
    "user_id",
    "ip",
    "method",
    "route",
    "status_code",
    "response_time_ms",
    "event_type",
    "severity",
    "risk_score",
    "is_error",
    "is_server_error",
    "is_slow",
    "is_very_slow",
    "is_critical_route",
    "is_login_failed",
    "is_unauthorized",
    "is_payment_failed",
    "is_database_timeout",
]


def load_processed_logs(input_path=INPUT_PATH):
    if not os.path.exists(input_path):
        raise FileNotFoundError(
            f"No se encontró {input_path}. Primero ejecuta log_processor_service.py"
        )

    df = pd.read_csv(input_path, encoding="utf-8-sig")

    missing_columns = [
        column for column in REQUIRED_COLUMNS
        if column not in df.columns
    ]

    if missing_columns:
        raise ValueError(f"Faltan columnas necesarias para construir secuencias: {missing_columns}")

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp"])

    df = df.sort_values("timestamp").reset_index(drop=True)

    return df


def sequence_to_text(values):
    return " ".join([str(value) for value in values])


def has_controlled_labels(sequence_df):
    return "scenario_label" in sequence_df.columns


def infer_sequence_label_from_scenario(sequence_df):
    """
    Para el dataset controlado de V2, scenario_label representa la intención real
    del escenario generado.

    Esto es importante porque los falsos positivos entrenables pueden tener
    eventos sospechosos, como login_failed, slow_response o un 403 aislado,
    pero siguen siendo normales.

    Por eso, si existe scenario_label, lo usamos como referencia principal.
    """

    labels = sequence_df["scenario_label"].astype(str).str.lower().tolist()

    anomaly_count = labels.count("anomaly")
    normal_count = labels.count("normal")

    # Si la secuencia contiene al menos una parte diseñada como anomalía,
    # se etiqueta como anomaly. Esto permite detectar variantes low,
    # escenarios mixtos y anomalías sutiles.
    if anomaly_count > 0:
        return "anomaly"

    if normal_count > 0:
        return "normal"

    # Si aparece un label desconocido, no detenemos el pipeline.
    # Se usa fallback por reglas.
    return None


def infer_sequence_label_by_rules(sequence_df):
    """
    Fallback para datasets antiguos que no tienen scenario_label.

    Esta lógica viene de la primera versión del sequence builder:
    etiqueta anomaly cuando detecta acumulación de señales peligrosas.
    """

    max_risk_score = int(sequence_df["risk_score"].max())

    critical_count = int((sequence_df["severity"] == "critical").sum())
    warning_count = int((sequence_df["severity"] == "warning").sum())

    login_failed_count = int(sequence_df["is_login_failed"].sum())
    unauthorized_count = int(sequence_df["is_unauthorized"].sum())
    payment_failed_count = int(sequence_df["is_payment_failed"].sum())
    database_timeout_count = int(sequence_df["is_database_timeout"].sum())
    server_error_count = int(sequence_df["is_server_error"].sum())
    very_slow_count = int(sequence_df["is_very_slow"].sum())

    brute_force_pattern = login_failed_count >= 5
    unauthorized_pattern = unauthorized_count >= 2
    payment_pattern = payment_failed_count >= 2
    database_pattern = database_timeout_count >= 2
    server_error_pattern = server_error_count >= 2
    performance_pattern = very_slow_count >= 2

    high_risk_pattern = max_risk_score >= 18 and critical_count >= 1
    repeated_warning_pattern = warning_count >= 5
    repeated_critical_pattern = critical_count >= 2

    is_anomaly = (
        brute_force_pattern
        or unauthorized_pattern
        or payment_pattern
        or database_pattern
        or server_error_pattern
        or performance_pattern
        or high_risk_pattern
        or repeated_warning_pattern
        or repeated_critical_pattern
    )

    return "anomaly" if is_anomaly else "normal"


def infer_sequence_label(sequence_df):
    """
    Lógica híbrida:

    1. Si el dataset viene del generador controlado V2 y tiene scenario_label,
       se usa scenario_label como ground truth.

    2. Si el dataset no tiene scenario_label, se usan reglas automáticas.

    Así el sequence builder funciona con datasets nuevos y antiguos.
    """

    if has_controlled_labels(sequence_df):
        scenario_label = infer_sequence_label_from_scenario(sequence_df)

        if scenario_label is not None:
            return scenario_label

    return infer_sequence_label_by_rules(sequence_df)


def infer_sequence_reason(sequence_df, label):
    if has_controlled_labels(sequence_df):
        scenarios = sorted(sequence_df["scenario"].astype(str).unique().tolist()) if "scenario" in sequence_df.columns else []
        scenario_labels = sorted(sequence_df["scenario_label"].astype(str).unique().tolist())

        if label == "anomaly":
            return (
                "Secuencia etiquetada como anomaly usando scenario_label del dataset controlado. "
                f"Escenarios presentes: {', '.join(scenarios)}. "
                f"Labels presentes: {', '.join(scenario_labels)}."
            )

        return (
            "Secuencia etiquetada como normal usando scenario_label del dataset controlado. "
            f"Escenarios presentes: {', '.join(scenarios)}. "
            f"Labels presentes: {', '.join(scenario_labels)}."
        )

    if label == "normal":
        return "Secuencia sin señales críticas repetidas ni patrón anómalo evidente."

    reasons = []

    if sequence_df["is_login_failed"].sum() >= 5:
        reasons.append("múltiples login_failed")

    if sequence_df["is_unauthorized"].sum() >= 2:
        reasons.append("accesos no autorizados repetidos")

    if sequence_df["is_payment_failed"].sum() >= 2:
        reasons.append("pagos fallidos repetidos")

    if sequence_df["is_database_timeout"].sum() >= 2:
        reasons.append("timeouts de base de datos repetidos")

    if sequence_df["is_server_error"].sum() >= 2:
        reasons.append("errores 5xx repetidos")

    if sequence_df["is_very_slow"].sum() >= 2:
        reasons.append("respuestas muy lentas repetidas")

    if sequence_df["risk_score"].max() >= 18:
        reasons.append("risk_score alto")

    if not reasons:
        reasons.append("combinación de señales de riesgo en la secuencia")

    return "Secuencia anómala por: " + ", ".join(reasons) + "."


def build_sequence_record(sequence_id, entity_type, entity_id, sequence_df):
    label = infer_sequence_label(sequence_df)
    reason = infer_sequence_reason(sequence_df, label)

    event_sequence = sequence_to_text(sequence_df["event_type"].tolist())
    route_sequence = sequence_to_text(sequence_df["route"].tolist())
    status_sequence = sequence_to_text(sequence_df["status_code"].tolist())
    method_sequence = sequence_to_text(sequence_df["method"].tolist())

    record = {
        "sequence_id": f"SEQ-{sequence_id:05d}",
        "entity_type": entity_type,
        "entity_id": entity_id,
        "start_time": sequence_df["timestamp"].min(),
        "end_time": sequence_df["timestamp"].max(),
        "window_size": len(sequence_df),

        "event_sequence": event_sequence,
        "route_sequence": route_sequence,
        "status_sequence": status_sequence,
        "method_sequence": method_sequence,

        "avg_response_time": float(sequence_df["response_time_ms"].mean()),
        "max_response_time": float(sequence_df["response_time_ms"].max()),
        "max_risk_score": int(sequence_df["risk_score"].max()),

        "critical_count": int((sequence_df["severity"] == "critical").sum()),
        "warning_count": int((sequence_df["severity"] == "warning").sum()),
        "error_count": int(sequence_df["is_error"].sum()),
        "server_error_count": int(sequence_df["is_server_error"].sum()),
        "slow_count": int(sequence_df["is_slow"].sum()),
        "very_slow_count": int(sequence_df["is_very_slow"].sum()),
        "critical_route_count": int(sequence_df["is_critical_route"].sum()),

        "login_failed_count": int(sequence_df["is_login_failed"].sum()),
        "unauthorized_count": int(sequence_df["is_unauthorized"].sum()),
        "payment_failed_count": int(sequence_df["is_payment_failed"].sum()),
        "database_timeout_count": int(sequence_df["is_database_timeout"].sum()),

        "label": label,
        "label_id": 1 if label == "anomaly" else 0,
        "reason": reason,
    }

    # Guardamos trazabilidad del dataset controlado.
    # Esto ayuda a revisar si el Transformer aprende desde escenarios correctos.
    if "scenario" in sequence_df.columns:
        record["scenario_sequence"] = sequence_to_text(sequence_df["scenario"].tolist())
        record["main_scenarios"] = ", ".join(
            sorted(sequence_df["scenario"].astype(str).unique().tolist())
        )

    if "scenario_label" in sequence_df.columns:
        record["scenario_label_sequence"] = sequence_to_text(sequence_df["scenario_label"].tolist())
        record["scenario_label_distribution"] = json.dumps(
            sequence_df["scenario_label"].value_counts().to_dict(),
            ensure_ascii=False
        )

    return record


def build_sequences_for_group(group_df, entity_type, entity_id, start_sequence_id):
    records = []
    sequence_id = start_sequence_id

    group_df = group_df.sort_values("timestamp").reset_index(drop=True)

    if len(group_df) < WINDOW_SIZE:
        return records, sequence_id

    """
    Ventana deslizante para secuencias.

    Con WINDOW_SIZE=20 y STRIDE=5:
    - Secuencia 1: eventos 0 al 19
    - Secuencia 2: eventos 5 al 24
    - Secuencia 3: eventos 10 al 29

    Esto permite que el Transformer vea patrones más largos sin reducir demasiado
    la cantidad de ejemplos.
    """

    for start_index in range(0, len(group_df) - WINDOW_SIZE + 1, STRIDE):
        end_index = start_index + WINDOW_SIZE
        sequence_df = group_df.iloc[start_index:end_index]

        record = build_sequence_record(
            sequence_id=sequence_id,
            entity_type=entity_type,
            entity_id=entity_id,
            sequence_df=sequence_df,
        )

        records.append(record)
        sequence_id += 1

    return records, sequence_id


def build_log_sequences(df, group_by_column=GROUP_BY_COLUMN):
    if group_by_column not in df.columns:
        raise ValueError(f"No existe la columna para agrupar secuencias: {group_by_column}")

    all_records = []
    sequence_id = 1

    """
    Agrupamos por IP porque muchos patrones de seguridad aparecen mejor
    cuando se observa el comportamiento completo de una misma IP.
    """

    for entity_id, group_df in df.groupby(group_by_column):
        records, sequence_id = build_sequences_for_group(
            group_df=group_df,
            entity_type=group_by_column,
            entity_id=entity_id,
            start_sequence_id=sequence_id,
        )

        all_records.extend(records)

    sequences_df = pd.DataFrame(all_records)

    return sequences_df


def build_report(sequences_df):
    if sequences_df.empty:
        return {
            "total_sequences": 0,
            "window_size": WINDOW_SIZE,
            "stride": STRIDE,
            "group_by": GROUP_BY_COLUMN,
            "label_distribution": {},
            "top_entities": {},
        }

    report = {
        "total_sequences": int(len(sequences_df)),
        "window_size": WINDOW_SIZE,
        "stride": STRIDE,
        "group_by": GROUP_BY_COLUMN,
        "label_distribution": sequences_df["label"].value_counts().to_dict(),
        "top_entities": sequences_df["entity_id"].value_counts().head(10).to_dict(),
        "avg_response_time_mean": float(sequences_df["avg_response_time"].mean()),
        "max_risk_score_mean": float(sequences_df["max_risk_score"].mean()),
        "anomaly_rate": float((sequences_df["label"] == "anomaly").mean()),
    }

    if "main_scenarios" in sequences_df.columns:
        report["top_scenarios"] = sequences_df["main_scenarios"].value_counts().head(20).to_dict()

    return report


def save_outputs(sequences_df, report):
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    os.makedirs(os.path.dirname(REPORT_PATH), exist_ok=True)

    sequences_df.to_csv(OUTPUT_PATH, index=False, encoding="utf-8-sig")

    with open(REPORT_PATH, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4, ensure_ascii=False, default=str)


def main():
    print("Cargando logs procesados...")
    df = load_processed_logs()

    print("Construyendo secuencias para Transformer...")
    sequences_df = build_log_sequences(df)

    report = build_report(sequences_df)
    save_outputs(sequences_df, report)

    print(f"\nSecuencias guardadas en: {OUTPUT_PATH}")
    print(f"Reporte guardado en: {REPORT_PATH}")

    print("\nResumen del dataset secuencial:")
    print(json.dumps(report, indent=4, ensure_ascii=False))

    if not sequences_df.empty:
        print("\nEjemplo de secuencia:")
        columns = [
            "sequence_id",
            "entity_type",
            "entity_id",
            "event_sequence",
            "max_risk_score",
            "label",
            "reason",
        ]

        print(sequences_df[columns].head(3).to_string(index=False))


if __name__ == "__main__":
    main()