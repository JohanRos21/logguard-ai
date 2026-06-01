import os
import json
import joblib
import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


INPUT_PATH = "data/processed/logs_processed.csv"

MODEL_DIR = "models/anomaly_detector"
MODEL_PATH = os.path.join(MODEL_DIR, "isolation_forest.pkl")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.pkl")
FEATURE_COLUMNS_PATH = os.path.join(MODEL_DIR, "feature_columns.json")
METRICS_PATH = os.path.join(MODEL_DIR, "metrics.json")

REPORTS_DIR = "reports"
ANOMALIES_CSV_PATH = os.path.join(REPORTS_DIR, "ml_anomalies.csv")
ANOMALY_REPORT_PATH = os.path.join(REPORTS_DIR, "anomaly_detection_report.json")


# Columnas que usará el modelo para detectar comportamiento raro.
# No usamos texto crudo; usamos señales numéricas creadas por el procesador.
FEATURE_COLUMNS = [
    "status_code",
    "response_time_ms",
    "hour",
    "day_of_week",
    "minute",
    "is_weekend",
    "is_night",
    "is_success",
    "is_client_error",
    "is_server_error",
    "is_error",
    "is_slow",
    "is_very_slow",
    "is_critical_route",
    "is_auth_event",
    "is_payment_event",
    "is_warning_event",
    "is_critical_event",
    "is_login_failed",
    "is_unauthorized",
    "is_payment_failed",
    "is_database_timeout",
    "requests_by_ip",
    "requests_by_user",
    "requests_by_route",
    "errors_by_ip",
    "errors_by_route",
    "failed_logins_by_ip",
    "failed_logins_by_user",
    "unauthorized_by_ip",
    "payment_failures_by_route",
    "avg_response_by_route",
    "max_response_by_route",
    "method_code",
    "route_code",
    "event_type_code",
    "risk_score",
]


def load_processed_logs(input_path=INPUT_PATH):
    if not os.path.exists(input_path):
        raise FileNotFoundError(
            f"No se encontró {input_path}. Primero ejecuta log_processor_service.py"
        )

    df = pd.read_csv(input_path, encoding="utf-8-sig")

    missing_columns = [
        column for column in FEATURE_COLUMNS
        if column not in df.columns
    ]

    if missing_columns:
        raise ValueError(f"Faltan columnas para entrenar el modelo: {missing_columns}")

    return df


def prepare_training_data(df):
    # Isolation Forest trabaja con valores numéricos.
    # Por eso tomamos solo las features creadas previamente por el procesador.
    X = df[FEATURE_COLUMNS].copy()

    # Si por alguna razón quedó un valor vacío, lo reemplazamos por 0.
    # Esto evita que el entrenamiento se detenga por datos incompletos.
    X = X.fillna(0)

    scaler = StandardScaler()

    # El escalado evita que columnas grandes como response_time_ms dominen
    # sobre columnas binarias como is_error o is_payment_failed.
    X_scaled = scaler.fit_transform(X)

    return X, X_scaled, scaler


def train_isolation_forest(X_scaled):
    # Isolation Forest detecta puntos que se comportan diferente al patrón general.
    # contamination indica una estimación del porcentaje de datos que podrían ser anomalías.
    # En logs reales este valor se ajustaría con validación; para el MVP usamos 8%.
    model = IsolationForest(
        n_estimators=200,
        contamination=0.08,
        random_state=42,
        n_jobs=-1
    )

    model.fit(X_scaled)

    return model


def add_anomaly_predictions(df, model, X_scaled):
    result_df = df.copy()

    # predict devuelve:
    #  1  = comportamiento normal
    # -1  = anomalía
    raw_predictions = model.predict(X_scaled)

    # decision_function devuelve un score:
    # mientras más bajo, más anómalo es el registro.
    anomaly_scores = model.decision_function(X_scaled)

    result_df["ml_prediction"] = raw_predictions
    result_df["is_ml_anomaly"] = (raw_predictions == -1).astype(int)
    result_df["anomaly_score"] = anomaly_scores

    return result_df


def build_report(result_df):
    total_logs = len(result_df)
    total_anomalies = int(result_df["is_ml_anomaly"].sum())
    anomaly_rate = total_anomalies / total_logs if total_logs > 0 else 0

    anomalies_df = result_df[result_df["is_ml_anomaly"] == 1]

    report = {
        "model": "IsolationForest",
        "total_logs": total_logs,
        "total_anomalies": total_anomalies,
        "anomaly_rate": anomaly_rate,
        "contamination": 0.08,
        "features_used": FEATURE_COLUMNS,
        "anomalies_by_severity": anomalies_df["severity"].value_counts().to_dict()
        if not anomalies_df.empty else {},
        "anomalies_by_event_type": anomalies_df["event_type"].value_counts().to_dict()
        if not anomalies_df.empty else {},
        "top_anomalous_routes": anomalies_df["route"].value_counts().head(10).to_dict()
        if not anomalies_df.empty else {},
        "top_anomalous_ips": anomalies_df["ip"].value_counts().head(10).to_dict()
        if not anomalies_df.empty else {},
    }

    return report


def save_artifacts(model, scaler, report, result_df):
    os.makedirs(MODEL_DIR, exist_ok=True)
    os.makedirs(REPORTS_DIR, exist_ok=True)

    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)

    with open(FEATURE_COLUMNS_PATH, "w", encoding="utf-8") as file:
        json.dump(FEATURE_COLUMNS, file, indent=4, ensure_ascii=False)

    with open(METRICS_PATH, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4, ensure_ascii=False)

    with open(ANOMALY_REPORT_PATH, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4, ensure_ascii=False)

    anomalies_df = result_df[result_df["is_ml_anomaly"] == 1].copy()
    anomalies_df.to_csv(ANOMALIES_CSV_PATH, index=False, encoding="utf-8-sig")


def main():
    print("Cargando logs procesados...")
    df = load_processed_logs()

    print("Preparando datos para entrenamiento...")
    _, X_scaled, scaler = prepare_training_data(df)

    print("Entrenando modelo Isolation Forest...")
    model = train_isolation_forest(X_scaled)

    print("Detectando anomalías...")
    result_df = add_anomaly_predictions(df, model, X_scaled)

    report = build_report(result_df)

    save_artifacts(
        model=model,
        scaler=scaler,
        report=report,
        result_df=result_df
    )

    print("\nEntrenamiento completado.")
    print(f"Modelo guardado en: {MODEL_PATH}")
    print(f"Scaler guardado en: {SCALER_PATH}")
    print(f"Features guardadas en: {FEATURE_COLUMNS_PATH}")
    print(f"Reporte guardado en: {ANOMALY_REPORT_PATH}")
    print(f"Anomalías detectadas guardadas en: {ANOMALIES_CSV_PATH}")

    print("\nResumen:")
    print(f"Total de logs: {report['total_logs']}")
    print(f"Total de anomalías ML: {report['total_anomalies']}")
    print(f"Tasa de anomalías: {report['anomaly_rate']:.2%}")

    print("\nAnomalías por severidad:")
    print(report["anomalies_by_severity"])

    print("\nAnomalías por tipo de evento:")
    print(report["anomalies_by_event_type"])


if __name__ == "__main__":
    main()