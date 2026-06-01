import os
import json
import joblib
import pandas as pd


MODEL_DIR = "models/anomaly_detector"
MODEL_PATH = os.path.join(MODEL_DIR, "isolation_forest.pkl")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.pkl")
FEATURE_COLUMNS_PATH = os.path.join(MODEL_DIR, "feature_columns.json")


def load_artifacts():
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(
            f"No se encontró el modelo: {MODEL_PATH}. Primero ejecuta train_anomaly_model.py"
        )

    if not os.path.exists(SCALER_PATH):
        raise FileNotFoundError(
            f"No se encontró el scaler: {SCALER_PATH}. Primero ejecuta train_anomaly_model.py"
        )

    if not os.path.exists(FEATURE_COLUMNS_PATH):
        raise FileNotFoundError(
            f"No se encontró feature_columns.json: {FEATURE_COLUMNS_PATH}"
        )

    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)

    with open(FEATURE_COLUMNS_PATH, "r", encoding="utf-8") as file:
        feature_columns = json.load(file)

    return model, scaler, feature_columns


def prepare_single_log(log_data, feature_columns):
    df = pd.DataFrame([log_data])

    missing_columns = [
        column for column in feature_columns
        if column not in df.columns
    ]

    if missing_columns:
        raise ValueError(
            f"El log no tiene todas las columnas necesarias para la predicción: {missing_columns}"
        )

    # El modelo fue entrenado con un orden exacto de columnas.
    # Si cambiamos el orden, la predicción puede ser incorrecta aunque los nombres existan.
    X = df[feature_columns].copy()
    X = X.fillna(0)

    return X


def interpret_prediction(raw_prediction, anomaly_score):
    is_anomaly = raw_prediction == -1

    if is_anomaly:
        if anomaly_score < -0.12:
            severity_suggestion = "critical"
        else:
            severity_suggestion = "warning"
    else:
        severity_suggestion = "normal"

    return {
        "is_anomaly": bool(is_anomaly),
        "ml_prediction": int(raw_prediction),
        "anomaly_score": float(anomaly_score),
        "severity_suggestion": severity_suggestion
    }


def predict_anomaly(log_data):
    model, scaler, feature_columns = load_artifacts()

    X = prepare_single_log(log_data, feature_columns)

    # Se usa el mismo scaler entrenado previamente.
    # Esto es importante porque el modelo aprendió con datos normalizados.
    X_scaled = scaler.transform(X)

    raw_prediction = model.predict(X_scaled)[0]
    anomaly_score = model.decision_function(X_scaled)[0]

    result = interpret_prediction(raw_prediction, anomaly_score)

    return result


def main():
    # Log normal de ejemplo.
    normal_log = {
        "status_code": 200,
        "response_time_ms": 320,
        "hour": 10,
        "day_of_week": 1,
        "minute": 15,
        "is_weekend": 0,
        "is_night": 0,
        "is_success": 1,
        "is_client_error": 0,
        "is_server_error": 0,
        "is_error": 0,
        "is_slow": 0,
        "is_very_slow": 0,
        "is_critical_route": 0,
        "is_auth_event": 0,
        "is_payment_event": 0,
        "is_warning_event": 0,
        "is_critical_event": 0,
        "is_login_failed": 0,
        "is_unauthorized": 0,
        "is_payment_failed": 0,
        "is_database_timeout": 0,
        "requests_by_ip": 40,
        "requests_by_user": 18,
        "requests_by_route": 200,
        "errors_by_ip": 1,
        "errors_by_route": 2,
        "failed_logins_by_ip": 0,
        "failed_logins_by_user": 0,
        "unauthorized_by_ip": 0,
        "payment_failures_by_route": 0,
        "avg_response_by_route": 450,
        "max_response_by_route": 1200,
        "method_code": 0,
        "route_code": 1,
        "event_type_code": 2,
        "risk_score": 0,
    }

    # Log anómalo de ejemplo.
    # Simula un pago fallido en ruta crítica, con error 500 y respuesta muy lenta.
    anomalous_log = {
        "status_code": 500,
        "response_time_ms": 7600,
        "hour": 2,
        "day_of_week": 1,
        "minute": 42,
        "is_weekend": 0,
        "is_night": 1,
        "is_success": 0,
        "is_client_error": 0,
        "is_server_error": 1,
        "is_error": 1,
        "is_slow": 1,
        "is_very_slow": 1,
        "is_critical_route": 1,
        "is_auth_event": 0,
        "is_payment_event": 1,
        "is_warning_event": 0,
        "is_critical_event": 1,
        "is_login_failed": 0,
        "is_unauthorized": 0,
        "is_payment_failed": 1,
        "is_database_timeout": 0,
        "requests_by_ip": 300,
        "requests_by_user": 40,
        "requests_by_route": 500,
        "errors_by_ip": 50,
        "errors_by_route": 80,
        "failed_logins_by_ip": 0,
        "failed_logins_by_user": 0,
        "unauthorized_by_ip": 0,
        "payment_failures_by_route": 30,
        "avg_response_by_route": 4200,
        "max_response_by_route": 9000,
        "method_code": 1,
        "route_code": 5,
        "event_type_code": 8,
        "risk_score": 24,
    }

    print("Predicción para log normal:")
    print(predict_anomaly(normal_log))

    print("\nPredicción para log anómalo:")
    print(predict_anomaly(anomalous_log))


if __name__ == "__main__":
    main()