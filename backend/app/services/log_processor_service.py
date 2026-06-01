import os
import pandas as pd


INPUT_PATH = "data/synthetic/web_logs.csv"
OUTPUT_PATH = "data/processed/logs_processed.csv"


CRITICAL_ROUTES = [
    "/api/payments",
    "/api/enrollments",
    "/api/admin/users",
    "/api/database",
    "/api/orders",
    "/dashboard/admin",
]


AUTH_EVENTS = [
    "login_success",
    "login_failed",
    "unauthorized_access",
    "password_reset",
]


PAYMENT_EVENTS = [
    "payment_failed",
    "payment_success",
]


CRITICAL_EVENTS = [
    "server_error",
    "database_timeout",
    "payment_failed",
    "enrollment_failed",
]


WARNING_EVENTS = [
    "login_failed",
    "unauthorized_access",
    "slow_response",
    "validation_error",
]


def load_logs(input_path=INPUT_PATH):
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"No se encontró el archivo de logs: {input_path}")

    df = pd.read_csv(input_path)

    required_columns = [
        "timestamp",
        "user_id",
        "ip",
        "method",
        "route",
        "status_code",
        "response_time_ms",
        "event_type",
        "message",
        "severity",
    ]

    missing_columns = [col for col in required_columns if col not in df.columns]

    if missing_columns:
        raise ValueError(f"Faltan columnas requeridas: {missing_columns}")

    return df


def clean_logs(df):
    df = df.copy()

    df = df.dropna(subset=[
        "timestamp",
        "user_id",
        "ip",
        "method",
        "route",
        "status_code",
        "response_time_ms",
        "event_type",
        "severity",
    ])

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp"])

    df["status_code"] = df["status_code"].astype(int)
    df["response_time_ms"] = df["response_time_ms"].astype(float)

    df["user_id"] = df["user_id"].astype(str)
    df["ip"] = df["ip"].astype(str)
    df["method"] = df["method"].astype(str)
    df["route"] = df["route"].astype(str)
    df["event_type"] = df["event_type"].astype(str)
    df["message"] = df["message"].astype(str)
    df["severity"] = df["severity"].astype(str)

    df = df.sort_values("timestamp").reset_index(drop=True)

    return df


def add_time_features(df):
    df = df.copy()

    df["hour"] = df["timestamp"].dt.hour
    df["day_of_week"] = df["timestamp"].dt.dayofweek
    df["minute"] = df["timestamp"].dt.minute
    df["is_weekend"] = df["day_of_week"].isin([5, 6]).astype(int)
    df["is_night"] = df["hour"].between(0, 5).astype(int)

    return df


def add_status_features(df):
    df = df.copy()

    df["is_success"] = df["status_code"].between(200, 299).astype(int)
    df["is_client_error"] = df["status_code"].between(400, 499).astype(int)
    df["is_server_error"] = df["status_code"].between(500, 599).astype(int)
    df["is_error"] = (df["status_code"] >= 400).astype(int)

    df["is_slow"] = (df["response_time_ms"] >= 2500).astype(int)
    df["is_very_slow"] = (df["response_time_ms"] >= 5000).astype(int)

    return df


def add_event_features(df):
    df = df.copy()

    df["is_critical_route"] = df["route"].isin(CRITICAL_ROUTES).astype(int)
    df["is_auth_event"] = df["event_type"].isin(AUTH_EVENTS).astype(int)
    df["is_payment_event"] = df["event_type"].isin(PAYMENT_EVENTS).astype(int)
    df["is_warning_event"] = df["event_type"].isin(WARNING_EVENTS).astype(int)
    df["is_critical_event"] = df["event_type"].isin(CRITICAL_EVENTS).astype(int)

    df["is_login_failed"] = (df["event_type"] == "login_failed").astype(int)
    df["is_unauthorized"] = (df["event_type"] == "unauthorized_access").astype(int)
    df["is_payment_failed"] = (df["event_type"] == "payment_failed").astype(int)
    df["is_database_timeout"] = (df["event_type"] == "database_timeout").astype(int)

    return df


def add_group_features(df):
    df = df.copy()

    df["requests_by_ip"] = df.groupby("ip")["ip"].transform("count")
    df["requests_by_user"] = df.groupby("user_id")["user_id"].transform("count")
    df["requests_by_route"] = df.groupby("route")["route"].transform("count")

    df["errors_by_ip"] = df.groupby("ip")["is_error"].transform("sum")
    df["errors_by_route"] = df.groupby("route")["is_error"].transform("sum")

    df["failed_logins_by_ip"] = df.groupby("ip")["is_login_failed"].transform("sum")
    df["failed_logins_by_user"] = df.groupby("user_id")["is_login_failed"].transform("sum")

    df["unauthorized_by_ip"] = df.groupby("ip")["is_unauthorized"].transform("sum")
    df["payment_failures_by_route"] = df.groupby("route")["is_payment_failed"].transform("sum")

    df["avg_response_by_route"] = df.groupby("route")["response_time_ms"].transform("mean")
    df["max_response_by_route"] = df.groupby("route")["response_time_ms"].transform("max")

    return df


def add_categorical_codes(df):
    df = df.copy()

    df["method_code"] = df["method"].astype("category").cat.codes
    df["route_code"] = df["route"].astype("category").cat.codes
    df["event_type_code"] = df["event_type"].astype("category").cat.codes
    df["severity_code"] = df["severity"].astype("category").cat.codes

    return df


def add_risk_score(df):
    df = df.copy()

    df["risk_score"] = 0

    df["risk_score"] += df["is_error"] * 2
    df["risk_score"] += df["is_server_error"] * 3
    df["risk_score"] += df["is_slow"] * 2
    df["risk_score"] += df["is_very_slow"] * 3
    df["risk_score"] += df["is_critical_route"] * 2
    df["risk_score"] += df["is_critical_event"] * 3
    df["risk_score"] += df["is_login_failed"] * 1
    df["risk_score"] += df["is_unauthorized"] * 2
    df["risk_score"] += df["is_payment_failed"] * 3
    df["risk_score"] += (df["failed_logins_by_ip"] >= 10).astype(int) * 4
    df["risk_score"] += (df["errors_by_route"] >= 10).astype(int) * 3
    df["risk_score"] += (df["payment_failures_by_route"] >= 5).astype(int) * 4

    return df


def process_logs(input_path=INPUT_PATH, output_path=OUTPUT_PATH):
    df = load_logs(input_path)
    df = clean_logs(df)

    df = add_time_features(df)
    df = add_status_features(df)
    df = add_event_features(df)
    df = add_group_features(df)
    df = add_categorical_codes(df)
    df = add_risk_score(df)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    df.to_csv(output_path, index=False, encoding="utf-8")

    return df


def main():
    df = process_logs()

    print(f"Logs procesados guardados en: {OUTPUT_PATH}")
    print(f"Total de logs procesados: {len(df)}")

    print("\nDistribución por severidad:")
    print(df["severity"].value_counts())

    print("\nColumnas generadas:")
    for column in df.columns:
        print(f"- {column}")


if __name__ == "__main__":
    main()