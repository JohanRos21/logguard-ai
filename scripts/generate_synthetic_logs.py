import os
import random
from datetime import datetime, timedelta

import pandas as pd


OUTPUT_PATH = "data/synthetic/web_logs.csv"
TOTAL_LOGS = 2000
RANDOM_SEED = 42


USERS = [f"user_{i:03d}" for i in range(1, 121)]
ADMIN_USERS = [f"admin_{i:02d}" for i in range(1, 8)]

IPS = [
    "190.12.45.10", "190.12.45.11", "190.12.45.12",
    "181.65.22.30", "181.65.22.31",
    "200.48.10.5", "200.48.10.6",
    "192.168.1.10", "192.168.1.11", "192.168.1.12",
    "10.0.0.15", "10.0.0.16",
    "45.90.130.77", "45.90.130.78",
]

NORMAL_ROUTES = [
    "/",
    "/login",
    "/dashboard",
    "/dashboard/alumno",
    "/dashboard/admin",
    "/api/students",
    "/api/products",
    "/api/reports",
    "/api/inventory",
    "/api/profile",
    "/api/notifications",
]

CRITICAL_ROUTES = [
    "/api/payments",
    "/api/enrollments",
    "/api/admin/users",
    "/api/database",
    "/api/orders",
]


NORMAL_EVENTS = [
    {
        "event_type": "page_view",
        "method": "GET",
        "status_code": 200,
        "message": "Página cargada correctamente",
        "severity": "normal",
    },
    {
        "event_type": "login_success",
        "method": "POST",
        "status_code": 200,
        "message": "Inicio de sesión correcto",
        "severity": "normal",
    },
    {
        "event_type": "data_loaded",
        "method": "GET",
        "status_code": 200,
        "message": "Datos cargados correctamente",
        "severity": "normal",
    },
    {
        "event_type": "record_created",
        "method": "POST",
        "status_code": 201,
        "message": "Registro creado correctamente",
        "severity": "normal",
    },
]

WARNING_EVENTS = [
    {
        "event_type": "login_failed",
        "method": "POST",
        "status_code": 401,
        "message": "Credenciales incorrectas",
        "severity": "warning",
    },
    {
        "event_type": "unauthorized_access",
        "method": "GET",
        "status_code": 403,
        "message": "Intento de acceso no autorizado",
        "severity": "warning",
    },
    {
        "event_type": "slow_response",
        "method": "GET",
        "status_code": 200,
        "message": "Respuesta lenta del servidor",
        "severity": "warning",
    },
    {
        "event_type": "validation_error",
        "method": "POST",
        "status_code": 422,
        "message": "Error de validación en formulario",
        "severity": "warning",
    },
]

CRITICAL_EVENTS = [
    {
        "event_type": "server_error",
        "method": "GET",
        "status_code": 500,
        "message": "Error interno del servidor",
        "severity": "critical",
    },
    {
        "event_type": "database_timeout",
        "method": "GET",
        "status_code": 503,
        "message": "Timeout de base de datos",
        "severity": "critical",
    },
    {
        "event_type": "payment_failed",
        "method": "POST",
        "status_code": 500,
        "message": "Error crítico al procesar pago",
        "severity": "critical",
    },
    {
        "event_type": "enrollment_failed",
        "method": "POST",
        "status_code": 500,
        "message": "Error crítico al procesar matrícula",
        "severity": "critical",
    },
]


def random_response_time(severity):
    if severity == "normal":
        return random.randint(80, 700)

    if severity == "warning":
        return random.randint(800, 2500)

    return random.randint(2500, 8000)


def random_user(event_type):
    if event_type == "unauthorized_access":
        return random.choice(USERS)

    if event_type in ["admin_action", "record_deleted"]:
        return random.choice(ADMIN_USERS)

    return random.choice(USERS + ADMIN_USERS)


def random_route(severity):
    if severity == "critical":
        return random.choice(CRITICAL_ROUTES)

    if severity == "warning":
        return random.choice(NORMAL_ROUTES + CRITICAL_ROUTES)

    return random.choice(NORMAL_ROUTES)


def generate_base_logs():
    logs = []
    start_time = datetime.now() - timedelta(days=7)

    event_pool = (
        NORMAL_EVENTS * 8
        + WARNING_EVENTS * 3
        + CRITICAL_EVENTS * 1
    )

    for i in range(TOTAL_LOGS):
        event = random.choice(event_pool)
        severity = event["severity"]

        timestamp = start_time + timedelta(
            minutes=random.randint(0, 7 * 24 * 60),
            seconds=random.randint(0, 59)
        )

        log = {
            "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "user_id": random_user(event["event_type"]),
            "ip": random.choice(IPS),
            "method": event["method"],
            "route": random_route(severity),
            "status_code": event["status_code"],
            "response_time_ms": random_response_time(severity),
            "event_type": event["event_type"],
            "message": event["message"],
            "severity": severity,
        }

        logs.append(log)

    return logs


def inject_brute_force_attack(logs):
    attacker_ip = "45.90.130.200"
    target_user = "user_099"
    base_time = datetime.now() - timedelta(hours=4)

    for i in range(35):
        logs.append({
            "timestamp": (base_time + timedelta(seconds=i * 12)).strftime("%Y-%m-%d %H:%M:%S"),
            "user_id": target_user,
            "ip": attacker_ip,
            "method": "POST",
            "route": "/login",
            "status_code": 401,
            "response_time_ms": random.randint(100, 350),
            "event_type": "login_failed",
            "message": "Múltiples intentos fallidos de inicio de sesión",
            "severity": "critical",
        })


def inject_payment_outage(logs):
    base_time = datetime.now() - timedelta(hours=2)

    for i in range(30):
        logs.append({
            "timestamp": (base_time + timedelta(seconds=i * 20)).strftime("%Y-%m-%d %H:%M:%S"),
            "user_id": random.choice(USERS),
            "ip": random.choice(IPS),
            "method": "POST",
            "route": "/api/payments",
            "status_code": 500,
            "response_time_ms": random.randint(3000, 9000),
            "event_type": "payment_failed",
            "message": "Pagos fallidos repetidos en tienda virtual",
            "severity": "critical",
        })


def inject_slow_endpoint(logs):
    base_time = datetime.now() - timedelta(hours=1)

    for i in range(25):
        logs.append({
            "timestamp": (base_time + timedelta(seconds=i * 30)).strftime("%Y-%m-%d %H:%M:%S"),
            "user_id": random.choice(USERS),
            "ip": random.choice(IPS),
            "method": "GET",
            "route": "/api/reports",
            "status_code": 200,
            "response_time_ms": random.randint(3500, 7000),
            "event_type": "slow_response",
            "message": "Endpoint de reportes con respuesta anormalmente lenta",
            "severity": "warning",
        })


def inject_unauthorized_admin_access(logs):
    base_time = datetime.now() - timedelta(minutes=40)
    suspicious_ip = "190.200.10.99"

    for i in range(18):
        logs.append({
            "timestamp": (base_time + timedelta(seconds=i * 35)).strftime("%Y-%m-%d %H:%M:%S"),
            "user_id": random.choice(USERS),
            "ip": suspicious_ip,
            "method": "GET",
            "route": "/dashboard/admin",
            "status_code": 403,
            "response_time_ms": random.randint(120, 600),
            "event_type": "unauthorized_access",
            "message": "Intento repetido de acceso a panel administrativo",
            "severity": "warning",
        })


def main():
    random.seed(RANDOM_SEED)

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)

    logs = generate_base_logs()

    inject_brute_force_attack(logs)
    inject_payment_outage(logs)
    inject_slow_endpoint(logs)
    inject_unauthorized_admin_access(logs)

    df = pd.DataFrame(logs)
    df = df.sort_values("timestamp").reset_index(drop=True)

    df.to_csv(OUTPUT_PATH, index=False, encoding="utf-8")

    print(f"Dataset generado en: {OUTPUT_PATH}")
    print(f"Total de logs: {len(df)}")

    print("\nDistribución por severidad:")
    print(df["severity"].value_counts())

    print("\nDistribución por tipo de evento:")
    print(df["event_type"].value_counts())


if __name__ == "__main__":
    main()