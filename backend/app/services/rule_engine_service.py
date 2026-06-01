import os
import json
import pandas as pd


INPUT_PATH = "data/processed/logs_processed.csv"
ALERTS_CSV_PATH = "reports/rule_alerts.csv"
ALERTS_JSON_PATH = "reports/rule_alerts.json"


def load_processed_logs(input_path=INPUT_PATH):
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"No se encontró el archivo procesado: {input_path}")

    df = pd.read_csv(input_path, encoding="utf-8-sig")

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
        "is_error",
        "is_server_error",
        "is_slow",
        "is_very_slow",
        "is_critical_route",
        "is_login_failed",
        "is_unauthorized",
        "is_payment_failed",
        "is_database_timeout",
        "failed_logins_by_ip",
        "failed_logins_by_user",
        "unauthorized_by_ip",
        "payment_failures_by_route",
        "errors_by_route",
        "risk_score",
    ]

    missing_columns = [column for column in required_columns if column not in df.columns]

    if missing_columns:
        raise ValueError(f"Faltan columnas requeridas: {missing_columns}")

    return df


def create_alert(row, alert_type, severity, reason, recommendation):
    return {
        "timestamp": row["timestamp"],
        "severity": severity,
        "alert_type": alert_type,
        "user_id": row["user_id"],
        "ip": row["ip"],
        "method": row["method"],
        "route": row["route"],
        "status_code": int(row["status_code"]),
        "response_time_ms": float(row["response_time_ms"]),
        "event_type": row["event_type"],
        "risk_score": int(row["risk_score"]),
        "reason": reason,
        "recommendation": recommendation,
    }


def detect_brute_force(row):
    # Detecta posible ataque de fuerza bruta.
    # No basta con un login fallido aislado; se vuelve crítico cuando una misma IP
    # acumula varios intentos fallidos, porque eso puede indicar automatización.
    if row["is_login_failed"] == 1 and row["failed_logins_by_ip"] >= 10:
        return create_alert(
            row=row,
            alert_type="brute_force_attempt",
            severity="critical",
            reason="Se detectaron múltiples intentos fallidos de login desde la misma IP.",
            recommendation="Revisar la IP sospechosa, aplicar bloqueo temporal y validar posibles intentos de fuerza bruta."
        )

    # Este caso se centra en un usuario específico.
    # Puede ser un usuario real olvidando su contraseña o un intento puntual.
    if row["is_login_failed"] == 1 and row["failed_logins_by_user"] >= 5:
        return create_alert(
            row=row,
            alert_type="multiple_failed_logins_user",
            severity="warning",
            reason="Un usuario registra varios intentos fallidos de inicio de sesión.",
            recommendation="Verificar si el usuario olvidó sus credenciales o si existe intento de acceso no autorizado."
        )

    return None


def detect_unauthorized_access(row):
    # Acceder al panel administrativo sin permisos es una señal importante.
    # Se marca como warning porque puede ser error de permisos o intento sospechoso.
    if row["is_unauthorized"] == 1 and row["route"] == "/dashboard/admin":
        return create_alert(
            row=row,
            alert_type="unauthorized_admin_access",
            severity="warning",
            reason="Se detectó un intento de acceso no autorizado al panel administrativo.",
            recommendation="Revisar permisos del usuario, validar sesión y monitorear la IP de origen."
        )

    # Si una misma IP insiste en accesos no autorizados, la severidad sube.
    # Esto puede indicar exploración de rutas protegidas.
    if row["is_unauthorized"] == 1 and row["unauthorized_by_ip"] >= 5:
        return create_alert(
            row=row,
            alert_type="repeated_unauthorized_access",
            severity="critical",
            reason="Se detectaron múltiples intentos de acceso no autorizado desde la misma IP.",
            recommendation="Bloquear o limitar temporalmente la IP y revisar posibles rutas expuestas."
        )

    return None


def detect_server_errors(row):
    # Un error 5xx en una ruta crítica puede afectar pagos, matrículas,
    # administración o servicios centrales. Por eso se clasifica como crítico.
    if row["is_server_error"] == 1 and row["is_critical_route"] == 1:
        return create_alert(
            row=row,
            alert_type="critical_route_server_error",
            severity="critical",
            reason="Se detectó un error 5xx en una ruta crítica del sistema.",
            recommendation="Revisar logs del backend, servicios relacionados y disponibilidad de la base de datos."
        )

    # Muchos errores en la misma ruta indican que no fue un fallo aislado,
    # sino una posible falla persistente del endpoint.
    if row["is_server_error"] == 1 and row["errors_by_route"] >= 10:
        return create_alert(
            row=row,
            alert_type="repeated_server_errors_route",
            severity="critical",
            reason="Una ruta presenta múltiples errores del servidor.",
            recommendation="Investigar el endpoint afectado, revisar trazas del backend y validar dependencias externas."
        )

    return None


def detect_payment_failures(row):
    # Los pagos son una operación de negocio crítica.
    # Si los fallos se repiten, puede haber caída o mala configuración de la pasarela.
    if row["is_payment_failed"] == 1 and row["payment_failures_by_route"] >= 5:
        return create_alert(
            row=row,
            alert_type="payment_failure_outage",
            severity="critical",
            reason="Se detectaron pagos fallidos repetidos en una ruta de pagos.",
            recommendation="Revisar integración con la pasarela de pagos, credenciales, webhooks y disponibilidad del servicio."
        )

    # Un pago fallido individual no siempre es crítico.
    # Puede ser tarjeta rechazada, error del usuario o falla temporal.
    if row["is_payment_failed"] == 1:
        return create_alert(
            row=row,
            alert_type="single_payment_failure",
            severity="warning",
            reason="Se detectó un pago fallido.",
            recommendation="Verificar el detalle de la transacción y confirmar si el problema se repite."
        )

    return None


def detect_database_timeout(row):
    # Un timeout de base de datos suele afectar varias partes del sistema:
    # login, pagos, reportes, matrículas, inventario, etc.
    if row["is_database_timeout"] == 1:
        return create_alert(
            row=row,
            alert_type="database_timeout",
            severity="critical",
            reason="Se detectó un timeout de base de datos.",
            recommendation="Revisar conexión a base de datos, carga del servidor, consultas lentas e índices."
        )

    return None


def detect_performance_issues(row):
    # Una ruta crítica muy lenta puede impedir completar operaciones importantes,
    # aunque técnicamente devuelva status 200.
    if row["is_very_slow"] == 1 and row["is_critical_route"] == 1:
        return create_alert(
            row=row,
            alert_type="critical_route_very_slow",
            severity="critical",
            reason="Una ruta crítica presenta tiempo de respuesta muy alto.",
            recommendation="Revisar rendimiento del endpoint, consultas a base de datos y servicios externos."
        )

    # Una respuesta lenta general sirve como alerta temprana de degradación.
    if row["is_slow"] == 1:
        return create_alert(
            row=row,
            alert_type="slow_response",
            severity="warning",
            reason="Se detectó una respuesta lenta del servidor.",
            recommendation="Monitorear el endpoint y revisar si el tiempo de respuesta aumenta o se repite."
        )

    return None


def detect_high_risk_score(row):
    # risk_score combina señales como error, ruta crítica, lentitud,
    # pago fallido, login fallido y accesos no autorizados.
    # Esta regla funciona como capa general cuando varias señales se acumulan.
    if row["risk_score"] >= 18:
        return create_alert(
            row=row,
            alert_type="high_risk_score",
            severity="critical",
            reason="El log presenta un puntaje de riesgo alto según múltiples señales combinadas.",
            recommendation="Revisar el evento de forma prioritaria y validar si corresponde a un incidente activo."
        )

    if row["risk_score"] >= 10:
        return create_alert(
            row=row,
            alert_type="medium_risk_score",
            severity="warning",
            reason="El log presenta un puntaje de riesgo medio.",
            recommendation="Monitorear el evento y revisar si se repite en el tiempo."
        )

    return None


def apply_rules_to_row(row):
    # Cada regla revisa el mismo log desde una perspectiva distinta:
    # seguridad, rendimiento, pagos, base de datos o riesgo general.
    # Un mismo log puede generar más de una alerta.
    rules = [
        detect_brute_force,
        detect_unauthorized_access,
        detect_server_errors,
        detect_payment_failures,
        detect_database_timeout,
        detect_performance_issues,
        detect_high_risk_score,
    ]

    alerts = []

    for rule in rules:
        alert = rule(row)

        if alert:
            alerts.append(alert)

    return alerts


def run_rule_engine(input_path=INPUT_PATH):
    df = load_processed_logs(input_path)

    all_alerts = []

    # El motor de reglas trabaja sobre logs ya enriquecidos por el procesador.
    # Por eso puede usar columnas como failed_logins_by_ip, errors_by_route y risk_score.
    for _, row in df.iterrows():
        alerts = apply_rules_to_row(row)
        all_alerts.extend(alerts)

    alerts_df = pd.DataFrame(all_alerts)

    os.makedirs("reports", exist_ok=True)

    if not alerts_df.empty:
        # Evita duplicados exactos si una regla se dispara más de una vez
        # sobre el mismo evento.
        alerts_df = alerts_df.drop_duplicates(
            subset=[
                "timestamp",
                "alert_type",
                "user_id",
                "ip",
                "route",
                "event_type",
            ]
        ).reset_index(drop=True)

        alerts_df.to_csv(ALERTS_CSV_PATH, index=False, encoding="utf-8-sig")

        with open(ALERTS_JSON_PATH, "w", encoding="utf-8") as file:
            json.dump(
                alerts_df.to_dict(orient="records"),
                file,
                indent=4,
                ensure_ascii=False
            )
    else:
        alerts_df.to_csv(ALERTS_CSV_PATH, index=False, encoding="utf-8-sig")

        with open(ALERTS_JSON_PATH, "w", encoding="utf-8") as file:
            json.dump([], file, indent=4, ensure_ascii=False)

    return alerts_df


def main():
    alerts_df = run_rule_engine()

    print(f"Alertas CSV guardadas en: {ALERTS_CSV_PATH}")
    print(f"Alertas JSON guardadas en: {ALERTS_JSON_PATH}")
    print(f"Total de alertas generadas: {len(alerts_df)}")

    if not alerts_df.empty:
        print("\nDistribución por severidad:")
        print(alerts_df["severity"].value_counts())

        print("\nDistribución por tipo de alerta:")
        print(alerts_df["alert_type"].value_counts())


if __name__ == "__main__":
    main()