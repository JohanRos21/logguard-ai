"""
Synthetic Web Log Generator — V2
=================================

Extiende V2 con tres bloques nuevos diseñados para mejorar la calidad
del entrenamiento del Transformer:

  [BLOQUE A] Escenarios mixtos (MIXED_SCENARIOS)
      Cada entidad combina dos tipos de anomalía en la misma secuencia.
      Ej: brute_force que transiciona a admin_probe, o payment_outage
      que deriva en database_outage. Entrena al modelo a detectar
      patrones compuestos, no solo incidentes aislados.
      10 combinaciones × 2 entidades = 20 entidades.

  [BLOQUE B] Falsos positivos entrenables (FALSE_POSITIVE_SCENARIOS)
      Entidades con eventos que PARECEN anómalos pero son normales:
      usuario que falla login 2-3 veces y luego entra, endpoint lento
      por mantenimiento que se recupera, acceso admin aislado de un
      operador legítimo. scenario_label = "normal".
      Entrena al modelo a NO disparar ante cualquier 401 o slowness.
      5 tipos × 3 entidades = 15 entidades.

  [BLOQUE C] Variantes de intensidad (INTENSITY_VARIANTS)
      Mismo escenario base, distinta intensidad: brute_force lento
      (intentos espaciados) vs rápido (ráfaga), database_outage parcial
      vs total. Entrena al modelo a detectar el PATRÓN, no los valores
      exactos de response_time o frecuencia.
      5 escenarios × 2 intensidades × 2 entidades = 20 entidades.

Cambios heredados de V2: C1-C7 (ver historial en git).
"""

import os
import json
import random
from datetime import datetime, timedelta

import pandas as pd


# ─── Rutas de salida ───────────────────────────────────────────────────────────

PRIMARY_OUTPUT_PATH = "data/synthetic/web_logs.csv"
V2_OUTPUT_PATH = "data/synthetic/web_logs_v2_extended.csv"
REPORT_PATH = "reports/v2_extended_log_generation_report.json"


# ─── Configuración de volumen ─────────────────────────────────────────────────

RANDOM_SEED = 42
LOGS_PER_ENTITY = 90

# V2 base
NORMAL_ENTITIES = 44
WARNING_ENTITIES = 6

# ── Bloque A: escenarios mixtos ───────────────────────────────────────────────
# Cada par combina dos generadores de anomalía en la misma secuencia.
# Primera mitad (logs 0-44) usa gen_a, segunda mitad (logs 45-89) usa gen_b.
# 2 entidades por combinación para que haya redundancia en el entrenamiento.
MIXED_SCENARIOS = [
    ("brute_force",           "admin_probe"),
    ("brute_force",           "payment_outage"),
    ("payment_outage",        "database_outage"),
    ("database_outage",       "performance_degradation"),
    ("performance_degradation","brute_force"),
    ("admin_probe",           "database_outage"),
    ("payment_outage",        "admin_probe"),
    ("brute_force",           "database_outage"),
    ("performance_degradation","payment_outage"),
    ("admin_probe",           "performance_degradation"),
]
MIXED_ENTITIES_PER_COMBO = 2

# ── Bloque B: falsos positivos entrenables ────────────────────────────────────
# scenario_label = "normal" — el modelo debe aprender a NO clasificarlos como anomalía.
FALSE_POSITIVE_SCENARIOS = {
    "fp_login_retry":      3,   # usuario olvida contraseña: 2-3 fallos → login exitoso
    "fp_maintenance_slow": 3,   # endpoint lento por mantenimiento programado → se recupera
    "fp_isolated_403":     3,   # un solo acceso 403 de operador legítimo, nada más
    "fp_burst_normal":     3,   # ráfaga de tráfico normal legítima (muchos GET rápidos)
    "fp_single_500":       3,   # un solo error 500 aislado, resto normal
}

# ── Bloque C: variantes de intensidad ─────────────────────────────────────────
# Mismo patrón anómalo, distinta intensidad.
# "low" = ataques espaciados / degradación leve
# "high" = ráfaga / colapso total
INTENSITY_VARIANTS = {
    "brute_force":            ["low", "high"],
    "payment_outage":         ["low", "high"],
    "database_outage":        ["low", "high"],
    "performance_degradation":["low", "high"],
    "admin_probe":            ["low", "high"],
}
INTENSITY_ENTITIES_PER_VARIANT = 2

# [C7] Umbral máximo tolerable de logs críticos sobre el total.
MAX_ANOMALY_RATIO = 0.35

ANOMALY_SCENARIOS = {
    "brute_force": 4,
    "payment_outage": 4,
    "database_outage": 4,
    "performance_degradation": 4,
    "admin_probe": 4,
}

# [C2] + V2: se agregan todos los nuevos scenarios al diccionario central.
SCENARIO_LABELS = {
    # Base V2
    "normal_traffic":           "normal",
    "controlled_warning":       "normal",
    "brute_force":              "anomaly",
    "payment_outage":           "anomaly",
    "database_outage":          "anomaly",
    "performance_degradation":  "anomaly",
    "admin_probe":              "anomaly",
    # Bloque A — mixtos
    "mixed_brute_force+admin_probe":              "anomaly",
    "mixed_brute_force+payment_outage":           "anomaly",
    "mixed_payment_outage+database_outage":       "anomaly",
    "mixed_database_outage+performance_degradation": "anomaly",
    "mixed_performance_degradation+brute_force":  "anomaly",
    "mixed_admin_probe+database_outage":          "anomaly",
    "mixed_payment_outage+admin_probe":           "anomaly",
    "mixed_brute_force+database_outage":          "anomaly",
    "mixed_performance_degradation+payment_outage": "anomaly",
    "mixed_admin_probe+performance_degradation":  "anomaly",
    # Bloque B — falsos positivos
    "fp_login_retry":       "normal",
    "fp_maintenance_slow":  "normal",
    "fp_isolated_403":      "normal",
    "fp_burst_normal":      "normal",
    "fp_single_500":        "normal",
    # Bloque C — variantes de intensidad
    "brute_force_low":              "anomaly",
    "brute_force_high":             "anomaly",
    "payment_outage_low":           "anomaly",
    "payment_outage_high":          "anomaly",
    "database_outage_low":          "anomaly",
    "database_outage_high":         "anomaly",
    "performance_degradation_low":  "anomaly",
    "performance_degradation_high": "anomaly",
    "admin_probe_low":              "anomaly",
    "admin_probe_high":             "anomaly",
}


# ─── Rutas ────────────────────────────────────────────────────────────────────

NORMAL_ROUTES = [
    "/",
    "/login",
    "/dashboard",
    "/dashboard/alumno",
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


# ─── Plantillas de eventos ────────────────────────────────────────────────────

NORMAL_EVENTS = [
    {
        "event_type": "page_view",
        "method": "GET",
        "status_code": 200,
        "message": "Página cargada correctamente",
    },
    {
        "event_type": "login_success",
        "method": "POST",
        "status_code": 200,
        "message": "Inicio de sesión correcto",
    },
    {
        "event_type": "data_loaded",
        "method": "GET",
        "status_code": 200,
        "message": "Datos cargados correctamente",
    },
    {
        "event_type": "record_created",
        "method": "POST",
        "status_code": 201,
        "message": "Registro creado correctamente",
    },
]

WARNING_EVENTS = [
    {
        "event_type": "login_failed",
        "method": "POST",
        "route": "/login",
        "status_code": 401,
        "message": "Credenciales incorrectas",
    },
    {
        "event_type": "validation_error",
        "method": "POST",
        "route": "/api/profile",
        "status_code": 422,
        "message": "Error de validación en formulario",
    },
    {
        "event_type": "slow_response",
        "method": "GET",
        "route": "/api/reports",
        "status_code": 200,
        "message": "Respuesta lenta moderada del servidor",
    },
    {
        "event_type": "unauthorized_access",
        "method": "GET",
        "route": "/dashboard/admin",
        "status_code": 403,
        "message": "Intento aislado de acceso no autorizado",
    },
]


# ─── Helpers ──────────────────────────────────────────────────────────────────

def make_ip(third_octet: int, fourth_octet: int) -> str:
    return f"172.16.{third_octet}.{fourth_octet}"


def make_user(prefix: str, index: int) -> str:
    return f"{prefix}_user_{index:03d}"


def random_normal_response_time() -> int:
    return random.randint(90, 750)


def random_warning_response_time(event_type: str) -> int:
    if event_type == "slow_response":
        return random.randint(900, 2200)
    return random.randint(120, 900)


def random_critical_response_time() -> int:
    return random.randint(3000, 9000)


# [C4] Calcula el offset de inicio de cada entidad en segundos,
# evitando solapamientos. Cada entidad ocupa LOGS_PER_ENTITY × 4 min
# más un gap fijo de 30 min entre entidades.
_ENTITY_DURATION_SECONDS = LOGS_PER_ENTITY * 4 * 60   # 6 horas exactas
_ENTITY_GAP_SECONDS = 30 * 60                          # 30 min de colchón

def entity_base_time(base_start: datetime, entity_index: int) -> datetime:
    """Devuelve el timestamp de inicio de la entidad N sin solapamiento."""
    offset = entity_index * (_ENTITY_DURATION_SECONDS + _ENTITY_GAP_SECONDS)
    return base_start + timedelta(seconds=offset)


# ─── Factory central de logs ──────────────────────────────────────────────────

def create_log(
    timestamp: datetime,
    user_id: str,
    ip: str,
    method: str,
    route: str,
    status_code: int,
    response_time_ms: int,
    event_type: str,
    message: str,
    severity: str,
    scenario: str,
) -> dict:
    # [C2] scenario_label se deriva aquí, no en cada generador.
    scenario_label = SCENARIO_LABELS.get(scenario, "unknown")

    return {
        "timestamp": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "user_id": user_id,
        "ip": ip,
        "method": method,
        "route": route,
        "status_code": status_code,
        "response_time_ms": response_time_ms,
        "event_type": event_type,
        "message": message,
        "severity": severity,
        "scenario": scenario,
        "scenario_label": scenario_label,
    }


# ─── Generadores de logs por tipo ─────────────────────────────────────────────

def generate_normal_log(timestamp: datetime, user_id: str, ip: str) -> dict:
    event = random.choice(NORMAL_EVENTS)
    return create_log(
        timestamp=timestamp,
        user_id=user_id,
        ip=ip,
        method=event["method"],
        route=random.choice(NORMAL_ROUTES),
        status_code=event["status_code"],
        response_time_ms=random_normal_response_time(),
        event_type=event["event_type"],
        message=event["message"],
        severity="normal",
        scenario="normal_traffic",
    )


def generate_warning_log(timestamp: datetime, user_id: str, ip: str, index: int) -> dict:
    if index % 10 not in [3, 8]:
        return generate_normal_log(timestamp, user_id, ip)

    event = WARNING_EVENTS[(index // 10) % len(WARNING_EVENTS)]
    return create_log(
        timestamp=timestamp,
        user_id=user_id,
        ip=ip,
        method=event["method"],
        route=event["route"],
        status_code=event["status_code"],
        response_time_ms=random_warning_response_time(event["event_type"]),
        event_type=event["event_type"],
        message=event["message"],
        severity="warning",
        # [C2] scenario_label="normal" sale automáticamente del diccionario.
        scenario="controlled_warning",
    )


def generate_brute_force_log(timestamp: datetime, user_id: str, ip: str, index: int) -> dict:
    # [C5] Densidad reducida: solo posiciones 0-3 son anómalas (4/10 → 40%).
    # En V1 eran 0-7 (80%). Ahora el modelo ve más "ruido normal" entremedio.
    position = index % 10

    if position in [0, 1, 2, 3]:
        return create_log(
            timestamp, user_id, ip,
            "POST", "/login", 401,
            random.randint(100, 450),
            "login_failed",
            "Múltiples intentos fallidos de inicio de sesión",
            "critical", "brute_force",
        )

    if position in [4, 5]:
        return create_log(
            timestamp, user_id, ip,
            "GET", "/dashboard/admin", 403,
            random.randint(150, 600),
            "unauthorized_access",
            "Acceso no autorizado posterior a múltiples fallos de login",
            "critical", "brute_force",
        )

    return generate_normal_log(timestamp, user_id, ip)


def generate_payment_outage_log(timestamp: datetime, user_id: str, ip: str, index: int) -> dict:
    # [C5] Reducido de 0-6 → 0-3 críticos por ciclo (4/10 → 40%).
    position = index % 10

    if position in [0, 1, 2, 3]:
        return create_log(
            timestamp, user_id, ip,
            "POST", "/api/payments", 500,
            random_critical_response_time(),
            "payment_failed",
            "Pagos fallidos repetidos en tienda virtual",
            "critical", "payment_outage",
        )

    if position in [4, 5]:
        return create_log(
            timestamp, user_id, ip,
            "GET", "/api/payments", 500,
            random_critical_response_time(),
            "server_error",
            "Error interno del servidor en ruta de pagos",
            "critical", "payment_outage",
        )

    return generate_normal_log(timestamp, user_id, ip)


def generate_database_outage_log(timestamp: datetime, user_id: str, ip: str, index: int) -> dict:
    # [C5] Reducido: 0-3 timeouts, 4-5 server_error, resto normal.
    position = index % 10

    if position in [0, 1, 2, 3]:
        return create_log(
            timestamp, user_id, ip,
            "GET", "/api/database", 503,
            random_critical_response_time(),
            "database_timeout",
            "Timeout de base de datos",
            "critical", "database_outage",
        )

    if position in [4, 5]:
        return create_log(
            timestamp, user_id, ip,
            "GET", "/api/reports", 500,
            random_critical_response_time(),
            "server_error",
            "Error interno asociado a consultas lentas",
            "critical", "database_outage",
        )

    return generate_normal_log(timestamp, user_id, ip)


def generate_performance_degradation_log(timestamp: datetime, user_id: str, ip: str, index: int) -> dict:
    # [C5] Reducido de 0-5 → 0-3 slow_response por ciclo.
    # Añadimos posición 4 como "moderada" para que la transición sea gradual.
    position = index % 10

    if position in [0, 1, 2, 3]:
        return create_log(
            timestamp, user_id, ip,
            "GET", "/api/reports", 200,
            random.randint(5200, 9000),
            "slow_response",
            "Endpoint con respuesta anormalmente lenta",
            "critical", "performance_degradation",
        )

    if position == 4:
        # Respuesta "casi normal pero elevada" — zona gris intencionada.
        return create_log(
            timestamp, user_id, ip,
            "GET", "/api/reports", 200,
            random.randint(2500, 5000),
            "slow_response",
            "Respuesta elevada, posible inicio de degradación",
            "warning", "performance_degradation",
        )

    return generate_normal_log(timestamp, user_id, ip)


def generate_admin_probe_log(timestamp: datetime, user_id: str, ip: str, index: int) -> dict:
    # [C5] Reducido de 0-7 → 0-3 unauthorized_access + 4-5 admin/users.
    position = index % 10

    if position in [0, 1, 2, 3]:
        return create_log(
            timestamp, user_id, ip,
            "GET", "/dashboard/admin", 403,
            random.randint(120, 700),
            "unauthorized_access",
            "Intentos repetidos de acceso al panel administrativo",
            "critical", "admin_probe",
        )

    if position in [4, 5]:
        return create_log(
            timestamp, user_id, ip,
            "GET", "/api/admin/users", 403,
            random.randint(200, 850),
            "unauthorized_access",
            "Intento de acceso no autorizado a usuarios administrativos",
            "critical", "admin_probe",
        )

    return generate_normal_log(timestamp, user_id, ip)


ANOMALY_GENERATORS = {
    "brute_force": generate_brute_force_log,
    "payment_outage": generate_payment_outage_log,
    "database_outage": generate_database_outage_log,
    "performance_degradation": generate_performance_degradation_log,
    "admin_probe": generate_admin_probe_log,
}


# ─── BLOQUE A: Generadores de escenarios mixtos ───────────────────────────────
#
# Una sola entidad atraviesa DOS anomalías distintas.
# Logs 0-44  → generador del escenario A (primera mitad)
# Logs 45-89 → generador del escenario B (segunda mitad)
# Esto le muestra al Transformer que una secuencia puede tener
# más de un patrón anómalo, y que debe detectar ambos.

def generate_mixed_log(
    timestamp: datetime,
    user_id: str,
    ip: str,
    index: int,
    gen_a,
    gen_b,
    scenario_name: str,
) -> dict:
    # Llama al generador correspondiente según la mitad de la secuencia.
    # Re-mapea el index local (0-44 → 0-44, 45-89 → 0-44) para que
    # el patrón posicional de cada generador funcione igual que en solitario.
    if index < LOGS_PER_ENTITY // 2:
        log = gen_a(timestamp, user_id, ip, index)
    else:
        local_index = index - (LOGS_PER_ENTITY // 2)
        log = gen_b(timestamp, user_id, ip, local_index)

    # Sobreescribimos el scenario para que el reporte lo identifique
    # como mixto, pero el label de anomalía ya viene correcto del generador base.
    log["scenario"] = scenario_name
    log["scenario_label"] = SCENARIO_LABELS.get(scenario_name, "anomaly")
    return log


def make_mixed_generator(gen_a, gen_b, scenario_name: str):
    """Fábrica que devuelve un generador mixto listo para usar en generate_entity_logs."""
    def _generator(timestamp, user_id, ip, index):
        return generate_mixed_log(timestamp, user_id, ip, index, gen_a, gen_b, scenario_name)
    return _generator


# ─── BLOQUE B: Generadores de falsos positivos ────────────────────────────────
#
# Estos generadores producen eventos que PARECEN anómalos superficialmente
# pero representan comportamiento normal con contexto:
#   - fp_login_retry:      usuario olvida contraseña → falla 2-3 veces → entra
#   - fp_maintenance_slow: endpoint lento por mantenimiento → vuelve a la normalidad
#   - fp_isolated_403:     un solo 403 aislado de un operador legítimo
#   - fp_burst_normal:     ráfaga de tráfico legítima (muchos GET rápidos)
#   - fp_single_500:       un único error 500, todo lo demás normal
#
# scenario_label = "normal" en todos — el modelo debe aprender a no disparar.

def generate_fp_login_retry(timestamp: datetime, user_id: str, ip: str, index: int) -> dict:
    """
    Patrón: 2-3 login_failed al inicio de cada bloque de 15 logs,
    seguido de login_success y tráfico normal.
    Un humano que olvidó su contraseña, no un atacante.
    """
    position = index % 15

    if position in [0, 1]:
        return create_log(
            timestamp, user_id, ip,
            "POST", "/login", 401,
            random.randint(150, 500),
            "login_failed",
            "Usuario ingresó credenciales incorrectas (reintento legítimo)",
            "warning", "fp_login_retry",
        )

    if position == 2:
        return create_log(
            timestamp, user_id, ip,
            "POST", "/login", 200,
            random.randint(200, 600),
            "login_success",
            "Inicio de sesión exitoso tras reintentos",
            "normal", "fp_login_retry",
        )

    return generate_normal_log(timestamp, user_id, ip)


def generate_fp_maintenance_slow(timestamp: datetime, user_id: str, ip: str, index: int) -> dict:
    """
    Patrón: ventana central (logs 30-50) con respuestas lentas
    que luego se recuperan. Simula un mantenimiento programado de 80 minutos.
    Antes y después: tráfico completamente normal.
    """
    if 30 <= index <= 50:
        # Slowness que decrece gradualmente hacia el final de la ventana
        if index <= 42:
            rt = random.randint(2800, 6000)
            severity = "warning"
        else:
            rt = random.randint(1200, 2800)
            severity = "warning"

        return create_log(
            timestamp, user_id, ip,
            "GET", "/api/reports", 200,
            rt,
            "slow_response",
            "Respuesta lenta por mantenimiento programado (recuperándose)",
            severity, "fp_maintenance_slow",
        )

    return generate_normal_log(timestamp, user_id, ip)


def generate_fp_isolated_403(timestamp: datetime, user_id: str, ip: str, index: int) -> dict:
    """
    Patrón: un único 403 en toda la secuencia (posición 40).
    Simula un operador que accidentalmente toca una ruta fuera de su rol.
    El modelo NO debe detectar esto como anomalía.
    """
    if index == 40:
        return create_log(
            timestamp, user_id, ip,
            "GET", "/dashboard/admin", 403,
            random.randint(150, 400),
            "unauthorized_access",
            "Acceso accidental a ruta admin por operador (evento aislado)",
            "warning", "fp_isolated_403",
        )

    return generate_normal_log(timestamp, user_id, ip)


def generate_fp_burst_normal(timestamp: datetime, user_id: str, ip: str, index: int) -> dict:
    """
    Patrón: muchas page_views y data_loaded en rápida sucesión.
    Simula un usuario power-user o un proceso de sincronización legítimo.
    Todos los status son 200, response_time normal.
    """
    # Es todo tráfico normal — la "anomalía" es solo la densidad de requests,
    # que en este dataset está controlada por LOGS_PER_ENTITY igual que los demás.
    event = random.choice([
        {"event_type": "page_view",   "method": "GET",  "status_code": 200, "message": "Carga legítima de página"},
        {"event_type": "data_loaded", "method": "GET",  "status_code": 200, "message": "Sincronización de datos legítima"},
        {"event_type": "record_created", "method": "POST", "status_code": 201, "message": "Creación de registro en lote"},
    ])
    return create_log(
        timestamp, user_id, ip,
        event["method"],
        random.choice(NORMAL_ROUTES),
        event["status_code"],
        random.randint(60, 400),   # más rápido que normal — es un proceso automatizado
        event["event_type"],
        event["message"],
        "normal", "fp_burst_normal",
    )


def generate_fp_single_500(timestamp: datetime, user_id: str, ip: str, index: int) -> dict:
    """
    Patrón: un único server_error 500 aislado (posición 55).
    Simula un error transitorio de infraestructura que no se repite.
    El modelo NO debe detectar esto como anomalía de payment_outage o database_outage.
    """
    if index == 55:
        return create_log(
            timestamp, user_id, ip,
            "GET", random.choice(NORMAL_ROUTES), 500,
            random.randint(800, 2000),
            "server_error",
            "Error interno transitorio aislado (no se repite)",
            "warning", "fp_single_500",
        )

    return generate_normal_log(timestamp, user_id, ip)


FALSE_POSITIVE_GENERATORS = {
    "fp_login_retry":      generate_fp_login_retry,
    "fp_maintenance_slow": generate_fp_maintenance_slow,
    "fp_isolated_403":     generate_fp_isolated_403,
    "fp_burst_normal":     generate_fp_burst_normal,
    "fp_single_500":       generate_fp_single_500,
}


# ─── BLOQUE C: Generadores de variantes de intensidad ────────────────────────
#
# Mismo patrón base, dos niveles de intensidad:
#   "low"  → ataques espaciados, degradación leve, señal más sutil
#   "high" → ráfaga concentrada, colapso total, señal más obvia
#
# Esto entrena al modelo a detectar el PATRÓN independientemente
# de si los valores numéricos son extremos o moderados.

def generate_brute_force_low(timestamp: datetime, user_id: str, ip: str, index: int) -> dict:
    """Intentos de login espaciados — 2 por ciclo de 15, no 4 por ciclo de 10."""
    position = index % 15
    if position in [0, 1]:
        return create_log(
            timestamp, user_id, ip,
            "POST", "/login", 401,
            random.randint(200, 600),
            "login_failed",
            "Intento de login fallido (baja frecuencia)",
            "critical", "brute_force_low",
        )
    return generate_normal_log(timestamp, user_id, ip)


def generate_brute_force_high(timestamp: datetime, user_id: str, ip: str, index: int) -> dict:
    """Ráfaga intensa — 7 de cada 10 son login_failed, response_time mínimo."""
    position = index % 10
    if position in [0, 1, 2, 3, 4, 5, 6]:
        return create_log(
            timestamp, user_id, ip,
            "POST", "/login", 401,
            random.randint(50, 200),   # muy rápido — herramienta automatizada
            "login_failed",
            "Ráfaga intensa de intentos de login fallidos",
            "critical", "brute_force_high",
        )
    return generate_normal_log(timestamp, user_id, ip)


def generate_payment_outage_low(timestamp: datetime, user_id: str, ip: str, index: int) -> dict:
    """Fallos de pago intermitentes — 2 de cada 15, response_time elevado pero no extremo."""
    position = index % 15
    if position in [0, 1]:
        return create_log(
            timestamp, user_id, ip,
            "POST", "/api/payments", 500,
            random.randint(1800, 4000),
            "payment_failed",
            "Fallo de pago intermitente (degradación leve)",
            "critical", "payment_outage_low",
        )
    return generate_normal_log(timestamp, user_id, ip)


def generate_payment_outage_high(timestamp: datetime, user_id: str, ip: str, index: int) -> dict:
    """Colapso total del gateway — 8 de cada 10 fallan, timeouts máximos."""
    position = index % 10
    if position in [0, 1, 2, 3, 4, 5, 6, 7]:
        return create_log(
            timestamp, user_id, ip,
            "POST", "/api/payments", 500,
            random.randint(7000, 9000),
            "payment_failed",
            "Colapso total de pasarela de pagos",
            "critical", "payment_outage_high",
        )
    return generate_normal_log(timestamp, user_id, ip)


def generate_database_outage_low(timestamp: datetime, user_id: str, ip: str, index: int) -> dict:
    """Timeouts de BD esporádicos — 2 de cada 20, respuesta elevada."""
    position = index % 20
    if position in [0, 1]:
        return create_log(
            timestamp, user_id, ip,
            "GET", "/api/database", 503,
            random.randint(2000, 4500),
            "database_timeout",
            "Timeout de base de datos esporádico (carga elevada)",
            "critical", "database_outage_low",
        )
    return generate_normal_log(timestamp, user_id, ip)


def generate_database_outage_high(timestamp: datetime, user_id: str, ip: str, index: int) -> dict:
    """BD completamente caída — 6 de cada 10 son 503, cascada a otros endpoints."""
    position = index % 10
    if position in [0, 1, 2, 3]:
        return create_log(
            timestamp, user_id, ip,
            "GET", "/api/database", 503,
            random.randint(7000, 9000),
            "database_timeout",
            "Base de datos completamente inaccesible",
            "critical", "database_outage_high",
        )
    if position in [4, 5]:
        return create_log(
            timestamp, user_id, ip,
            "GET", random.choice(["/api/reports", "/api/students", "/api/payments"]), 500,
            random.randint(6000, 9000),
            "server_error",
            "Error en cascada por caída total de BD",
            "critical", "database_outage_high",
        )
    return generate_normal_log(timestamp, user_id, ip)


def generate_performance_degradation_low(timestamp: datetime, user_id: str, ip: str, index: int) -> dict:
    """Degradación leve — respuestas de 2-4s, 3 de cada 20 logs."""
    position = index % 20
    if position in [0, 1, 2]:
        return create_log(
            timestamp, user_id, ip,
            "GET", "/api/reports", 200,
            random.randint(2200, 4500),
            "slow_response",
            "Respuesta lenta moderada (degradación leve del sistema)",
            "critical", "performance_degradation_low",
        )
    return generate_normal_log(timestamp, user_id, ip)


def generate_performance_degradation_high(timestamp: datetime, user_id: str, ip: str, index: int) -> dict:
    """Colapso de performance — respuestas >6s, 6 de cada 10 logs afectados."""
    position = index % 10
    if position in [0, 1, 2, 3, 4, 5]:
        return create_log(
            timestamp, user_id, ip,
            "GET", random.choice(["/api/reports", "/api/students", "/dashboard"]), 200,
            random.randint(6500, 9000),
            "slow_response",
            "Sistema bajo colapso de performance generalizado",
            "critical", "performance_degradation_high",
        )
    return generate_normal_log(timestamp, user_id, ip)


def generate_admin_probe_low(timestamp: datetime, user_id: str, ip: str, index: int) -> dict:
    """Exploración admin pausada — 1 intento cada 20 logs, patrón sutil."""
    position = index % 20
    if position == 0:
        return create_log(
            timestamp, user_id, ip,
            "GET", random.choice(["/dashboard/admin", "/api/admin/users"]), 403,
            random.randint(200, 600),
            "unauthorized_access",
            "Intento aislado de acceso admin (exploración pausada)",
            "critical", "admin_probe_low",
        )
    return generate_normal_log(timestamp, user_id, ip)


def generate_admin_probe_high(timestamp: datetime, user_id: str, ip: str, index: int) -> dict:
    """Exploración admin agresiva — 7 de cada 10 son intentos a rutas protegidas distintas."""
    admin_routes = [
        "/dashboard/admin",
        "/api/admin/users",
        "/api/enrollments",
        "/api/database",
        "/api/orders",
    ]
    position = index % 10
    if position in [0, 1, 2, 3, 4, 5, 6]:
        return create_log(
            timestamp, user_id, ip,
            "GET", random.choice(admin_routes), 403,
            random.randint(100, 500),
            "unauthorized_access",
            "Exploración agresiva de rutas administrativas protegidas",
            "critical", "admin_probe_high",
        )
    return generate_normal_log(timestamp, user_id, ip)


INTENSITY_GENERATORS = {
    "brute_force_low":               generate_brute_force_low,
    "brute_force_high":              generate_brute_force_high,
    "payment_outage_low":            generate_payment_outage_low,
    "payment_outage_high":           generate_payment_outage_high,
    "database_outage_low":           generate_database_outage_low,
    "database_outage_high":          generate_database_outage_high,
    "performance_degradation_low":   generate_performance_degradation_low,
    "performance_degradation_high":  generate_performance_degradation_high,
    "admin_probe_low":               generate_admin_probe_low,
    "admin_probe_high":              generate_admin_probe_high,
}


# ─── Generador de secuencia por entidad ───────────────────────────────────────

# [C6] Eliminado el parámetro "scenario" — era dead parameter.
# Los generadores ya conocen su propio escenario internamente.
def generate_entity_logs(
    ip: str,
    user_id: str,
    base_time: datetime,
    generator_fn,
) -> list[dict]:
    logs = []
    for index in range(LOGS_PER_ENTITY):
        timestamp = base_time + timedelta(
            minutes=index * 4,
            seconds=random.randint(0, 50),
        )
        logs.append(generator_fn(timestamp, user_id, ip, index))
    return logs


# ─── Validación de balance ────────────────────────────────────────────────────

# [C7] Valida que el ratio de logs críticos no supere MAX_ANOMALY_RATIO.
# Aborta con ValueError si se supera para forzar ajuste de parámetros.
def validate_balance(df: pd.DataFrame) -> None:
    total = len(df)
    critical_count = (df["severity"] == "critical").sum()
    ratio = critical_count / total

    print(f"\n[Balance] critical={critical_count} / total={total} → ratio={ratio:.2%}")

    if ratio > MAX_ANOMALY_RATIO:
        raise ValueError(
            f"Ratio de anomalías ({ratio:.2%}) supera el umbral permitido "
            f"({MAX_ANOMALY_RATIO:.0%}). "
            f"Ajusta NORMAL_ENTITIES o la densidad de los generadores."
        )

    print(f"[Balance] ✓ Ratio dentro del umbral ({MAX_ANOMALY_RATIO:.0%})")


# ─── Generación del dataset ───────────────────────────────────────────────────

def generate_dataset() -> pd.DataFrame:
    random.seed(RANDOM_SEED)

    all_logs = []
    base_start = datetime.now() - timedelta(days=7)
    entity_index = 0

    # ── Bloque normal (V2 heredado) ───────────────────────────────────────────
    for i in range(1, NORMAL_ENTITIES + 1):
        ip = make_ip(10, i)
        user_id = make_user("normal", i)
        base_time = entity_base_time(base_start, entity_index)
        logs = generate_entity_logs(
            ip=ip, user_id=user_id, base_time=base_time,
            generator_fn=lambda ts, uid, ip_, idx: generate_normal_log(ts, uid, ip_),
        )
        all_logs.extend(logs)
        entity_index += 1

    # ── Bloque warning (V2 heredado) ──────────────────────────────────────────
    for i in range(1, WARNING_ENTITIES + 1):
        ip = make_ip(20, i)
        user_id = make_user("warning", i)
        base_time = entity_base_time(base_start, entity_index)
        logs = generate_entity_logs(
            ip=ip, user_id=user_id, base_time=base_time,
            generator_fn=generate_warning_log,
        )
        all_logs.extend(logs)
        entity_index += 1

    # ── Bloque anomaly base (V2 heredado) ─────────────────────────────────────
    ip_group = 30
    for scenario, amount in ANOMALY_SCENARIOS.items():
        generator_fn = ANOMALY_GENERATORS[scenario]
        for i in range(1, amount + 1):
            ip = make_ip(ip_group, i)
            user_id = make_user(scenario, i)
            base_time = entity_base_time(base_start, entity_index)
            logs = generate_entity_logs(
                ip=ip, user_id=user_id, base_time=base_time,
                generator_fn=generator_fn,
            )
            all_logs.extend(logs)
            entity_index += 1
        ip_group += 1

    # ── BLOQUE A: Escenarios mixtos ───────────────────────────────────────────
    # Cada combo toma dos generadores base y los concatena en una sola entidad.
    # Primera mitad de la secuencia = gen_a, segunda mitad = gen_b.
    ip_group = 50
    for combo_index, (scenario_a, scenario_b) in enumerate(MIXED_SCENARIOS):
        gen_a = ANOMALY_GENERATORS[scenario_a]
        gen_b = ANOMALY_GENERATORS[scenario_b]
        scenario_name = f"mixed_{scenario_a}+{scenario_b}"

        mixed_gen = make_mixed_generator(gen_a, gen_b, scenario_name)

        for i in range(1, MIXED_ENTITIES_PER_COMBO + 1):
            ip = make_ip(ip_group, i)
            user_id = make_user(f"mixed_{combo_index + 1}", i)
            base_time = entity_base_time(base_start, entity_index)
            logs = generate_entity_logs(
                ip=ip, user_id=user_id, base_time=base_time,
                generator_fn=mixed_gen,
            )
            all_logs.extend(logs)
            entity_index += 1

        ip_group += 1

    # ── BLOQUE B: Falsos positivos entrenables ────────────────────────────────
    # scenario_label = "normal" — el modelo debe aprender a ignorarlos.
    ip_group = 70
    for fp_scenario, amount in FALSE_POSITIVE_SCENARIOS.items():
        generator_fn = FALSE_POSITIVE_GENERATORS[fp_scenario]
        for i in range(1, amount + 1):
            ip = make_ip(ip_group, i)
            user_id = make_user(fp_scenario, i)
            base_time = entity_base_time(base_start, entity_index)
            logs = generate_entity_logs(
                ip=ip, user_id=user_id, base_time=base_time,
                generator_fn=generator_fn,
            )
            all_logs.extend(logs)
            entity_index += 1
        ip_group += 1

    # ── BLOQUE C: Variantes de intensidad ─────────────────────────────────────
    # Mismo patrón, distinta severidad de señal (low vs high).
    ip_group = 80
    for base_scenario, intensities in INTENSITY_VARIANTS.items():
        for intensity in intensities:
            variant_key = f"{base_scenario}_{intensity}"
            generator_fn = INTENSITY_GENERATORS[variant_key]
            for i in range(1, INTENSITY_ENTITIES_PER_VARIANT + 1):
                ip = make_ip(ip_group, i)
                user_id = make_user(variant_key, i)
                base_time = entity_base_time(base_start, entity_index)
                logs = generate_entity_logs(
                    ip=ip, user_id=user_id, base_time=base_time,
                    generator_fn=generator_fn,
                )
                all_logs.extend(logs)
                entity_index += 1
            ip_group += 1

    df = pd.DataFrame(all_logs)
    df = df.sort_values("timestamp").reset_index(drop=True)

    validate_balance(df)

    return df


# ─── Reporte ──────────────────────────────────────────────────────────────────

def build_report(df: pd.DataFrame) -> dict:
    total = len(df)
    critical_count = int((df["severity"] == "critical").sum())

    # Conteo de entidades por bloque para trazabilidad
    mixed_entity_count = len(MIXED_SCENARIOS) * MIXED_ENTITIES_PER_COMBO
    fp_entity_count = sum(FALSE_POSITIVE_SCENARIOS.values())
    intensity_entity_count = sum(
        len(intensities) * INTENSITY_ENTITIES_PER_VARIANT
        for intensities in INTENSITY_VARIANTS.values()
    )
    base_anomaly_count = sum(ANOMALY_SCENARIOS.values())

    return {
        "version": "v2",
        "total_logs": total,
        "logs_per_entity": LOGS_PER_ENTITY,
        "anomaly_ratio": round(critical_count / total, 4),
        "entity_summary": {
            "normal":           NORMAL_ENTITIES,
            "warning":          WARNING_ENTITIES,
            "anomaly_base":     base_anomaly_count,
            "bloque_a_mixed":   mixed_entity_count,
            "bloque_b_fp":      fp_entity_count,
            "bloque_c_intensity": intensity_entity_count,
            "total_entities":   (
                NORMAL_ENTITIES + WARNING_ENTITIES +
                base_anomaly_count + mixed_entity_count +
                fp_entity_count + intensity_entity_count
            ),
        },
        "severity_distribution":        df["severity"].value_counts().to_dict(),
        "scenario_label_distribution":  df["scenario_label"].value_counts().to_dict(),
        "scenario_distribution":        df["scenario"].value_counts().to_dict(),
        "event_type_distribution":      df["event_type"].value_counts().to_dict(),
    }


def save_outputs(df: pd.DataFrame, report: dict) -> None:
    os.makedirs(os.path.dirname(PRIMARY_OUTPUT_PATH), exist_ok=True)
    os.makedirs(os.path.dirname(REPORT_PATH), exist_ok=True)

    df.to_csv(V2_OUTPUT_PATH, index=False, encoding="utf-8-sig")
    df.to_csv(PRIMARY_OUTPUT_PATH, index=False, encoding="utf-8-sig")

    with open(REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4, ensure_ascii=False)


# ─── Entry point ──────────────────────────────────────────────────────────────

def main() -> None:
    df = generate_dataset()
    report = build_report(df)
    save_outputs(df, report)

    print("\nDataset V2 Extended generado correctamente.")
    print(f"Archivo V2:            {V2_OUTPUT_PATH}")
    print(f"Archivo pipeline:      {PRIMARY_OUTPUT_PATH}")
    print(f"Reporte:               {REPORT_PATH}")

    print("\nResumen:")
    print(json.dumps(report, indent=4, ensure_ascii=False))

    print("\nPrimeras filas:")
    print(df.head(10).to_string(index=False))


if __name__ == "__main__":
    main()