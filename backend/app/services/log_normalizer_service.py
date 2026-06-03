import re
import shlex
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


AVAILABLE_ADAPTERS = [
    "generic_json",
    "django",
    "express",
    "nginx_basic",
    "apache_basic",
    "logfmt",
    "nginx_combined",
    "apache_combined",
    "common_access_log",
]

STRING_PAYLOAD_ADAPTERS = {
    "logfmt",
    "nginx_combined",
    "apache_combined",
    "common_access_log",
    "nginx_basic",
    "apache_basic",
}

ACCESS_LOG_PATTERN = re.compile(
    r"^(?P<ip>\S+)\s+\S+\s+\S+\s+"
    r"\[(?P<timestamp>[^\]]+)\]\s+"
    r'"(?P<method>\S+)\s+(?P<route>\S+)(?:\s+[^"]*)?"\s+'
    r"(?P<status>\d{3})\s+(?P<bytes_sent>\S+)"
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?.*$'
)


SENSITIVE_KEYS = {
    "password",
    "new_password",
    "old_password",
    "token",
    "access_token",
    "refresh_token",
    "authorization",
    "cookie",
    "cookies",
    "session",
    "csrf",
    "secret",
    "api_key",
    "card_number",
    "cvv",
}


FIELD_ALIASES = {
    "ip": [
        "ip",
        "client_ip",
        "remote_addr",
        "remoteAddress",
        "x_forwarded_for",
        "x-forwarded-for",
    ],
    "route": [
        "route",
        "path",
        "url",
        "endpoint",
        "request_path",
    ],
    "method": [
        "method",
        "http_method",
        "request_method",
    ],
    "status_code": [
        "status_code",
        "status",
        "code",
        "response_status",
    ],
    "response_time_ms": [
        "response_time_ms",
        "duration",
        "duration_ms",
        "elapsed_ms",
        "latency",
        "latency_ms",
    ],
    "source_severity": [
        "source_severity",
        "severity",
        "level",
        "log_level",
    ],
    "message": [
        "message",
        "msg",
        "error",
        "detail",
    ],
    "user_id": [
        "user_id",
        "user",
        "userId",
        "account_id",
    ],
    "role": [
        "role",
        "user_role",
    ],
    "event_type": [
        "event_type",
        "event",
        "type",
        "action",
    ],
    "timestamp": [
        "timestamp",
        "time",
        "datetime",
        "created_at",
    ],
}


def get_available_adapters() -> List[str]:
    return AVAILABLE_ADAPTERS


def _get_first_value(payload: Dict[str, Any], aliases: List[str]) -> Any:
    for key in aliases:
        if key in payload and payload[key] not in [None, ""]:
            return payload[key]

    return None


def _safe_int(value: Any) -> Optional[int]:
    if value is None or value == "":
        return None

    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _safe_float(value: Any) -> Optional[float]:
    if value is None or value == "":
        return None

    try:
        return float(value)
    except (TypeError, ValueError):
        match = re.search(r"-?\d+(?:\.\d+)?", str(value))

        if not match:
            return None

        try:
            return float(match.group(0))
        except ValueError:
            return None


def _safe_str(value: Any) -> Optional[str]:
    if value is None:
        return None

    return str(value).strip()


def _normalize_method(value: Any) -> str:
    method = _safe_str(value)

    if not method:
        return "GET"

    return method.upper()


def _normalize_severity(value: Any) -> Optional[str]:
    severity = _safe_str(value)

    if not severity:
        return None

    severity = severity.lower()

    if severity in ["warn", "warning"]:
        return "warning"

    if severity in ["error", "critical", "fatal"]:
        return "critical"

    if severity in ["info", "normal", "success", "debug"]:
        return "normal"

    return None


def _sanitize_metadata(metadata: Dict[str, Any]) -> Dict[str, Any]:
    clean_metadata = {}

    for key, value in metadata.items():
        key_lower = str(key).lower()

        if key_lower in SENSITIVE_KEYS:
            continue

        if any(sensitive_key in key_lower for sensitive_key in SENSITIVE_KEYS):
            continue

        if isinstance(value, dict):
            clean_metadata[key] = _sanitize_metadata(value)
        elif isinstance(value, list):
            clean_metadata[key] = [
                _sanitize_metadata(item) if isinstance(item, dict) else item
                for item in value
            ]
        else:
            clean_metadata[key] = value

    return clean_metadata


def _parse_logfmt_payload(payload: str) -> Optional[Dict[str, Any]]:
    try:
        tokens = shlex.split(payload)
    except ValueError:
        return None

    parsed = {}

    for token in tokens:
        if "=" not in token:
            continue

        key, value = token.split("=", 1)
        key = key.strip()

        if not key:
            continue

        parsed[key] = value

    return parsed or None


def _parse_access_log_timestamp(value: str) -> Optional[str]:
    try:
        return datetime.strptime(value, "%d/%b/%Y:%H:%M:%S %z").isoformat()
    except ValueError:
        return None


def _parse_access_log_payload(payload: str) -> Optional[Dict[str, Any]]:
    match = ACCESS_LOG_PATTERN.match(payload.strip())

    if not match:
        return None

    data = match.groupdict()
    method = data["method"]
    route = data["route"]
    status_code = data["status"]
    timestamp = _parse_access_log_timestamp(data["timestamp"])
    bytes_sent = data.get("bytes_sent")
    referer = data.get("referer")
    user_agent = data.get("user_agent")

    parsed = {
        "ip": data["ip"],
        "timestamp": timestamp,
        "method": method,
        "route": route,
        "status_code": status_code,
        "response_time_ms": 0,
        "message": f"HTTP {method} {route} returned {status_code}",
    }

    if bytes_sent and bytes_sent != "-":
        parsed["bytes_sent"] = bytes_sent

    if referer and referer != "-":
        parsed["referer"] = referer

    if user_agent and user_agent != "-":
        parsed["user_agent"] = user_agent

    return parsed


def _parse_string_payload(payload: str, adapter: str) -> Optional[Dict[str, Any]]:
    if adapter == "logfmt":
        return _parse_logfmt_payload(payload)

    if adapter in {
        "nginx_combined",
        "apache_combined",
        "common_access_log",
        "nginx_basic",
        "apache_basic",
    }:
        return _parse_access_log_payload(payload)

    return None


def _infer_event_type(
    route: str,
    method: str,
    status_code: int,
    response_time_ms: float,
) -> str:
    route_lower = route.lower()

    if status_code == 401 and "login" in route_lower:
        return "login_failed"

    if status_code == 403:
        return "unauthorized_access"

    if status_code >= 500:
        return "server_error"

    if ("payment" in route_lower or "payments" in route_lower) and status_code >= 400:
        return "payment_failed"

    if response_time_ms >= 1000:
        return "slow_response"

    if status_code in [400, 422]:
        return "validation_error"

    if status_code in [200, 201]:
        if method in ["POST", "PUT", "PATCH"]:
            return "record_created"

        if method == "GET":
            return "data_loaded"

    return "generic_event"


def _infer_source_severity(
    event_type: str,
    status_code: int,
    response_time_ms: float,
) -> str:
    if status_code >= 500:
        return "critical"

    if event_type in ["database_timeout", "server_error"]:
        return "critical"

    if status_code in [400, 401, 403, 422]:
        return "warning"

    if response_time_ms >= 1000:
        return "warning"

    return "normal"


def normalize_external_log(
    raw_log: Dict[str, Any],
    adapter: str = "generic_json",
    source: Optional[str] = None,
    environment: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Convierte un log externo flexible al formato canónico de LogGuard.

    Este servicio no guarda en BD, no llama al Transformer y no genera incidentes.
    Solo normaliza.
    """

    if not isinstance(raw_log, dict):
        raw_log = {"payload": raw_log}

    if adapter not in AVAILABLE_ADAPTERS:
        return {
            "success": False,
            "adapter_used": adapter,
            "normalized_log": None,
            "errors": [f"Adapter no soportado: {adapter}"],
            "warnings": [],
        }

    payload = raw_log.get("payload", raw_log)

    if isinstance(payload, str):
        parsed_payload = _parse_string_payload(payload, adapter)

        if parsed_payload is None:
            return {
                "success": False,
                "adapter_used": adapter,
                "normalized_log": None,
                "errors": [f"No se pudo parsear el payload con adapter {adapter}."],
                "warnings": [],
            }

        payload = parsed_payload

    if not isinstance(payload, dict):
        return {
            "success": False,
            "adapter_used": adapter,
            "normalized_log": None,
            "errors": ["El payload debe ser un objeto JSON."],
            "warnings": [],
        }

    source_value = source or raw_log.get("source") or payload.get("source") or "external_app"
    environment_value = (
        environment
        or raw_log.get("environment")
        or payload.get("environment")
        or "development"
    )

    timestamp = _get_first_value(payload, FIELD_ALIASES["timestamp"])
    ip = _get_first_value(payload, FIELD_ALIASES["ip"])
    route = _get_first_value(payload, FIELD_ALIASES["route"])
    method = _get_first_value(payload, FIELD_ALIASES["method"])
    status_code = _get_first_value(payload, FIELD_ALIASES["status_code"])
    response_time_ms = _get_first_value(payload, FIELD_ALIASES["response_time_ms"])
    source_severity = _get_first_value(payload, FIELD_ALIASES["source_severity"])
    message = _get_first_value(payload, FIELD_ALIASES["message"])
    user_id = _get_first_value(payload, FIELD_ALIASES["user_id"])
    role = _get_first_value(payload, FIELD_ALIASES["role"])
    event_type = _get_first_value(payload, FIELD_ALIASES["event_type"])

    method = _normalize_method(method)
    route = _safe_str(route) or "/"
    ip = _safe_str(ip) or "unknown"
    status_code = _safe_int(status_code) or 200
    response_time_ms = _safe_float(response_time_ms) or 0.0
    source_severity = _normalize_severity(source_severity)

    if not event_type:
        event_type = _infer_event_type(
            route=route,
            method=method,
            status_code=status_code,
            response_time_ms=response_time_ms,
        )
    else:
        event_type = _safe_str(event_type) or "generic_event"

    if not source_severity:
        source_severity = _infer_source_severity(
            event_type=event_type,
            status_code=status_code,
            response_time_ms=response_time_ms,
        )

    if not message:
        message = f"Normalized external log: {event_type}"

    metadata = {}

    for key, value in payload.items():
        all_aliases = [alias for aliases in FIELD_ALIASES.values() for alias in aliases]

        if key not in all_aliases:
            metadata[key] = value

    metadata["adapter"] = adapter

    normalized_log = {
        "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
        "source": _safe_str(source_value) or "external_app",
        "environment": _safe_str(environment_value) or "development",
        "event_type": event_type,
        "source_severity": source_severity,
        "user_id": _safe_str(user_id),
        "role": _safe_str(role),
        "ip": ip,
        "method": method,
        "route": route,
        "status_code": status_code,
        "response_time_ms": response_time_ms,
        "message": _safe_str(message) or f"Normalized external log: {event_type}",
        "metadata": _sanitize_metadata(metadata),
    }

    errors = []
    warnings = []

    if normalized_log["ip"] == "unknown":
        warnings.append("No se encontró IP. Se usó 'unknown'.")

    if normalized_log["route"] == "/":
        warnings.append("No se encontró ruta. Se usó '/'.")

    return {
        "success": True,
        "adapter_used": adapter,
        "normalized_log": normalized_log,
        "errors": errors,
        "warnings": warnings,
    }
