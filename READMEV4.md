LogGuard AI V4

La V4 de LogGuard AI extiende la V3 agregando un Universal Log Adapter para recibir logs externos en formatos comunes y normalizarlos al formato interno del sistema.

Mientras que la V3 permite recibir logs reales en el formato estándar de LogGuard, la V4 permite aceptar formatos más flexibles como JSON genérico, logfmt y logs tipo Apache/Nginx.

Resumen de evolución

V1:

-- Motor de reglas explicable.
-- Risk score.
-- Isolation Forest para logs individuales.
-- Alert Manager inicial.
-- API FastAPI.

V2:

-- Dataset secuencial.
-- Secuencias agrupadas por IP.
-- Transformer Encoder para detectar anomalías temporales.
-- Predicción normal/anomaly sobre secuencias.

V3:

-- PostgreSQL.
-- Endpoints /v3.
-- Dashboard.
-- Ingesta real.
-- Auto-análisis con Transformer.
-- Predicciones reales.
-- Incidentes reales.

V4:

-- Universal Log Adapter.
-- Normalización de logs externos.
-- Ingesta adaptativa.
-- Soporte para JSON flexible, logfmt, Apache/Nginx combined y common access log.

Motivación de la V4

La V3 funciona bien cuando el sistema externo envía logs con el formato canónico de LogGuard.

Ejemplo:

{
  "event_type": "login_failed",
  "ip": "127.0.0.1",
  "method": "POST",
  "route": "/api/login",
  "status_code": 401,
  "response_time_ms": 84
}

Pero muchas aplicaciones usan otros nombres de campos:

{
  "level": "warn",
  "path": "/api/login",
  "status": 401,
  "duration": 84,
  "client_ip": "127.0.0.1"
}

La V4 agrega una capa que convierte esos formatos al estándar interno.

Flujo:

Log externo
→ Universal Log Adapter
→ Formato LogGuard
→ Ingesta V3
→ Transformer
→ Incidentes reales
Adaptadores soportados
generic_json
django
express
nginx_basic
apache_basic
logfmt
nginx_combined
apache_combined
common_access_log

Endpoint:

GET /v4/adapters
Normalización previa

Endpoint:

POST /v4/normalization-preview

Sirve para probar cómo LogGuard interpretaría un log externo.

No guarda en base de datos.
No llama al Transformer.
No genera incidentes.

Ejemplo con logfmt:

{
  "adapter": "logfmt",
  "source": "logfmt_app",
  "environment": "development",
  "payload": "level=warn method=POST path=/api/login status=401 duration=84ms ip=127.0.0.1 msg=\"Invalid credentials\" password=NO_GUARDAR"
}

Resultado esperado:

{
  "success": true,
  "adapter_used": "logfmt",
  "normalized_log": {
    "event_type": "login_failed",
    "source_severity": "warning",
    "ip": "127.0.0.1",
    "method": "POST",
    "route": "/api/login",
    "status_code": 401,
    "response_time_ms": 84,
    "message": "Invalid credentials"
  }
}

El campo password no se guarda en metadata.

Ingesta adaptativa

Endpoints:

POST /v4/ingest-adaptive-log
POST /v4/ingest-adaptive-batch

Estos endpoints normalizan el log externo y luego reutilizan el flujo de V3.

Flujo:

Log externo
→ normalización V4
→ ingested_logs
→ auto-análisis Transformer
→ ingested_sequence_predictions
→ real_incidents

Si todavía no hay 20 eventos de la misma IP, responde:

insufficient_logs

Si hay suficientes eventos, analiza automáticamente la secuencia.

Seguridad

Los endpoints protegidos usan API Key:

Authorization: Bearer <LOGGUARD_API_KEY>

Protegidos:

POST /v4/normalization-preview
POST /v4/ingest-adaptive-log
POST /v4/ingest-adaptive-batch

Público:

GET /v4/adapters
Formatos soportados
JSON flexible
{
  "level": "warn",
  "path": "/api/login",
  "status": 401,
  "duration": 84,
  "client_ip": "127.0.0.1"
}

Mapeos principales:

path      → route
status    → status_code
duration  → response_time_ms
client_ip → ip
level     → source_severity
msg       → message
logfmt
level=warn method=POST path=/api/login status=401 duration=84ms ip=127.0.0.1 msg="Invalid credentials"
Apache/Nginx Combined Log Format
127.0.0.1 - - [03/Jun/2026:10:15:32 -0500] "POST /api/login HTTP/1.1" 401 532 "-" "Mozilla/5.0"
Common Access Log
127.0.0.1 - - [03/Jun/2026:10:15:32 -0500] "GET /dashboard HTTP/1.1" 200 1024
Inferencia automática

Si el log no trae event_type, LogGuard lo infiere con reglas simples:

401 + login → login_failed
403 → unauthorized_access
500+ → server_error
payment + error → payment_failed
respuesta lenta → slow_response
400/422 → validation_error
200/201 + GET → data_loaded
200/201 + POST/PUT/PATCH → record_created

También infiere source_severity:

500+ → critical
400/401/403/422 → warning
respuesta lenta → warning
caso normal → normal
Sanitización

La V4 evita guardar datos sensibles en metadata.

Campos bloqueados:

password
token
access_token
refresh_token
authorization
cookie
session
csrf
secret
api_key
card_number
cvv
Archivos principales
backend/app/services/log_normalizer_service.py
backend/app/v4_schemas.py
backend/app/main.py

La V4 reutiliza los servicios de V3 para guardar logs, analizar secuencias y generar incidentes.

Comparación V3 vs V4

V3 responde:

¿Puede LogGuard recibir logs reales en su formato estándar?

V4 responde:

¿Puede LogGuard recibir logs externos en formatos comunes y adaptarlos automáticamente?

La V4 no reemplaza a la V3.
La V4 normaliza y luego usa la V3.

Limitaciones de la V4

-- No entiende cualquier formato de log existente.
-- Los parsers de Apache/Nginx cubren formatos comunes, no configuraciones avanzadas.
-- django y express funcionan principalmente sobre JSON flexible.
-- Todavía no existe SDK oficial.
-- Todavía no soporta OpenTelemetry ni Syslog.

Próximas mejoras

-- Crear SDK para Django, Express o FastAPI.
-- Agregar adaptadores específicos por framework.
-- Soportar OpenTelemetry JSON.
-- Soportar Syslog básico.
-- Permitir mappings personalizados por proyecto.
-- Agregar notificaciones por email o webhook.
-- Dockerizar backend y frontend completos.

Conclusión

La V4 convierte a LogGuard AI en una herramienta más flexible para integrarse con otros sistemas.

La V3 recibía logs reales si estaban en el formato de LogGuard.
La V4 permite recibir logs en formatos más comunes, normalizarlos y enviarlos al mismo flujo de análisis, predicción e incidentes reales.