LogGuard AI V3

La V3 de LogGuard AI extiende la V2 agregando persistencia en PostgreSQL, endpoints /v3, dashboard visual, ingesta real de logs externos, análisis automático con el Transformer e incidentes reales.

Mientras que la V2 analiza secuencias enviadas manualmente al modelo, la V3 permite que un sistema externo envíe logs reales a LogGuard para que sean almacenados, agrupados, analizados y convertidos en alertas/incidentes entendibles.

Resumen de evolución

V1:

-- Motor de reglas explicable.
-- Risk score.
-- Isolation Forest para detección de anomalías en logs individuales.
-- Alert Manager inicial.
-- API FastAPI para consultar métricas, alertas, anomalías e incidentes.

V2:

-- Dataset controlado extendido.
-- Secuencias de logs agrupadas por IP.
-- Transformer Encoder pequeño para detectar patrones temporales.
-- Predicción normal/anomaly sobre secuencias.
-- Endpoints API para análisis secuencial.

V3:

-- Persistencia en PostgreSQL.
-- SQLAlchemy como capa de acceso a datos.
-- Endpoints /v3 conectados a base de datos.
-- Dashboard visual.
-- Ingesta real de logs externos.
-- API Key para proteger la ingesta.
-- Auto-análisis de logs reales con el Transformer.
-- Generación de incidentes reales.
-- Integración visual con una plataforma externa.

Motivación de la V3

La V2 resolvió el problema de analizar patrones temporales mediante secuencias de logs.

Sin embargo, todavía tenía varias limitaciones:

-- El sistema seguía dependiendo principalmente de archivos CSV/JSON.
-- No había persistencia real en base de datos.
-- El dashboard todavía no estaba conectado a datos persistentes.
-- Las secuencias se analizaban de forma manual.
-- No existía una ingesta real de logs desde otros sistemas.
-- No se generaban incidentes reales desde predicciones del Transformer.

La V3 busca convertir LogGuard AI en una plataforma más cercana a un sistema real de monitoreo.

El nuevo flujo es:

Sistema externo
→ POST /v3/ingest-log
→ PostgreSQL
→ Auto-análisis con Transformer
→ Predicción normal/anomaly
→ Incidente real
→ Dashboard
Persistencia con PostgreSQL

La V3 agrega PostgreSQL para almacenar datos históricos, métricas, predicciones, logs reales e incidentes.

Tablas principales:

-- processed_logs
-- log_sequences
-- sequence_predictions
-- model_metrics
-- ingested_logs
-- ingested_sequence_predictions
-- real_incidents

Esto permite que el sistema ya no dependa únicamente de archivos generados, sino que pueda consultar información desde una base de datos real.

Endpoints V3

La V3 agrega endpoints conectados a PostgreSQL.

Endpoints principales:

GET /v3/summary
GET /v3/logs
GET /v3/sequences
GET /v3/predictions
GET /v3/model-metrics
GET /v3/charts

Estos endpoints sirven para consultar datos históricos, métricas del modelo, predicciones y gráficos para el dashboard.

Ingesta real de logs

La V3 permite recibir logs reales desde sistemas externos.

Endpoints de ingesta:

POST /v3/ingest-log
POST /v3/ingest-batch

Estos endpoints requieren API Key:

Authorization: Bearer <LOGGUARD_API_KEY>

Ejemplo de log real:

{
  "source": "colegio_backend",
  "environment": "development",
  "event_type": "login_failed",
  "source_severity": "warning",
  "user_id": "123",
  "role": "ALUMNO",
  "ip": "127.0.0.1",
  "method": "POST",
  "route": "/api/login/",
  "status_code": 401,
  "response_time_ms": 84,
  "message": "Intento fallido de inicio de sesión",
  "metadata": {
    "reason": "invalid_credentials"
  }
}

source_severity es la severidad preliminar enviada por el sistema externo.

LogGuard calcula internamente la severidad final:

final_severity

No se deben enviar contraseñas, tokens, cookies ni datos sensibles.

Auto-análisis con Transformer

En V2, el análisis de secuencias se hacía enviando manualmente una secuencia al endpoint del Transformer.

En V3, cuando entran logs reales por /v3/ingest-log o /v3/ingest-batch, LogGuard intenta analizar automáticamente la última ventana de eventos de la entidad afectada.

Configuración base:

-- Agrupación: por IP.
-- Tamaño de ventana: 20 eventos.
-- Modelo: Transformer secuencial entrenado en V2.

Flujo:

ingested_logs
→ últimos 20 eventos por IP
→ Transformer
→ normal/anomaly
→ ingested_sequence_predictions

Si todavía no hay suficientes logs, el sistema responde con:

insufficient_logs

Si la ventana ya fue analizada, evita duplicados usando sequence_hash.

Predicciones reales

Las predicciones generadas desde logs reales se guardan en:

ingested_sequence_predictions

Campos principales:

-- Entidad analizada.
-- Secuencia de eventos.
-- Rutas.
-- Métodos.
-- Status codes.
-- Predicción IA.
-- Probabilidad de anomalía.
-- Severidad final.

Ejemplo conceptual:

{
  "entity_type": "ip",
  "entity_id": "127.0.0.1",
  "ai_prediction": "anomaly",
  "anomaly_probability": 0.9997,
  "final_severity": "critical"
}
Incidentes reales

La V3 también convierte predicciones anómalas en incidentes reales.

Tabla:

real_incidents

Endpoints:

POST /v3/generate-real-incidents
GET  /v3/real-incidents
GET  /v3/real-incidents/summary

Ejemplos de tipos de incidente:

-- repeated_unauthorized_access
-- brute_force_suspected
-- admin_probe
-- payment_risk
-- database_risk
-- performance_degradation
-- generic_anomaly

Esto permite que el dashboard no solo muestre ANOMALY, sino una alerta más clara.

Ejemplo:

Posible fuerza bruta detectada desde 127.0.0.1

con recomendación:

Revisar rate limiting, bloqueo temporal, intentos fallidos y protección de credenciales.
Dashboard

La V3 incluye un dashboard para visualizar:

-- Métricas del modelo entrenado.
-- Logs procesados.
-- Predicciones históricas.
-- Logs reales ingeridos.
-- Predicciones reales del Transformer.
-- Incidentes reales.
-- Gráficos por severidad, evento, ruta e IP.

También se integró visualmente en una plataforma externa mediante proxy.

Ejemplo de flujo:

/dashboard/admin/logguard
→ /api/logguard/v3/summary
→ LogGuard AI
Archivos principales de V3

Modelos de base de datos:

backend/app/db_models.py

Conexión PostgreSQL:

backend/app/database.py

Carga de datos históricos:

backend/app/services/database_seed_service.py

Consultas V3:

backend/app/services/database_query_service.py

Ingesta real:

backend/app/services/ingestion_service.py
backend/app/ingestion_schemas.py

Análisis de secuencias reales:

backend/app/services/realtime_sequence_service.py

Generación de incidentes reales:

backend/app/services/real_incident_service.py

API principal:

backend/app/main.py

Script de limpieza de monitoreo real:

scripts/clear_real_monitoring_data.py
Cómo ejecutar V3

Levantar PostgreSQL:

docker compose --env-file .env up -d postgres

Crear tablas:

python -m backend.app.database

Cargar datos históricos:

python -m backend.app.services.database_seed_service

Levantar API:

python -m uvicorn backend.app.main:app --reload --port 8001

Abrir Swagger:

http://127.0.0.1:8001/docs
Variables de entorno

Ejemplo:

POSTGRES_DB=logguard_ai
POSTGRES_USER=logguard_user
POSTGRES_PASSWORD=logguard_password
POSTGRES_HOST=127.0.0.1
POSTGRES_PORT=5433

DATABASE_URL=postgresql+psycopg://logguard_user:logguard_password@127.0.0.1:5433/logguard_ai

LOGGUARD_API_KEY=change-me

El archivo .env no debe subirse a GitHub.

Limpieza de datos reales de prueba

La V3 incluye un script para limpiar únicamente datos de monitoreo real:

python scripts\clear_real_monitoring_data.py

Este script limpia:

-- ingested_logs
-- ingested_sequence_predictions
-- real_incidents

No borra:

-- processed_logs
-- log_sequences
-- sequence_predictions
-- model_metrics
-- modelos entrenados
-- reportes

Comparación V2 vs V3

V2 responde a la pregunta:

¿Esta secuencia enviada manualmente parece anómala?

V3 responde a la pregunta:

¿Los logs reales que llegan desde un sistema externo muestran un comportamiento anómalo y deben convertirse en incidente?

La V3 no reemplaza a la V2.

La V3 usa el Transformer entrenado en V2 y lo conecta con un flujo real:

-- Ingesta.
-- Persistencia.
-- Auto-análisis.
-- Predicción.
-- Incidentes.
-- Dashboard.

Limitaciones de la V3

La V3 todavía espera que los sistemas externos envíen logs en el formato estructurado de LogGuard.

El sistema aún no normaliza automáticamente cualquier formato de log externo.

Los adaptadores multi-plataforma todavía no están implementados.

Los incidentes reales se generan con reglas iniciales sobre predicciones del Transformer.

El sistema todavía necesita validación con más datos reales.

Próximas mejoras

-- Dockerizar backend y frontend completos.
-- Crear un SDK ligero para enviar logs desde otros proyectos.
-- Agregar adaptadores para Django, Express, Nginx, Apache y JSON genérico.
-- Crear un Universal Log Adapter para normalizar logs de distintos formatos.
-- Agregar gestión de incidentes: acknowledged / resolved.
-- Agregar notificaciones por email o webhook.
-- Preparar despliegue completo.

Conclusión

La V3 convierte LogGuard AI en una plataforma de monitoreo real.

La V1 detecta anomalías en eventos individuales.

La V2 detecta anomalías en secuencias.

La V3 conecta ese modelo secuencial con logs reales, PostgreSQL, dashboard e incidentes reales.

La siguiente gran evolución sería una V4 enfocada en adaptación automática de formatos y soporte multi-plataforma.