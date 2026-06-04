LogGuard AI V5
Async Pipeline, Incident Lifecycle & Webhook Notifications

La V5 incorpora procesamiento asíncrono, gestión operativa de incidentes, notificaciones webhook y soporte completo con Docker Compose.

Principales cambios
Análisis asíncrono con Redis y Celery.
Ejecución del Transformer en segundo plano.
Consulta de tareas mediante task_id.
Ciclo de vida para incidentes reales.
Notificaciones webhook con historial.
Stack completo dockerizado: backend, worker, frontend, PostgreSQL y Redis.
Migraciones centralizadas con scripts/migrate_all.py.
Análisis asíncrono

Endpoints principales:

POST /v5/worker-ping
POST /v5/analyze-entity-async
GET  /v5/tasks/{task_id}

Flujo general:

FastAPI → Redis → Celery Worker → Transformer → Incidents
Gestión de incidentes

Estados soportados:

open
acknowledged
resolved
reopened

Endpoints principales:

GET   /v5/incidents
GET   /v5/incidents/summary
PATCH /v5/incidents/{incident_id}/acknowledge
PATCH /v5/incidents/{incident_id}/resolve
PATCH /v5/incidents/{incident_id}/reopen
Webhook notifications

Eventos soportados:

webhook.test
incident.created
incident.updated
incident.resolved
incident.reopened

Endpoints principales:

GET  /v5/notifications
GET  /v5/notifications/summary
POST /v5/notifications/test-webhook

Estados de notificación:

pending
sent
failed
skipped

Las notificaciones son opcionales y se configuran por variables de entorno.

Docker Compose

Servicios incluidos:

PostgreSQL
Redis
FastAPI Backend
Celery Worker
Next.js Frontend

Levantar el stack:

docker compose --env-file .env.docker up -d --build

Contenedores esperados:

logguard_postgres
logguard_redis
logguard_backend
logguard_worker
logguard_frontend

URLs:

Backend Swagger: http://127.0.0.1:8001/docs
Frontend:        http://127.0.0.1:3001
Variables Docker

Usar como base:

.env.docker.example

Variables principales:

DATABASE_URL=postgresql+psycopg://logguard_user:logguard_password@postgres:5432/logguard_ai

REDIS_URL=redis://redis:6379/0
CELERY_BROKER_URL=redis://redis:6379/0
CELERY_RESULT_BACKEND=redis://redis:6379/1

LOGGUARD_API_KEY=change-me
LOGGUARD_ASYNC_ANALYSIS=true

LOGGUARD_NOTIFICATIONS_ENABLED=false
LOGGUARD_WEBHOOK_ENABLED=false
LOGGUARD_WEBHOOK_URL=
LOGGUARD_WEBHOOK_TIMEOUT_SECONDS=5
Migraciones

Script general:

scripts/migrate_all.py

Ejecutar localmente:

python scripts/migrate_all.py

Ejecutar en Docker:

docker compose --env-file .env.docker exec backend python scripts/migrate_all.py
Validación rápida
GET  /v4/adapters
POST /v5/worker-ping
GET  /v5/tasks/{task_id}
GET  /v5/incidents
GET  /v5/notifications
Estado

V5 deja implementado:

Async analysis pipeline
Incident lifecycle management
Webhook notification system
Notification history
Full Docker Compose stack
Centralized migrations