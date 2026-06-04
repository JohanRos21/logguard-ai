# LogGuard AI

Sistema de monitoreo, detección de anomalías y gestión de incidentes para logs web.

LogGuard AI recibe logs de aplicaciones web, los normaliza, los almacena en PostgreSQL y los analiza usando reglas explicables, modelos tradicionales de ML y un Transformer secuencial. Cuando detecta patrones anómalos, puede generar incidentes reales, enviarlos a un dashboard y notificar sistemas externos por webhook.

El proyecto está pensado como un prototipo técnico local-first, con arquitectura completa para backend, frontend, procesamiento asíncrono, persistencia, proyectos/API keys, control de uso y reentrenamiento controlado.

## Qué analiza

Algunos eventos que puede procesar:

* intentos fallidos de login
* accesos no autorizados
* pagos fallidos
* errores del servidor
* timeouts de base de datos
* respuestas lentas
* patrones anómalos por IP o secuencia de eventos

## Features

* API versionada con FastAPI.
* Generación de logs sintéticos y datasets controlados.
* Motor de reglas explicable.
* Detección con Isolation Forest.
* Análisis secuencial con Transformer.
* Ingesta real de logs.
* Adaptador universal para JSON flexible, logfmt y access logs.
* Persistencia en PostgreSQL.
* Procesamiento asíncrono con Redis y Celery.
* Incidentes reales con ciclo de vida: acknowledge, resolve y reopen.
* Notificaciones webhook.
* Dashboard en Next.js.
* Proyectos y API keys por proyecto.
* Registro de uso por proyecto y planes.
* Feedback humano sobre incidentes.
* Reentrenamiento controlado.
* Registro de modelos globales y por proyecto.
* Stack completo con Docker Compose.

## Arquitectura

Flujo general:

```txt
External logs
-> Universal log adapter
-> PostgreSQL
-> Sequence analysis
-> Transformer prediction
-> Real incidents
-> Dashboard / Webhook / Feedback
-> Controlled retraining dataset
-> Candidate model
-> Model registry
```

Servicios principales:

* FastAPI backend
* PostgreSQL
* Redis
* Celery worker
* Next.js frontend

## Versiones del proyecto

El proyecto fue construido por etapas:

* [V1](READMEV1.md): reglas explicables, `risk_score`, Isolation Forest y primera API con FastAPI.
* [V2](READMEV2.md): dataset secuencial y Transformer Encoder para anomalías en secuencias de logs.
* [V3](READMEV3.md): PostgreSQL, ingesta real, auto-análisis, incidentes reales y dashboard.
* [V4](READMEV4.md): adaptador universal e ingesta adaptativa para formatos externos.
* [V5](READMEV5.md): Redis, Celery, análisis asíncrono, lifecycle de incidentes, webhooks y Docker.
* [V6](READMEV6.md): proyectos, API keys, usage tracking, planes, retraining controlado y model registry.

## Stack

Backend:

* Python
* FastAPI
* SQLAlchemy
* PostgreSQL
* Redis
* Celery
* Pandas
* NumPy
* Scikit-learn
* PyTorch

Frontend:

* Next.js
* React
* TypeScript
* Tailwind CSS
* Recharts
* Lucide React

Infraestructura:

* Docker Compose
* PostgreSQL 16
* Redis 7

## Ejecutar con Docker

Crear el archivo de entorno:

```powershell
copy .env.docker.example .env.docker
```

Editar `.env.docker` y definir una API key propia:

```env
LOGGUARD_API_KEY=change-me
```

Levantar todo el stack:

```powershell
docker compose --env-file .env.docker up -d --build
```

El backend ejecuta las migraciones al iniciar. Si se quieren correr manualmente:

```powershell
docker compose --env-file .env.docker exec backend python scripts/migrate_all.py
```

URLs locales:

```txt
Backend:  http://127.0.0.1:8001
Swagger:  http://127.0.0.1:8001/docs
Frontend: http://127.0.0.1:3001
```

## Endpoints

La lista completa está disponible en Swagger:

```txt
http://127.0.0.1:8001/docs
```

Algunos grupos principales:

```txt
GET  /health
GET  /metrics
POST /analyze-log
```

```txt
POST /v3/ingest-log
POST /v3/ingest-batch
GET  /v3/real-monitoring-summary
```

```txt
GET  /v4/adapters
POST /v4/normalization-preview
POST /v4/ingest-adaptive-log
POST /v4/ingest-adaptive-batch
```

```txt
POST  /v5/analyze-entity-async
GET   /v5/incidents
PATCH /v5/incidents/{incident_id}/acknowledge
PATCH /v5/incidents/{incident_id}/resolve
PATCH /v5/incidents/{incident_id}/reopen
GET   /v5/notifications
GET   /v5/tasks/{task_id}
```

```txt
GET  /v6/auth/whoami
GET  /v6/plans
GET  /v6/usage/me
POST /v6/projects
POST /v6/projects/{project_id}/api-keys
POST /v6/incidents/{incident_id}/feedback
POST /v6/retraining/jobs
GET  /v6/model-versions/resolve
POST /v6/model-versions/{model_version_id}/activate
```

## Variables de entorno

Usar estos archivos como base:

```txt
.env.example
.env.docker.example
```

No subir archivos locales con secretos:

```txt
.env
.env.docker
```

Variables importantes:

```env
LOGGUARD_API_KEY=change-me
LOGGUARD_ASYNC_ANALYSIS=true
LOGGUARD_NOTIFICATIONS_ENABLED=false
LOGGUARD_WEBHOOK_ENABLED=false
LOGGUARD_RETRAINING_ACTUAL_ENABLED=false
LOGGUARD_MODEL_ACTIVATION_COPY_ENABLED=false
```

## Modelos entrenados

Los artefactos entrenados pueden estar fuera del repositorio, especialmente si están en:

```txt
models/
```

Si el repo no incluye el modelo Transformer, se debe entrenar localmente o colocar los artefactos esperados en:

```txt
models/sequence_transformer
```

El model registry de V6 maneja modelos candidatos, globales y por proyecto como metadata controlada. Por defecto no reemplaza físicamente el Transformer activo.

## Seguridad

Los endpoints protegidos usan:

```txt
Authorization: Bearer <token>
```

Hay dos tipos de token:

* Master API key: administra proyectos, retraining jobs y activación de modelos.
* Project API key: opera dentro de un proyecto específico.

Las project API keys no se guardan en texto plano. Se almacenan con hash, prefix y últimos caracteres visibles.

No se deben enviar passwords, cookies, tokens, tarjetas ni otros secretos dentro de los logs ingeridos.

## Validación rápida

Compilar:

```powershell
python -m compileall backend/app scripts/migrate_all.py
```

Ejecutar migraciones:

```powershell
docker compose --env-file .env.docker exec backend python scripts/migrate_all.py
```

Health check:

```txt
GET http://127.0.0.1:8001/health
```

## Estado

LogGuard AI queda como un prototipo técnico completo para monitoreo y analítica de seguridad sobre logs web.

Incluye backend, frontend, persistencia, cola de tareas, dashboard, ingesta real, incidentes, proyectos, API keys, usage tracking, reentrenamiento controlado y model registry.

Limitaciones actuales:

* No incluye facturación real.
* No incluye despliegue cloud automatizado.
* No reemplaza automáticamente el Transformer físico activo.
* No ejecuta entrenamiento pesado por defecto.
* La activación de modelos funciona como metadata del registry por defecto.
