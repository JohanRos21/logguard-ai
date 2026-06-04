LogGuard AI V6

La V6 agrega una capa multi-proyecto sobre LogGuard AI.

Esta version incorpora proyectos, claves API por proyecto, registro de uso, reentrenamiento controlado y un registro de modelos global/proyecto.

La V6 no reemplaza automaticamente el Transformer activo.
Los modelos nuevos quedan como candidatos y solo pueden activarse de forma explicita usando la master key.


Resumen de V6

La V6 incluye:

-- Proyectos y claves API por proyecto.
-- Registro de uso y planes.
-- Pipeline de reentrenamiento controlado.
-- Registro de modelos global/proyecto.
-- Puente seguro hacia entrenamiento real.
-- Resolucion de modelo por project_id.


Proyectos y claves API

La V6 permite crear proyectos y generar claves API para cada proyecto.

Esto permite separar por proyecto:

-- logs ingeridos
-- predicciones reales
-- incidentes reales
-- notificaciones
-- retroalimentacion humana
-- uso
-- modelos candidatos

Endpoints principales:

GET /v6/auth/whoami
POST /v6/projects
GET /v6/projects
GET /v6/projects/{project_id}
PATCH /v6/projects/{project_id}
PATCH /v6/projects/{project_id}/disable
PATCH /v6/projects/{project_id}/plan

POST /v6/projects/{project_id}/api-keys
GET /v6/projects/{project_id}/api-keys
PATCH /v6/projects/{project_id}/api-keys/{key_id}/disable
POST /v6/projects/{project_id}/rotate-api-key

Reglas:

-- La master key administra proyectos.
-- Una clave API de proyecto opera solo dentro de su proyecto.
-- Un proyecto disabled no puede usar sus claves.
-- Una clave disabled o revoked no autentica.


Registro de uso y planes

La V6 registra uso diario por proyecto.

Se registra uso de:

-- logs ingeridos
-- batches ingeridos
-- tareas async creadas
-- predicciones creadas
-- incidentes creados
-- notificaciones enviadas o fallidas
-- eventos de retroalimentacion y reentrenamiento

Endpoints:

GET /v6/plans
GET /v6/usage/me
GET /v6/projects/{project_id}/usage
GET /v6/projects/{project_id}/usage/daily

Notas:

-- Los planes disponibles actualmente son free, pro y enterprise.
-- Los limites concretos no se fijan en este README.
-- Los limites actuales deben consultarse con GET /v6/plans.
-- La master key no esta limitada por plan.
-- Las claves API de proyecto pueden quedar sujetas a limites.


Reentrenamiento controlado

La V6 permite guardar retroalimentacion humana sobre incidentes y usarla para preparar datasets controlados de reentrenamiento.

Modelos/tablas principales:

incident_feedback
retraining_jobs
model_versions

Etiquetas de retroalimentacion:

confirmed_anomaly
false_positive
normal_behavior
needs_review

Modos de reentrenamiento:

dataset_only
dry_run
train_candidate

Endpoints:

POST /v6/incidents/{incident_id}/feedback
GET /v6/incidents/{incident_id}/feedback
GET /v6/feedback

POST /v6/retraining/jobs
GET /v6/retraining/jobs
GET /v6/retraining/jobs/{job_id}
POST /v6/retraining/jobs/{job_id}/cancel

Cuando corre un job, LogGuard genera:

data/retraining/{job_id}/feedback_dataset.jsonl

Si el modo es train_candidate, tambien prepara:

data/retraining/{job_id}/candidate_model/
data/retraining/{job_id}/candidate_model_metadata.json

La tarea Celery asociada es:

logguard.run_retraining_job


Registro de modelos global/proyecto

La V6 agrega un registro de versiones de modelo.

Alcances soportados:

global
project

Regla de resolucion:

1. Si el proyecto tiene un modelo activo propio, se usa ese.
2. Si no tiene modelo propio, se usa el modelo global activo.
3. Si no hay modelo global activo en base de datos, se usa el fallback del sistema de archivos:

models/sequence_transformer

Endpoints:

GET /v6/model-versions
GET /v6/model-versions/active
GET /v6/model-versions/resolve
POST /v6/model-versions/{model_version_id}/activate

Reglas:

-- Activar un modelo requiere master key.
-- Activar un modelo archiva el modelo activo anterior del mismo alcance.
-- Activar no copia ni sobrescribe models/sequence_transformer.
-- Un modelo candidato no se activa automaticamente.


Puente seguro de entrenamiento

El puente seguro vive en:

backend/app/services/model_training_bridge.py

Responsabilidades:

-- Leer feedback_dataset.jsonl.
-- Preparar un dataset candidato intermedio.
-- Crear data/retraining/{job_id}/candidate_model/.
-- Crear candidate_model_metadata.json.
-- Evitar cualquier reemplazo automatico del modelo activo.

Variables relacionadas:

LOGGUARD_RETRAINING_ACTUAL_ENABLED=false
LOGGUARD_MODEL_ACTIVATION_COPY_ENABLED=false

Comportamiento por defecto:

-- No ejecuta entrenamiento real.
-- No reemplaza models/sequence_transformer.
-- Guarda actual_training_executed=false.
-- Guarda active_model_replaced=false.

Aunque LOGGUARD_RETRAINING_ACTUAL_ENABLED se active, el puente no ejecuta el entrenamiento real si no existe un flujo seguro de entrada y salida personalizada.


Seguridad

Una clave API de proyecto puede:

-- crear retroalimentacion de incidentes de su propio proyecto
-- consultar su propia retroalimentacion
-- usar endpoints de ingesta/consulta permitidos por proyecto

Una clave API de proyecto no puede:

-- crear jobs de reentrenamiento
-- activar modelos
-- modificar el modelo global

La master key puede:

-- administrar proyectos
-- crear jobs de reentrenamiento
-- cancelar jobs de reentrenamiento
-- activar versiones de modelo
-- consultar uso y registro global


Validacion rapida

Compilar:

python -m compileall backend/app scripts/migrate_v6_model_registry.py scripts/migrate_all.py

Ejecutar migraciones en Docker:

docker compose --env-file .env.docker exec backend python scripts/migrate_all.py

Probar en Swagger:

GET /v6/auth/whoami
GET /v6/plans
GET /v6/model-versions/resolve

Crear job de reentrenamiento controlado:

{
  "scope": "project",
  "project_id": "PROJ-XXXX",
  "mode": "train_candidate",
  "requested_by": "admin",
  "parameters": {
    "min_feedback": 1
  }
}

Resultado esperado por defecto:

status=completed
actual_training_executed=false
active_model_replaced=false


Alcance

La V6 incluye infraestructura para operar proyectos, uso, reentrenamiento controlado y registro de modelos.

La V6 no incluye:

-- facturacion
-- despliegue en nube
-- reemplazo automatico de modelos
-- entrenamiento pesado por defecto
-- borrado de modelos o datasets existentes
