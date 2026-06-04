LogGuard AI

Sistema inteligente de monitoreo, detección de anomalías y gestión de incidentes en logs web.

Versión actual: V1

LogGuard AI V1 implementa una primera versión funcional de un sistema de análisis de logs que combina reglas explicables, detección de anomalías con Machine Learning y una API REST para consultar métricas, alertas e incidentes.

El objetivo de esta versión es validar el flujo base del sistema:

Logs web
→ procesamiento y feature engineering
→ reglas + IA
→ consolidación de incidentes
→ API FastAPI

Descripción del proyecto

LogGuard AI analiza eventos generados por aplicaciones web, como intentos de login, pagos fallidos, errores del servidor, accesos no autorizados, timeouts de base de datos y respuestas lentas.

El sistema permite detectar incidentes como:

-- Posibles ataques de fuerza bruta.
-- Accesos no autorizados.
-- Fallos repetidos en pagos.
-- Errores 500 en rutas críticas.
-- Timeouts de base de datos.
-- Respuestas anormalmente lentas.
-- Patrones inusuales detectados por Machine Learning.

La V1 está construida como una prueba funcional del flujo completo, usando logs sintéticos realistas y una arquitectura preparada para evolucionar a versiones más avanzadas.

Arquitectura V1


Flujo implementado en V1
Generación de logs sintéticos

Archivo:

scripts/generate_synthetic_logs.py

Genera logs web simulados con eventos como:

-- login_failed
-- payment_failed
-- unauthorized_access
-- database_timeout
-- server_error
-- slow_response

Salida:

data/synthetic/web_logs.csv

Procesamiento y feature engineering

Archivo:

backend/app/services/log_processor_service.py

Convierte los logs crudos en datos preparados para reglas e IA.

Genera variables como:

-- is_error
-- is_server_error
-- is_slow
-- is_critical_route
-- is_payment_failed
-- failed_logins_by_ip
-- errors_by_route
-- payment_failures_by_route
-- risk_score

Salida:

data/processed/logs_processed.csv

Motor de reglas

Archivo:

backend/app/services/rule_engine_service.py

Detecta alertas usando reglas explícitas y explicables.

Ejemplos de reglas:

-- Muchos login_failed desde una misma IP.
-- Accesos no autorizados a rutas administrativas.
-- Errores 5xx en rutas críticas.
-- Pagos fallidos repetidos.
-- Timeouts de base de datos.
-- Respuestas lentas en endpoints importantes.

Salidas:

reports/rule_alerts.csv
reports/rule_alerts.json

Detector de anomalías con Machine Learning

Archivos:

backend/app/ml/train_anomaly_model.py
backend/app/ml/predict_anomaly.py

Modelo usado:

Isolation Forest

El modelo analiza las features numéricas generadas por el procesador y detecta registros que se alejan del comportamiento normal.

Artefactos generados:

models/anomaly_detector/isolation_forest.pkl
models/anomaly_detector/scaler.pkl
models/anomaly_detector/feature_columns.json
models/anomaly_detector/metrics.json

Salidas:

reports/ml_anomalies.csv
reports/anomaly_detection_report.json

Gestor de incidentes

Archivo:

backend/app/services/alert_manager_service.py

Combina:

-- alertas por reglas
-- anomalías detectadas por IA
-- risk_score
-- severidad
-- tipo de evento
-- ruta afectada

El objetivo es evitar ruido y consolidar varias detecciones relacionadas en incidentes finales.

Salidas:

reports/final_incidents.csv
reports/final_incidents.json
reports/incident_summary.json

API REST con FastAPI

Archivo:

backend/app/main.py

Expone endpoints para consultar el estado del sistema, métricas, alertas, anomalías e incidentes.

Endpoints principales:

GET /
GET /health
GET /metrics
GET /alerts
GET /anomalies
GET /incidents
GET /incidents/{incident_id}
POST /analyze-log

Documentación automática:

http://127.0.0.1:8000/docs

Tecnologías utilizadas

-- Python
-- Pandas
-- NumPy
-- Scikit-learn
-- Isolation Forest
-- FastAPI
-- Uvicorn
-- Pydantic
-- Joblib
-- CSV / JSON

Resultados de la V1

Durante las pruebas de la V1 se generaron y analizaron 2108 logs sintéticos.

Resultados del detector ML:

-- Total de logs analizados: 2108
-- Anomalías detectadas por ML: 169
-- Tasa de anomalías: 8.02%

Distribución de anomalías detectadas por ML:

-- critical: 138
-- warning: 31

Después de consolidar reglas + IA mediante el gestor de incidentes, se obtuvo:

-- Incidentes consolidados: 464
-- Incidentes critical: 368
-- Incidentes warning: 96

También se identificaron rutas con mayor concentración de incidentes, como:

-- /api/payments
-- /api/enrollments
-- /api/database
-- /api/admin/users
-- /api/orders

Instalación
Crear entorno virtual

python -m venv venv

Activar entorno virtual en Windows

venv\Scripts\activate

Instalar dependencias

pip install -r backend/requirements.txt

Ejecución del flujo completo

Desde la raíz del proyecto, ejecutar en este orden:

Generar logs sintéticos

python scripts/generate_synthetic_logs.py

Procesar logs y crear features

python backend/app/services/log_processor_service.py

Ejecutar motor de reglas

python backend/app/services/rule_engine_service.py

Entrenar detector de anomalías

python backend/app/ml/train_anomaly_model.py

Probar predicción de anomalías

python backend/app/ml/predict_anomaly.py

Consolidar incidentes finales

python backend/app/services/alert_manager_service.py

Ejecutar API

uvicorn backend.app.main --reload

Abrir Swagger UI

http://127.0.0.1:8000/docs

Ejemplo de uso de la API

Endpoint:

POST /analyze-log

Este endpoint recibe features ya procesadas y devuelve:

-- resultado del modelo ML
-- severidad final
-- recomendación

Ejemplo de respuesta:

{
"ml_result": {
"is_anomaly": true,
"ml_prediction": -1,
"anomaly_score": -0.0729,
"severity_suggestion": "warning"
},
"final_severity": "critical",
"recommendation": "Revisar pasarela de pagos, errores del backend, webhooks y disponibilidad del servicio."
}

Esto demuestra que la V1 no depende únicamente del score del modelo. La severidad final combina IA con lógica de negocio, risk_score y señales críticas del log.

Alcance de la V1

La V1 incluye:

-- Generación de logs sintéticos.
-- Procesamiento y feature engineering.
-- Motor de reglas explicable.
-- Detector de anomalías con Isolation Forest.
-- Consolidación de incidentes.
-- API REST con FastAPI.
-- Swagger UI para pruebas.
-- Reportes en CSV y JSON.

Limitaciones de la V1

La V1 funciona como una primera versión funcional, pero tiene limitaciones importantes:

-- Usa logs sintéticos, no logs reales de producción.
-- El modelo ML usa Isolation Forest sobre features tabulares.
-- No analiza todavía secuencias profundas de eventos.
-- No incluye dashboard web visual.
-- No usa base de datos persistente.
-- El endpoint POST /analyze-log recibe features ya procesadas, no logs crudos.
-- Los modelos y reportes se generan localmente mediante scripts.

Transición hacia V2

La V1 valida la arquitectura base del sistema: generación de logs, procesamiento, reglas, detección ML, consolidación de incidentes y API.

La V2 se plantea como una evolución directa del mismo proyecto, no como un repositorio separado.

La razón principal para pasar a V2 es mejorar la capacidad del sistema para acercarse a un entorno más realista y robusto.

La V2 puede incluir:

-- Ingesta de logs crudos desde API.
-- Procesamiento automático dentro del backend.
-- Persistencia en base de datos.
-- Dashboard web interactivo.
-- Integración con una plataforma web real.
-- Mejor trazabilidad de incidentes.
-- Modelos más avanzados para análisis secuencial.
-- Posible uso de Deep Learning para detectar patrones de eventos en el tiempo.

Historial de versiones

V1

Primera versión funcional de LogGuard AI.

Incluye:

-- reglas explicables
-- Isolation Forest
-- risk_score
-- consolidación de incidentes
-- API FastAPI
-- reportes CSV/JSON
-- Swagger UI

V2

Próxima evolución del sistema.

Objetivo:

Convertir la V1 en una solución más cercana a producción, con mejor ingesta, almacenamiento, visualización, análisis secuencial y posible integración con plataformas reales.

Estado del proyecto

LogGuard AI V1 está funcional y probado localmente.

Estado actual:

-- scripts funcionando
-- modelo entrenado
-- reportes generados
-- incidentes consolidados
-- API activa
-- Swagger UI funcionando

Conclusión

LogGuard AI V1 demuestra una arquitectura inicial completa para detección de anomalías en logs web.

La solución combina reglas explícitas e inteligencia artificial mediante Isolation Forest para identificar eventos sospechosos y generar incidentes priorizados.

Esta primera versión sirve como base técnica para evolucionar hacia una V2 más robusta, con mayor automatización, persistencia, dashboard visual e integración con sistemas web reales.