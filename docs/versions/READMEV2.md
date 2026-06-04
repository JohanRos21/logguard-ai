LogGuard AI V2

La V2 de LogGuard AI extiende la primera versión del sistema agregando detección secuencial de anomalías mediante un Transformer Encoder pequeño entrenado desde cero.

Mientras que la V1 analiza eventos individuales y señales tabulares, la V2 analiza secuencias completas de logs para detectar patrones temporales anómalos.

Resumen de evolución

V1:

-- Motor de reglas explicable.
-- Risk score.
-- Isolation Forest para detección de anomalías en logs individuales.
-- Alert Manager para consolidar incidentes.
-- API FastAPI para consultar métricas, alertas, anomalías e incidentes.

V2:

-- Dataset controlado extendido.
-- Secuencias de logs agrupadas por IP.
-- Transformer Encoder pequeño para detectar patrones temporales.
-- Predicción normal/anomaly sobre secuencias.
-- Nuevos endpoints API para análisis secuencial.

Motivación de la V2

La V1 puede detectar eventos peligrosos individuales, como un pago fallido, un error 500, un timeout de base de datos o un intento de acceso no autorizado.

Sin embargo, muchos incidentes reales no se entienden completamente mirando un solo log. En varios casos, el riesgo aparece en el patrón completo:

login_failed → login_failed → login_failed → unauthorized_access

payment_failed → payment_failed → server_error → database_timeout

slow_response → slow_response → server_error

Por eso, la V2 incorpora un modelo Transformer capaz de analizar el orden y la combinación de eventos en una ventana temporal.

Dataset controlado extendido

Para entrenar el Transformer se construyó un dataset controlado extendido con distintos tipos de comportamiento:

-- Tráfico normal limpio.
-- Warning controlado.
-- Falsos positivos entrenables.
-- Anomalías simples.
-- Escenarios mixtos.
-- Variantes de intensidad low/high.

El objetivo no fue solo aumentar la cantidad de logs, sino mejorar la calidad del entrenamiento.

El dataset incluye casos normales, casos sospechosos pero legítimos y anomalías reales simuladas.

Esto permite que el modelo aprenda que no todo evento sospechoso debe clasificarse como anomalía.

Ejemplo de falso positivo entrenable:

login_failed → login_failed → login_success → data_loaded

Este patrón puede representar un usuario que olvidó su contraseña, no necesariamente un ataque.

Ejemplo de anomalía real:

login_failed → login_failed → login_failed → login_failed → unauthorized_access

Este patrón sí representa un posible intento de fuerza bruta o abuso de acceso.

Bloques del dataset V2

Bloque A: Escenarios mixtos

Este bloque combina dos tipos de anomalías en una misma entidad.

Ejemplos:

-- brute_force + admin_probe
-- payment_outage + database_outage
-- performance_degradation + payment_outage

Objetivo:

Mejorar la generalización del modelo frente a incidentes compuestos.

Bloque B: Falsos positivos entrenables

Este bloque incluye eventos que parecen anómalos, pero se etiquetan como normales por su contexto.

Ejemplos:

-- usuario que falla login 2 o 3 veces y luego inicia sesión correctamente
-- un único error 500 aislado
-- un acceso 403 accidental
-- endpoint lento durante mantenimiento y luego recuperación

Objetivo:

Reducir falsos positivos y mejorar la precisión del modelo.

Bloque C: Variantes de intensidad

Este bloque genera el mismo escenario con distintas intensidades.

Ejemplos:

-- brute_force_low
-- brute_force_high
-- database_outage_low
-- database_outage_high
-- performance_degradation_low
-- performance_degradation_high

Objetivo:

Evitar que el modelo memorice valores exactos y ayudarlo a aprender patrones.

Dataset secuencial

A partir de los logs procesados se generó un dataset de secuencias.

Configuración:

-- Agrupación: por IP.
-- Tamaño de ventana: 20 eventos.
-- Stride: 5 eventos.
-- Etiquetas: normal / anomaly.

Resultado final:

-- Total de secuencias: 1875
-- Secuencias normal: 975
-- Secuencias anomaly: 900
-- Tasa de anomalías: 48%

Este balance permite entrenar el Transformer sin que el modelo aprenda a favorecer una sola clase.

Modelo Transformer

La V2 usa un Transformer Encoder pequeño entrenado desde cero.

No se usó BERT ni DistilBERT porque los logs del proyecto son eventos estructurados, no texto natural largo.

Entrada del modelo:

-- event_sequence
-- route_sequence
-- status_sequence
-- method_sequence

Cada secuencia se transforma a IDs mediante vocabularios propios y luego pasa por embeddings.

Arquitectura general:

event_sequence + route_sequence + status_sequence + method_sequence
→ tokenización
→ embeddings
→ positional embedding
→ Transformer Encoder
→ pooling
→ capa densa
→ normal / anomaly

Configuración del modelo:

-- max_len: 20
-- embedding_dim: 64
-- num_heads: 4
-- num_layers: 2
-- ff_dim: 128
-- dropout: 0.2
-- epochs: 15
-- batch_size: 32
-- learning_rate: 0.001

Resultados del Transformer V2

Resultados obtenidos en el conjunto de prueba:

-- Accuracy: 0.9733
-- Precision anomaly: 0.9670
-- Recall anomaly: 0.9778
-- F1 anomaly: 0.9724

Matriz de confusión:

[[189, 6],
[4, 176]]

Interpretación:

-- 189 secuencias normales clasificadas correctamente.
-- 176 secuencias anómalas detectadas correctamente.
-- 6 falsos positivos.
-- 4 falsos negativos.

El modelo no alcanza 100%, pero eso es normal y deseable en un escenario realista. Un resultado perfecto podría indicar sobreajuste, dataset demasiado artificial o evaluación demasiado fácil.

API V2

La V2 agrega nuevos endpoints a la API FastAPI.

Endpoints nuevos:

GET /v2/metrics

Devuelve el reporte del dataset secuencial y las métricas del Transformer.

GET /v2/sequence-predictions

Permite revisar las predicciones generadas durante la evaluación del modelo.

POST /v2/analyze-sequence

Permite analizar una nueva secuencia de logs usando el Transformer entrenado.

Ejemplo de entrada:

{
"event_sequence": [
"login_failed",
"login_failed",
"login_failed",
"unauthorized_access"
],
"route_sequence": [
"/login",
"/login",
"/login",
"/dashboard/admin"
],
"status_sequence": [
"401",
"401",
"401",
"403"
],
"method_sequence": [
"POST",
"POST",
"POST",
"GET"
],
"threshold": 0.5
}

Ejemplo de salida:

{
"version": "v2",
"model": "LogSequenceTransformer",
"result": {
"prediction": "anomaly",
"anomaly_probability": 0.9997,
"severity_suggestion": "critical"
}
}

Archivos principales de V2

Generador de dataset controlado:

scripts/generate_controlled_logs_v2.py

Constructor de secuencias:

backend/app/services/sequence_builder_service.py

Entrenamiento del Transformer:

backend/app/ml/train_sequence_transformer.py

Predicción con Transformer:

backend/app/ml/predict_sequence_transformer.py

API principal:

backend/app/main.py

Archivos generados

Dataset controlado:

data/synthetic/web_logs_v2_extended.csv
data/synthetic/web_logs.csv

Logs procesados:

data/processed/logs_processed.csv

Dataset secuencial:

data/processed/log_sequences.csv

Modelo Transformer:

models/sequence_transformer/sequence_transformer.pt
models/sequence_transformer/vocab.json
models/sequence_transformer/config.json
models/sequence_transformer/metrics.json

Reportes:

reports/v2_extended_log_generation_report.json
reports/sequence_dataset_report.json
reports/sequence_transformer_report.json
reports/sequence_transformer_predictions.csv

Cómo ejecutar V2
Generar dataset controlado extendido:

python scripts/generate_controlled_logs_v2.py

Procesar logs:

python backend/app/services/log_processor_service.py

Construir secuencias:

python backend/app/services/sequence_builder_service.py

Entrenar Transformer:

python backend/app/ml/train_sequence_transformer.py

Probar predicción por consola:

python backend/app/ml/predict_sequence_transformer.py

Ejecutar API:

uvicorn backend.app.main --reload

Abrir Swagger:

http://127.0.0.1:8001/docs (O el que tenga levantado)

Comparación V1 vs V2

V1 analiza eventos individuales.

V2 analiza patrones temporales.

V1 usa Isolation Forest sobre features tabulares.

V2 usa Transformer Encoder sobre secuencias de eventos.

V1 responde a la pregunta:

¿Este log individual parece raro?

V2 responde a la pregunta:

¿Esta secuencia de comportamiento parece anómala?

Conclusión:

La V2 no reemplaza completamente a la V1. La complementa.

La arquitectura final queda más robusta combinando:

-- Reglas explicables.
-- Isolation Forest.
-- Transformer secuencial.

Limitaciones de la V2

La V2 sigue usando datos sintéticos controlados, no logs reales de producción.

El Transformer fue entrenado sobre escenarios diseñados manualmente.

El sistema todavía no usa base de datos persistente.

La API analiza secuencias enviadas manualmente, pero aún no consume logs en tiempo real.

El modelo puede tener falsos positivos y falsos negativos, como cualquier sistema de detección real.

El desempeño debe validarse con logs reales antes de considerarse apto para producción.

Próximas mejoras

-- Integrar almacenamiento en base de datos.
-- Crear dashboard visual.
-- Recibir logs crudos en tiempo real.
-- Consolidar alertas V1 y V2 en un mismo Alert Manager.
-- Agregar validación por entidad para evaluación más estricta.
-- Ajustar threshold según precisión o recall deseado.
-- Entrenar con logs reales o semirreales.
-- Desplegar con Docker.