from sqlalchemy import Boolean, Column, Date, DateTime, Float, Integer, String, Text, JSON, UniqueConstraint
from sqlalchemy.sql import func

from backend.app.database import Base


class ProcessedLog(Base):
    __tablename__ = "processed_logs"

    id = Column(Integer, primary_key=True, index=True)

    timestamp = Column(DateTime, index=True)
    user_id = Column(String(100), index=True)
    ip = Column(String(100), index=True)
    method = Column(String(20))
    route = Column(String(255), index=True)
    status_code = Column(Integer)
    response_time_ms = Column(Float)
    event_type = Column(String(100), index=True)
    message = Column(Text)
    severity = Column(String(50), index=True)

    scenario = Column(String(150), index=True)
    scenario_label = Column(String(50), index=True)

    hour = Column(Integer)
    day_of_week = Column(Integer)
    minute = Column(Integer)

    is_weekend = Column(Integer)
    is_night = Column(Integer)
    is_success = Column(Integer)
    is_client_error = Column(Integer)
    is_server_error = Column(Integer)
    is_error = Column(Integer)
    is_slow = Column(Integer)
    is_very_slow = Column(Integer)
    is_critical_route = Column(Integer)
    is_auth_event = Column(Integer)
    is_payment_event = Column(Integer)
    is_warning_event = Column(Integer)
    is_critical_event = Column(Integer)

    is_login_failed = Column(Integer)
    is_unauthorized = Column(Integer)
    is_payment_failed = Column(Integer)
    is_database_timeout = Column(Integer)

    requests_by_ip = Column(Integer)
    requests_by_user = Column(Integer)
    requests_by_route = Column(Integer)
    errors_by_ip = Column(Integer)
    errors_by_route = Column(Integer)
    failed_logins_by_ip = Column(Integer)
    failed_logins_by_user = Column(Integer)
    unauthorized_by_ip = Column(Integer)
    payment_failures_by_route = Column(Integer)

    avg_response_by_route = Column(Float)
    max_response_by_route = Column(Float)

    method_code = Column(Integer)
    route_code = Column(Integer)
    event_type_code = Column(Integer)
    severity_code = Column(Integer)

    risk_score = Column(Integer)

    created_at = Column(DateTime, server_default=func.now())


class LogSequence(Base):
    __tablename__ = "log_sequences"

    id = Column(Integer, primary_key=True, index=True)

    sequence_id = Column(String(50), unique=True, index=True)
    entity_type = Column(String(50), index=True)
    entity_id = Column(String(100), index=True)

    start_time = Column(DateTime, index=True)
    end_time = Column(DateTime, index=True)
    window_size = Column(Integer)

    event_sequence = Column(Text)
    route_sequence = Column(Text)
    status_sequence = Column(Text)
    method_sequence = Column(Text)

    avg_response_time = Column(Float)
    max_response_time = Column(Float)
    max_risk_score = Column(Integer)

    critical_count = Column(Integer)
    warning_count = Column(Integer)
    error_count = Column(Integer)
    server_error_count = Column(Integer)
    slow_count = Column(Integer)
    very_slow_count = Column(Integer)
    critical_route_count = Column(Integer)

    login_failed_count = Column(Integer)
    unauthorized_count = Column(Integer)
    payment_failed_count = Column(Integer)
    database_timeout_count = Column(Integer)

    label = Column(String(50), index=True)
    label_id = Column(Integer, index=True)
    reason = Column(Text)

    scenario_sequence = Column(Text)
    main_scenarios = Column(Text)
    scenario_label_sequence = Column(Text)
    scenario_label_distribution = Column(Text)

    created_at = Column(DateTime, server_default=func.now())


class SequencePrediction(Base):
    __tablename__ = "sequence_predictions"

    id = Column(Integer, primary_key=True, index=True)

    sequence_id = Column(String(50), index=True)
    entity_type = Column(String(50), index=True)
    entity_id = Column(String(100), index=True)

    start_time = Column(DateTime)
    end_time = Column(DateTime)
    window_size = Column(Integer)

    event_sequence = Column(Text)
    route_sequence = Column(Text)
    status_sequence = Column(Text)
    method_sequence = Column(Text)

    label = Column(String(50), index=True)
    label_id = Column(Integer)
    predicted_label = Column(String(50), index=True)
    predicted_label_id = Column(Integer)

    anomaly_probability = Column(Float)
    normal_probability = Column(Float)

    max_risk_score = Column(Integer)
    max_response_time = Column(Float)
    main_scenarios = Column(Text)
    reason = Column(Text)

    created_at = Column(DateTime, server_default=func.now())


class FinalIncident(Base):
    __tablename__ = "final_incidents"

    id = Column(Integer, primary_key=True, index=True)

    incident_id = Column(String(50), unique=True, index=True)
    severity = Column(String(50), index=True)
    severity_rank = Column(Integer)
    incident_type = Column(String(150), index=True)

    sources = Column(Text)
    detection_types = Column(Text)

    first_seen = Column(DateTime, index=True)
    last_seen = Column(DateTime, index=True)
    events_count = Column(Integer)

    user_id = Column(String(100), index=True)
    ip = Column(String(100), index=True)
    method = Column(String(20))
    route = Column(String(255), index=True)
    status_code = Column(Integer)
    max_response_time_ms = Column(Float)
    event_type = Column(String(100), index=True)

    max_risk_score = Column(Integer)
    min_anomaly_score = Column(Float)

    reason = Column(Text)
    recommendation = Column(Text)

    created_at = Column(DateTime, server_default=func.now())


class ModelMetric(Base):
    __tablename__ = "model_metrics"

    id = Column(Integer, primary_key=True, index=True)

    version = Column(String(50), index=True)
    model_name = Column(String(150), index=True)
    metric_source = Column(String(150))
    metrics_json = Column(JSON)

    created_at = Column(DateTime, server_default=func.now())


class IngestedLog(Base):
    __tablename__ = "ingested_logs"

    id = Column(Integer, primary_key=True, index=True)

    project_id = Column(String(50), nullable=True, index=True)
    timestamp = Column(DateTime, index=True)
    source = Column(String(100), index=True)
    environment = Column(String(50), index=True)
    event_type = Column(String(100), index=True)
    source_severity = Column(String(50), index=True)
    final_severity = Column(String(50), index=True)

    user_id = Column(String(100), index=True)
    role = Column(String(100), index=True)
    ip = Column(String(100), index=True)
    method = Column(String(20))
    route = Column(String(255), index=True)
    status_code = Column(Integer)
    response_time_ms = Column(Float)
    message = Column(Text)
    metadata_json = Column(JSON)

    ai_prediction = Column(String(100), nullable=True)
    anomaly_probability = Column(Float, nullable=True)

    created_at = Column(DateTime, server_default=func.now())


class IngestedSequencePrediction(Base):
    __tablename__ = "ingested_sequence_predictions"

    id = Column(Integer, primary_key=True, index=True)

    project_id = Column(String(50), nullable=True, index=True)
    sequence_hash = Column(String(64), unique=True, index=True)
    entity_type = Column(String(50), index=True)
    entity_id = Column(String(100), index=True)

    start_time = Column(DateTime, index=True)
    end_time = Column(DateTime, index=True)
    window_size = Column(Integer)

    event_sequence = Column(Text)
    route_sequence = Column(Text)
    status_sequence = Column(Text)
    method_sequence = Column(Text)

    ai_prediction = Column(String(50), index=True)
    anomaly_probability = Column(Float)
    normal_probability = Column(Float)
    final_severity = Column(String(50), index=True)
    source = Column(String(100), index=True)

    created_at = Column(DateTime, server_default=func.now())


class RealIncident(Base):
    __tablename__ = "real_incidents"

    id = Column(Integer, primary_key=True, index=True)

    project_id = Column(String(50), nullable=True, index=True)
    incident_id = Column(String(80), unique=True, index=True)
    incident_hash = Column(String(64), unique=True, index=True)

    title = Column(String(255))
    incident_type = Column(String(100), index=True)
    severity = Column(String(50), index=True)
    status = Column(String(50), index=True, default="open", server_default="open")

    entity_type = Column(String(50), index=True)
    entity_id = Column(String(100), index=True)
    source = Column(String(100), index=True)

    first_seen = Column(DateTime, index=True)
    last_seen = Column(DateTime, index=True)
    events_count = Column(Integer)
    sequences_count = Column(Integer)
    max_anomaly_probability = Column(Float)

    related_routes = Column(Text)
    related_event_types = Column(Text)
    related_sequence_ids = Column(Text)

    reason = Column(Text)
    recommendation = Column(Text)
    resolution_note = Column(Text, nullable=True)

    acknowledged_at = Column(DateTime, nullable=True)
    acknowledged_by = Column(String(100), nullable=True)
    resolved_at = Column(DateTime, nullable=True)
    resolved_by = Column(String(100), nullable=True)
    assignee = Column(String(100), nullable=True)

    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())


class NotificationEvent(Base):
    __tablename__ = "notification_events"

    id = Column(Integer, primary_key=True, index=True)

    project_id = Column(String(50), nullable=True, index=True)
    event_id = Column(String(50), unique=True, index=True)
    channel = Column(String(50), index=True, default="webhook", server_default="webhook")
    event_type = Column(String(100), index=True)

    incident_id = Column(String(80), nullable=True, index=True)
    severity = Column(String(50), nullable=True, index=True)
    status = Column(String(50), index=True, default="pending", server_default="pending")
    target = Column(Text, nullable=True)

    payload = Column(JSON, nullable=True)
    response_status_code = Column(Integer, nullable=True)
    response_body = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)

    created_at = Column(DateTime, server_default=func.now(), index=True)
    sent_at = Column(DateTime, nullable=True)


class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, index=True)

    project_id = Column(String(50), unique=True, index=True)
    name = Column(String(150), index=True)
    slug = Column(String(150), unique=True, index=True)
    description = Column(Text, nullable=True)
    status = Column(String(50), index=True, default="active", server_default="active")
    plan = Column(String(50), index=True, default="free", server_default="free")

    created_at = Column(DateTime, server_default=func.now(), index=True)
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())
    last_used_at = Column(DateTime, nullable=True)


class ProjectApiKey(Base):
    __tablename__ = "project_api_keys"

    id = Column(Integer, primary_key=True, index=True)

    key_id = Column(String(50), unique=True, index=True)
    project_id = Column(String(50), index=True)
    name = Column(String(150), nullable=True)
    key_prefix = Column(String(32), index=True)
    key_last4 = Column(String(4))
    key_hash = Column(String(64), unique=True, index=True)
    status = Column(String(50), index=True, default="active", server_default="active")

    created_at = Column(DateTime, server_default=func.now(), index=True)
    last_used_at = Column(DateTime, nullable=True)
    revoked_at = Column(DateTime, nullable=True)


class ProjectUsageDaily(Base):
    __tablename__ = "project_usage_daily"
    __table_args__ = (
        UniqueConstraint("project_id", "date", name="uq_project_usage_daily_project_date"),
    )

    id = Column(Integer, primary_key=True, index=True)

    project_id = Column(String(50), index=True)
    date = Column(Date, index=True)
    plan = Column(String(50), index=True)

    logs_ingested = Column(Integer, default=0, server_default="0")
    batches_ingested = Column(Integer, default=0, server_default="0")
    async_tasks_created = Column(Integer, default=0, server_default="0")
    predictions_created = Column(Integer, default=0, server_default="0")
    incidents_created = Column(Integer, default=0, server_default="0")
    notifications_sent = Column(Integer, default=0, server_default="0")
    notifications_failed = Column(Integer, default=0, server_default="0")

    created_at = Column(DateTime, server_default=func.now(), index=True)
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())


class ProjectUsageEvent(Base):
    __tablename__ = "project_usage_events"

    id = Column(Integer, primary_key=True, index=True)

    event_id = Column(String(50), unique=True, index=True)
    project_id = Column(String(50), index=True)
    event_type = Column(String(100), index=True)
    quantity = Column(Integer, default=1, server_default="1")
    metadata_json = Column(JSON, nullable=True)

    created_at = Column(DateTime, server_default=func.now(), index=True)


class IncidentFeedback(Base):
    __tablename__ = "incident_feedback"

    id = Column(Integer, primary_key=True, index=True)

    feedback_id = Column(String(50), unique=True, index=True)
    project_id = Column(String(50), nullable=True, index=True)
    incident_id = Column(String(80), index=True)
    prediction_id = Column(String(80), nullable=True, index=True)

    label = Column(String(50), index=True)
    confidence = Column(Float, nullable=True)
    reviewer = Column(String(150), nullable=True)
    note = Column(Text, nullable=True)
    source = Column(String(50), default="manual", server_default="manual", index=True)

    created_at = Column(DateTime, server_default=func.now(), index=True)
    updated_at = Column(DateTime, nullable=True, onupdate=func.now())


class RetrainingJob(Base):
    __tablename__ = "retraining_jobs"

    id = Column(Integer, primary_key=True, index=True)

    job_id = Column(String(50), unique=True, index=True)
    project_id = Column(String(50), nullable=True, index=True)
    scope = Column(String(50), default="global", server_default="global", index=True)
    status = Column(String(50), default="pending", server_default="pending", index=True)
    mode = Column(String(50), default="dataset_only", server_default="dataset_only", index=True)
    requested_by = Column(String(150), nullable=True)
    actual_training_requested = Column(Boolean, default=False, server_default="false")
    actual_training_executed = Column(Boolean, default=False, server_default="false")
    active_model_replaced = Column(Boolean, default=False, server_default="false")

    feedback_count = Column(Integer, default=0, server_default="0")
    dataset_size = Column(Integer, default=0, server_default="0")
    parameters_json = Column(Text, nullable=True)
    metrics_json = Column(Text, nullable=True)
    output_dataset_path = Column(Text, nullable=True)
    output_artifact_path = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)

    created_at = Column(DateTime, server_default=func.now(), index=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)


class ModelVersion(Base):
    __tablename__ = "model_versions"

    id = Column(Integer, primary_key=True, index=True)

    model_version_id = Column(String(50), unique=True, index=True)
    project_id = Column(String(50), nullable=True, index=True)
    scope = Column(String(50), default="global", server_default="global", index=True)
    model_name = Column(
        String(150),
        default="sequence_transformer",
        server_default="sequence_transformer",
        index=True,
    )
    version_tag = Column(String(150), index=True)
    status = Column(String(50), default="candidate", server_default="candidate", index=True)
    is_default = Column(Boolean, default=False, server_default="false", index=True)
    source_job_id = Column(String(50), nullable=True, index=True)
    artifact_path = Column(Text, nullable=True)
    metrics_json = Column(Text, nullable=True)
    activated_by = Column(String(150), nullable=True)
    activation_note = Column(Text, nullable=True)

    created_at = Column(DateTime, server_default=func.now(), index=True)
    activated_at = Column(DateTime, nullable=True)
    archived_at = Column(DateTime, nullable=True)
