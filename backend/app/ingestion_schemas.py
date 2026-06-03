from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class IngestLogRequest(BaseModel):
    timestamp: Optional[datetime] = None
    source: str = Field(..., min_length=1, max_length=100)
    environment: Optional[str] = Field(default="development", max_length=50)
    event_type: str = Field(..., min_length=1, max_length=100)
    source_severity: Optional[str] = Field(default=None, max_length=50)
    user_id: Optional[str] = Field(default=None, max_length=100)
    role: Optional[str] = Field(default=None, max_length=100)
    ip: str = Field(..., min_length=1, max_length=100)
    method: str = Field(..., min_length=1, max_length=20)
    route: str = Field(..., min_length=1, max_length=255)
    status_code: int = Field(..., ge=100, le=599)
    response_time_ms: float = Field(..., ge=0)
    message: str = Field(..., min_length=1)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class IngestBatchRequest(BaseModel):
    logs: List[IngestLogRequest] = Field(..., min_items=1, max_items=500)


class IngestLogResponse(BaseModel):
    status: str
    id: int
    source_severity: str
    final_severity: str
