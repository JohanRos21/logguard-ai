from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class V4NormalizationPreviewRequest(BaseModel):
    adapter: str = Field(default="generic_json")
    source: Optional[str] = Field(default=None)
    environment: Optional[str] = Field(default=None)
    payload: Any


class V4NormalizationPreviewResponse(BaseModel):
    success: bool
    adapter_used: str
    normalized_log: Optional[Dict[str, Any]]
    errors: list[str]
    warnings: list[str]


class V4AdaptiveLogRequest(BaseModel):
    adapter: str = Field(default="generic_json")
    source: Optional[str] = Field(default=None)
    environment: Optional[str] = Field(default=None)
    payload: Any


class V4AdaptiveBatchRequest(BaseModel):
    adapter: str = Field(default="generic_json")
    source: Optional[str] = Field(default=None)
    environment: Optional[str] = Field(default=None)
    logs: List[Any] = Field(..., min_items=1, max_items=500)


class V4AdaptiveLogResponse(BaseModel):
    version: str
    status: str
    adapter_used: str
    normalized_log: Dict[str, Any]
    ingestion_result: Dict[str, Any]


class V4AdaptiveBatchResponse(BaseModel):
    version: str
    status: str
    total_received: int
    total_normalized: int
    total_failed: int
    ingestion_result: Optional[Dict[str, Any]]
    errors: List[Dict[str, Any]]
