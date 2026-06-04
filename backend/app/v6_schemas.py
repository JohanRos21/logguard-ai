from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class V6ProjectCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=150)
    slug: str = Field(..., min_length=1, max_length=150)
    description: Optional[str] = None
    plan: str = Field(default="free")


class V6ProjectUpdateRequest(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=150)
    slug: Optional[str] = Field(default=None, min_length=1, max_length=150)
    description: Optional[str] = None
    status: Optional[str] = None
    plan: Optional[str] = None


class V6ProjectResponse(BaseModel):
    id: int
    project_id: str
    name: str
    slug: str
    description: Optional[str] = None
    status: str
    plan: str
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    last_used_at: Optional[str] = None


class V6ProjectApiKeyCreateRequest(BaseModel):
    name: Optional[str] = Field(default=None, max_length=150)


class V6ProjectApiKeyResponse(BaseModel):
    id: int
    key_id: str
    project_id: str
    name: Optional[str] = None
    key_prefix: str
    key_last4: str
    status: str
    created_at: Optional[str] = None
    last_used_at: Optional[str] = None
    revoked_at: Optional[str] = None


class V6ProjectApiKeyCreatedResponse(V6ProjectApiKeyResponse):
    api_key: str
    revoked_active_keys: Optional[int] = None


class V6AuthWhoAmIResponse(BaseModel):
    version: str
    auth_type: str
    project_id: Optional[str] = None
    project_status: Optional[str] = None
    plan: Optional[str] = None


class V6ProjectListResponse(BaseModel):
    version: str
    limit: int
    data: List[V6ProjectResponse]


class V6ProjectItemResponse(BaseModel):
    version: str
    data: V6ProjectResponse


class V6ProjectApiKeyListResponse(BaseModel):
    version: str
    limit: int
    data: List[V6ProjectApiKeyResponse]


class V6ProjectApiKeyItemResponse(BaseModel):
    version: str
    data: Dict[str, Any]


class V6PlanResponse(BaseModel):
    version: str
    data: Dict[str, Dict[str, int]]


class V6UsageSummaryResponse(BaseModel):
    version: str
    data: Dict[str, Any]


class V6UsageDailyResponse(BaseModel):
    version: str
    limit: int
    data: List[Dict[str, Any]]


class V6ProjectPlanUpdateRequest(BaseModel):
    plan: str = Field(...)


class V6IncidentFeedbackCreateRequest(BaseModel):
    label: str = Field(...)
    prediction_id: Optional[str] = None
    project_id: Optional[str] = None
    confidence: Optional[float] = Field(default=None, ge=0, le=1)
    reviewer: Optional[str] = Field(default=None, max_length=150)
    note: Optional[str] = None
    source: str = Field(default="manual")


class V6IncidentFeedbackResponse(BaseModel):
    version: str
    data: Dict[str, Any]


class V6IncidentFeedbackListResponse(BaseModel):
    version: str
    limit: int
    data: List[Dict[str, Any]]


class V6RetrainingJobCreateRequest(BaseModel):
    project_id: Optional[str] = None
    scope: str = Field(default="global")
    mode: str = Field(default="dataset_only")
    actual_training_requested: Optional[bool] = None
    requested_by: Optional[str] = Field(default=None, max_length=150)
    parameters: Dict[str, Any] = Field(default_factory=dict)


class V6RetrainingJobResponse(BaseModel):
    version: str
    data: Dict[str, Any]


class V6RetrainingJobListResponse(BaseModel):
    version: str
    limit: int
    data: List[Dict[str, Any]]


class V6ModelVersionResponse(BaseModel):
    version: str
    limit: Optional[int] = None
    data: Any


class V6ModelVersionActivateResponse(BaseModel):
    version: str
    data: Dict[str, Any]


class V6ModelResolveResponse(BaseModel):
    version: str
    data: Dict[str, Any]


class V6ActiveModelResponse(BaseModel):
    version: str
    data: Dict[str, Any]
