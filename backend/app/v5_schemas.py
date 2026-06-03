from typing import Optional

from pydantic import BaseModel, Field


class V5AnalyzeEntityAsyncRequest(BaseModel):
    entity_type: str = Field(default="ip")
    entity_id: str = Field(..., min_length=1)
    window_size: int = Field(default=20, ge=1)
    source: Optional[str] = None
    group_by: str = Field(default="ip")


class V5IncidentActionRequest(BaseModel):
    actor: Optional[str] = Field(default=None, max_length=100)
    note: Optional[str] = None


class V5ResolveIncidentRequest(BaseModel):
    actor: Optional[str] = Field(default=None, max_length=100)
    resolution_note: Optional[str] = None
