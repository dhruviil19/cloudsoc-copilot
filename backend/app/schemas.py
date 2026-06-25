from datetime import datetime
from typing import Optional, List, Any, Dict
from pydantic import BaseModel


class EventOut(BaseModel):
    id: int
    timestamp: datetime
    source: str
    event_type: str
    user: Optional[str] = None
    source_ip: Optional[str] = None
    country: Optional[str] = None
    host: Optional[str] = None
    action: Optional[str] = None
    status: Optional[str] = None
    raw_event_id: Optional[str] = None

    class Config:
        from_attributes = True


class AlertOut(BaseModel):
    id: int
    title: str
    severity: str
    risk_score: int
    user: Optional[str] = None
    source_ip: Optional[str] = None
    host: Optional[str] = None
    status: str
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    description: str
    ai_summary: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class EvidenceOut(BaseModel):
    evidence_type: str
    event: Dict[str, Any]
