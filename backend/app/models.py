from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
from .database import Base


class NormalizedEvent(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, index=True, nullable=False)
    source = Column(String(100), index=True, nullable=False)
    event_type = Column(String(100), index=True, nullable=False)
    user = Column(String(255), index=True, nullable=True)
    source_ip = Column(String(64), index=True, nullable=True)
    country = Column(String(100), nullable=True)
    host = Column(String(255), index=True, nullable=True)
    action = Column(String(255), nullable=True)
    status = Column(String(50), index=True, nullable=True)
    raw_event_id = Column(String(255), nullable=True)
    raw_event = Column(Text, nullable=False)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), index=True, nullable=False)
    severity = Column(String(50), index=True, nullable=False)
    risk_score = Column(Integer, nullable=False)
    user = Column(String(255), index=True, nullable=True)
    source_ip = Column(String(64), index=True, nullable=True)
    host = Column(String(255), index=True, nullable=True)
    status = Column(String(50), index=True, default="Open")
    mitre_tactic = Column(String(255), nullable=True)
    mitre_technique = Column(String(255), nullable=True)
    description = Column(Text, nullable=False)
    ai_summary = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    evidence = relationship("IncidentEvidence", back_populates="alert", cascade="all, delete-orphan")


class IncidentEvidence(Base):
    __tablename__ = "incident_evidence"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"), index=True, nullable=False)
    event_id = Column(Integer, ForeignKey("events.id"), index=True, nullable=False)
    evidence_type = Column(String(100), nullable=False)

    alert = relationship("Alert", back_populates="evidence")
    event = relationship("NormalizedEvent")
