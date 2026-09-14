from pydantic import BaseModel
from typing import List, Optional, Dict, Any

class ThreatAnalysisRequest(BaseModel):
    category: str
    payload: str
    metadata: Optional[Dict[str, Any]] = None

class RiskIndicator(BaseModel):
    name: str
    score: str

class AssessmentResult(BaseModel):
    risk_score: int
    risk_level: str
    category: str
    xai_explanation: str
    indicators: List[RiskIndicator]
    recommended_actions: List[Dict[str, str]]

class ResponseExecutionRequest(BaseModel):
    incident_id: str
    action_id: str
    target: str

class LoginRequest(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    username: str
    role: str

class AlertRequest(BaseModel):
    incident_id: str
    channel: str
    message: str

class IncidentUpdate(BaseModel):
    status: Optional[str] = None
    assigned_to: Optional[str] = None
    note: Optional[str] = None

class IncidentComment(BaseModel):
    comment: str

class UserCreate(BaseModel):
    username: str
    password: str
    role: str = "analyst"

class NotificationUpdate(BaseModel):
    read: bool = True

class ThreatIntelLookup(BaseModel):
    value: str
    indicator_type: Optional[str] = None

class ForecastRequest(BaseModel):
    horizon: int = 6

class SimulationRequest(BaseModel):
    actions: List[str] = []

class PsychologyRequest(BaseModel):
    payload: str

class BattleRequest(BaseModel):
    defender_actions: List[str] = []