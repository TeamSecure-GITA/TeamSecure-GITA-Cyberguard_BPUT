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

class OtpVerificationRequest(BaseModel):
    challenge_id: str
    otp: str

class PasskeyCredentialRequest(BaseModel):
    challenge_id: str
    credential: Dict[str, Any]

class AccessRequestCreate(BaseModel):
    email: str
    name: str = ""
    purpose: str = ""

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

class PermissionRequest(BaseModel):
    permission: str

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

class ScannerRequest(BaseModel):
    payload: str
    indicator_type: Optional[str] = None

class ThreatPhysicsRequest(BaseModel):
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

class DeceptionRequest(BaseModel):
    message: str
    replies: List[str] = []

class TopologyMorphRequest(BaseModel):
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    trigger: str = "reconnaissance"

class AgentConsensusRequest(BaseModel):
    telemetry: List[Dict[str, Any]] = []
    
class AnalystLoadRequest(BaseModel):
    telemetry: Dict[str, Any] = {}

class QStateRequest(BaseModel):
    telemetry: Dict[str, Any] = {}

class SatelliteRequest(BaseModel):
    telemetry: Dict[str, Any] = {}

class CognitiveEchoRequest(BaseModel):
    query: str

class NeuromorphicRequest(BaseModel):
    telemetry: Dict[str, Any] = {}

class AdvancedTelemetryRequest(BaseModel):
    telemetry: Dict[str, Any] = {}

class QuantumDecoyRequest(BaseModel):
    probe: str = "unknown"
    tool: str = "unclassified"

class TemporalHealingRequest(BaseModel):
    state: Dict[str, Any] = {}

class PolymorphismRequest(BaseModel):
    binary: Dict[str, Any] = {}

class InfrastructureEchoRequest(BaseModel):
    query: str

class DarkMeshRequest(BaseModel):
    nodes: List[str] = []
    epoch: int = 1

class VaccineRequest(BaseModel):
    indicators: List[str] = []

class SpeculativeTelemetryRequest(BaseModel):
    telemetry: Dict[str, Any] = {}

# New Response Models for Threat Intelligence & Engines
class DNAVectors(BaseModel):
    initial_access: str
    techniques: List[str] = []
    ioc_types: List[str] = []
    signals: int = 0

class DNAGenome(BaseModel):
    fingerprint: str
    hash: str
    vectors: DNAVectors
    similarity_score: int

class DNAResponse(BaseModel):
    incident_id: int
    genome: DNAGenome

class CorrelationMatch(BaseModel):
    incident_id: int
    score: int
    reason: str

class CorrelationResponse(BaseModel):
    campaign_id: str
    confidence: int
    related_incidents: List[CorrelationMatch]
    stage: str

class TimelineEvent(BaseModel):
    id: str
    timestamp: str
    label: str
    detail: str
    status: str

class AttackChainResponse(BaseModel):
    incident_id: int
    events: List[TimelineEvent]

class ForecastPoint(BaseModel):
    step: int
    label: str
    risk: int
    confidence: int

class ForecastResponse(BaseModel):
    baseline: int
    trend: str
    forecast: List[ForecastPoint]
    drivers: List[str]

class ActionImpact(BaseModel):
    id: str
    label: str
    reduction: int

class SimulationResponse(BaseModel):
    actions: List[ActionImpact]
    current_risk: int
    projected_risk: int
    risk_reduction: int
    outcome: str
