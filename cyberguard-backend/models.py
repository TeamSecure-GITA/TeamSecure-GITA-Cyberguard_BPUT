from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any, Literal

class ThreatAnalysisRequest(BaseModel):
    category: Optional[str] = None
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

class ProviderTicketRequest(BaseModel):
    summary: str
    description: str = ""
    urgency: int = 2

class ProviderIdentityDisableRequest(BaseModel):
    identity: str
    confirmed: bool = False

class ProviderEndpointIsolationRequest(BaseModel):
    endpoint_id: str
    confirmed: bool = False

class LoginRequest(BaseModel):
    username: str
    password: str

class GoogleLoginRequest(BaseModel):
    id_token: Optional[str] = None
    email: str
    name: Optional[str] = None
    photo_url: Optional[str] = None

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

class IdentityTrustRequest(BaseModel):
    device: str
    country: str
    source_ip: str
    mfa_enabled: bool
    behavioral_anomaly: bool = False

class InsiderRiskRequest(BaseModel):
    downloads: int = Field(default=0, ge=0, le=100000)
    off_hours: bool = False
    privilege_change: bool = False
    sensitive_access: int = Field(default=0, ge=0, le=100000)

class DeceptionInteractionRequest(BaseModel):
    host: str = Field(min_length=1, max_length=120)
    actor: str = Field(min_length=1, max_length=120)
    resource: str = Field(min_length=1, max_length=200)
    event_type: str = Field(min_length=1, max_length=40)
    source_ip: Optional[str] = None

class PolicyDefinition(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=1000)
    category: str = Field(default="all", min_length=1, max_length=40)
    threshold: int = Field(default=70, ge=0, le=100)
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"] = "HIGH"
    action: Literal["monitor", "require_mfa", "block", "isolate", "open_incident", "contain"] = "require_mfa"
    approval_required: bool = True
    enabled: bool = True

class ContainmentRequestCreate(BaseModel):
    incident_id: int = Field(gt=0)
    action: Literal["monitor", "require_mfa", "revoke_session", "block_ip", "isolate_host", "quarantine_message"]
    target: str = Field(min_length=1, max_length=160)

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
