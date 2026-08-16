from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4
from datetime import datetime

from pydantic import BaseModel, Field, HttpUrl, confloat, constr, field_validator

# ======================
# Enums
# ======================

class EngineType(str, Enum):
    BOLA = "bola"
    SUBDOMAIN_TAKEOVER = "subdomain_takeover"
    REFLECTED_XSS = "reflected_xss"

class JobStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class Severity(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

# ======================
# Identity Pair (for BOLA)
# ======================

class IdentityPair(BaseModel):
    """Two authenticated identities used for object-level authorization testing."""
    low_privilege_token: constr(min_length=10, max_length=4096)
    high_privilege_token: constr(min_length=10, max_length=4096)
    low_privilege_user_id: Optional[str] = None
    high_privilege_user_id: Optional[str] = None

    @field_validator("low_privilege_token", "high_privilege_token")
    @classmethod
    def no_whitespace(cls, v: str) -> str:
        if v.strip() != v:
            raise ValueError("Token must not contain leading/trailing whitespace")
        return v

# ======================
# CVSS v3.1
# ======================

class CVSSVector(BaseModel):
    """Minimal CVSS v3.1 Base metrics."""
    attack_vector: str = Field(..., pattern="^(N|A|L|P)$")
    attack_complexity: str = Field(..., pattern="^(L|H)$")
    privileges_required: str = Field(..., pattern="^(N|L|H)$")
    user_interaction: str = Field(..., pattern="^(N|R)$")
    scope: str = Field(..., pattern="^(U|C)$")
    confidentiality: str = Field(..., pattern="^(N|L|H)$")
    integrity: str = Field(..., pattern="^(N|L|H)$")
    availability: str = Field(..., pattern="^(N|L|H)$")

    score: confloat(ge=0.0, le=10.0)
    severity: Severity

# ======================
# Finding
# ======================

class Finding(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    engine: EngineType
    title: constr(min_length=5, max_length=200)
    description: constr(min_length=10, max_length=4000)
    severity: Severity
    cvss: Optional[CVSSVector] = None
    evidence: Dict[str, Any] = Field(default_factory=dict)
    remediation: Optional[str] = None
    affected_url: Optional[HttpUrl] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)

# ======================
# Job
# ======================

class JobCreate(BaseModel):
    """Incoming request to start a scan. Strictly validated."""
    engine: EngineType
    target: HttpUrl
    additional_targets: List[HttpUrl] = Field(default_factory=list, max_length=50)
    identity_pair: Optional[IdentityPair] = None
    options: Dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: confloat(ge=30, le=3600) = 300

    @field_validator("identity_pair")
    @classmethod
    def bola_requires_identity(cls, v, info):
        if info.data.get("engine") == EngineType.BOLA and v is None:
            raise ValueError("identity_pair is mandatory for BOLA engine")
        return v

class Job(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    engine: EngineType
    status: JobStatus = JobStatus.PENDING
    target: HttpUrl
    additional_targets: List[HttpUrl] = Field(default_factory=list)
    identity_pair: Optional[IdentityPair] = None
    options: Dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: float
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    error_message: Optional[str] = None
    findings: List[Finding] = Field(default_factory=list)

# ======================
# Progress & Engine Result
# ======================

class ProgressEvent(BaseModel):
    job_id: UUID
    percentage: confloat(ge=0.0, le=100.0)
    message: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class EngineResult(BaseModel):
    job_id: UUID
    success: bool
    findings: List[Finding]
    error: Optional[str] = None
    duration_seconds: float