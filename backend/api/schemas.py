from pydantic import BaseModel, Field, validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum

# Enums
class ScanType(str, Enum):
    SUBDOMAIN = "subdomain"
    PORT = "port"
    TECH = "tech"
    VULN = "vuln"
    FULL = "full"

class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class ScheduleType(str, Enum):
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"

class NotificationPriority(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

# Base schemas
class BaseSchema(BaseModel):
    class Config:
        from_attributes = True

# Target schemas
class TargetBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    base_domain: str = Field(..., min_length=1, max_length=200)
    description: Optional[str] = None
    tags: List[str] = []
    scope: Dict[str, Any] = {}
    notes: Optional[str] = None
    is_active: bool = True

class TargetCreate(TargetBase):
    @validator('base_domain')
    def validate_domain(cls, v):
        import validators
        if not validators.domain(v):
            raise ValueError('Invalid domain format')
        return v.lower()

class TargetUpdate(BaseModel):
    name: Optional[str] = None
    base_domain: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[List[str]] = None
    scope: Optional[Dict[str, Any]] = None
    notes: Optional[str] = None
    is_active: Optional[bool] = None

class TargetResponse(TargetBase, BaseSchema):
    id: int
    created_at: datetime
    updated_at: datetime
    subdomain_count: Optional[int] = 0
    vulnerability_count: Optional[int] = 0
    last_scan: Optional[datetime] = None

# Subdomain schemas
class SubdomainBase(BaseModel):
    subdomain: str
    ip_address: Optional[str] = None
    is_active: bool = True

class SubdomainResponse(SubdomainBase, BaseSchema):
    id: int
    target_id: int
    last_seen: datetime
    created_at: datetime
    service_count: Optional[int] = 0
    vulnerability_count: Optional[int] = 0

# Service schemas
class ServiceBase(BaseModel):
    port: int
    protocol: str = "tcp"
    service_name: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    is_active: bool = True

class ServiceResponse(ServiceBase, BaseSchema):
    id: int
    subdomain_id: int
    created_at: datetime
    updated_at: datetime

# Technology Stack schemas
class TechStackBase(BaseModel):
    technology: str
    category: Optional[str] = None
    version: Optional[str] = None
    confidence: Optional[float] = None
    source: Optional[str] = None

class TechStackResponse(TechStackBase, BaseSchema):
    id: int
    subdomain_id: int
    created_at: datetime
    updated_at: datetime

# Vulnerability schemas
class VulnerabilityBase(BaseModel):
    title: str
    severity: SeverityLevel
    confidence: str
    description: Optional[str] = None
    solution: Optional[str] = None
    reference: List[str] = []
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None
    scanner_name: Optional[str] = None
    template_id: Optional[str] = None
    matched_at: Optional[str] = None
    is_verified: bool = False
    is_false_positive: bool = False

class VulnerabilityResponse(VulnerabilityBase, BaseSchema):
    id: int
    subdomain_id: int
    created_at: datetime
    updated_at: datetime

# Scan schemas
class ScanBase(BaseModel):
    scan_type: ScanType
    scan_config: Dict[str, Any] = {}

class ScanCreate(ScanBase):
    target_id: int

class ScanResponse(ScanBase, BaseSchema):
    id: int
    target_id: int
    status: ScanStatus
    results: Dict[str, Any] = {}
    error_message: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime

# Scheduled Scan schemas
class ScheduledScanBase(BaseModel):
    scan_type: ScanType
    schedule_type: ScheduleType
    schedule_config: Dict[str, Any] = {}
    scan_config: Dict[str, Any] = {}
    is_active: bool = True

class ScheduledScanCreate(ScheduledScanBase):
    target_id: int

class ScheduledScanUpdate(BaseModel):
    scan_type: Optional[ScanType] = None
    schedule_type: Optional[ScheduleType] = None
    schedule_config: Optional[Dict[str, Any]] = None
    scan_config: Optional[Dict[str, Any]] = None
    is_active: Optional[bool] = None

class ScheduledScanResponse(ScheduledScanBase, BaseSchema):
    id: int
    target_id: int
    last_run: Optional[datetime] = None
    next_run: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

# CVE Watch schemas
class CVEWatchBase(BaseModel):
    cve_id: str
    description: Optional[str] = None
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    affected_technologies: List[str] = []
    is_active: bool = True

class CVEWatchResponse(CVEWatchBase, BaseSchema):
    id: int
    published_date: Optional[datetime] = None
    modified_date: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime

# Notification schemas
class NotificationBase(BaseModel):
    title: str
    message: str
    notification_type: str
    priority: NotificationPriority
    is_read: bool = False

class NotificationResponse(NotificationBase, BaseSchema):
    id: int
    target_id: Optional[int] = None
    scan_id: Optional[int] = None
    is_sent: bool = False
    sent_via: List[str] = []
    created_at: datetime

# Dashboard schemas
class DashboardStats(BaseModel):
    total_targets: int
    active_targets: int
    total_subdomains: int
    active_subdomains: int
    total_vulnerabilities: int
    critical_vulnerabilities: int
    high_vulnerabilities: int
    running_scans: int
    completed_scans_today: int
    failed_scans_today: int

class VulnerabilitySummary(BaseModel):
    severity: str
    count: int
    percentage: float

class TechnologySummary(BaseModel):
    technology: str
    count: int
    category: str

class RecentActivity(BaseModel):
    type: str
    target_name: str
    message: str
    timestamp: datetime
    severity: Optional[str] = None

class DashboardResponse(BaseModel):
    stats: DashboardStats
    vulnerability_breakdown: List[VulnerabilitySummary]
    top_technologies: List[TechnologySummary]
    recent_activities: List[RecentActivity]

# Search and Filter schemas
class SearchFilters(BaseModel):
    query: Optional[str] = None
    target_ids: Optional[List[int]] = None
    tags: Optional[List[str]] = None
    severity: Optional[List[SeverityLevel]] = None
    technology: Optional[List[str]] = None
    cve_id: Optional[str] = None
    is_verified: Optional[bool] = None
    is_false_positive: Optional[bool] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None

class PaginationParams(BaseModel):
    page: int = Field(1, ge=1)
    per_page: int = Field(20, ge=1, le=100)

class PaginatedResponse(BaseModel):
    items: List[Any]
    total: int
    page: int
    per_page: int
    pages: int
    has_next: bool
    has_prev: bool

# Scan History schemas
class ScanHistoryItem(BaseModel):
    id: int
    scan_type: ScanType
    status: ScanStatus
    target_name: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration: Optional[int] = None  # in seconds
    results_summary: Dict[str, Any] = {}

class ScanHistoryResponse(BaseModel):
    scans: List[ScanHistoryItem]
    total: int
    page: int
    per_page: int

# Export schemas
class ExportFormat(str, Enum):
    JSON = "json"
    CSV = "csv"
    PDF = "pdf"

class ExportRequest(BaseModel):
    format: ExportFormat
    filters: Optional[SearchFilters] = None
    include_fields: Optional[List[str]] = None

# Bulk Operations schemas
class BulkScanRequest(BaseModel):
    target_ids: List[int]
    scan_type: ScanType
    scan_config: Dict[str, Any] = {}

class BulkScanResponse(BaseModel):
    success: bool
    scan_ids: List[int]
    failed_targets: List[int]
    message: str

# User schemas (for authentication)
class UserBase(BaseModel):
    username: str
    email: str
    full_name: Optional[str] = None
    is_active: bool = True
    is_admin: bool = False

class UserCreate(UserBase):
    password: str

class UserResponse(UserBase, BaseSchema):
    id: int
    created_at: datetime
    updated_at: datetime

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

# Error schemas
class ErrorResponse(BaseModel):
    error: str
    message: str
    details: Optional[Dict[str, Any]] = None

class ValidationError(BaseModel):
    field: str
    message: str

class ValidationErrorResponse(BaseModel):
    error: str = "validation_error"
    message: str = "Invalid input data"
    details: List[ValidationError]