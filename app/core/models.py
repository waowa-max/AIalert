from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field

# 告警级别枚举
class Severity(str, Enum):
    P0 = "P0"  # 紧急
    P1 = "P1"  # 高
    P2 = "P2"  # 中
    P3 = "P3"  # 低

# 告警状态
class AlertStatus(str, Enum):
    FIRING = "firing"
    RESOLVED = "resolved"

# 标准化告警模型
class NormalizedAlert(BaseModel):
    event_id: str
    source_system: str
    source_event_id: str
    occurred_at: datetime
    ingested_at: datetime = Field(default_factory=datetime.now)
    
    resource: Dict[str, str]  # {service, cluster, pod, host...}
    metric_name: str
    metric_value: Optional[float] = None
    
    severity: Severity
    status: AlertStatus
    
    labels: Dict[str, str] = {}
    raw_payload: Optional[Dict[str, Any]] = None
    
    fingerprint: Optional[str] = None

# 聚合实例模型 (Incident)
class IncidentGroup(BaseModel):
    group_id: str
    fingerprint: str
    title: str
    severity: Severity
    status: str = "open" # open, closed, acknowledged
    
    first_seen_at: datetime
    last_seen_at: datetime
    event_count: int = 1
    
    alert_events: List[NormalizedAlert] = []
    
    ai_analysis: Optional[Dict[str, Any]] = None
    ticket_id: Optional[str] = None

# 工单状态
class TicketStatus(str, Enum):
    NEW = "NEW"
    TRIAGED = "TRIAGED"
    ASSIGNED = "ASSIGNED"
    IN_PROGRESS = "IN_PROGRESS"
    MITIGATED = "MITIGATED"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"

# 工单模型
class Ticket(BaseModel):
    ticket_id: str
    group_id: str
    priority: Severity
    status: TicketStatus
    assignee: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)
