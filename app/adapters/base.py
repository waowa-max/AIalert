from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

from app.core.models import AlertStatus, Severity


@dataclass(frozen=True)
class NormalizedIngestEvent:
    source: str
    source_event_id: str
    title: str
    service: str
    metric_name: str
    severity: Severity
    status: AlertStatus
    instance: str
    labels: Dict[str, Any]
    annotations: Dict[str, Any]
    starts_at: datetime
    ends_at: Optional[datetime]
    raw_payload: Dict[str, Any]


class BaseAdapter(ABC):
    name: str

    @abstractmethod
    def can_handle(self, source: str, payload: Dict[str, Any]) -> bool:
        raise NotImplementedError

    @abstractmethod
    def parse(self, payload: Dict[str, Any]) -> List[NormalizedIngestEvent]:
        raise NotImplementedError
