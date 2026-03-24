from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.adapters.base import BaseAdapter, NormalizedIngestEvent
from app.core.models import AlertStatus, Severity


def _parse_time(value: Any) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    try:
        s = str(value)
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s)
    except Exception:
        return datetime.now(timezone.utc)


def _stable_hash(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _status_from_grafana(state: Any) -> AlertStatus:
    s = str(state or "").lower()
    if s in {"ok", "normal", "resolved"}:
        return AlertStatus.RESOLVED
    return AlertStatus.FIRING


def _severity_from_grafana(payload: Dict[str, Any], tags: Dict[str, Any]) -> Severity:
    if isinstance(tags, dict):
        v = str(tags.get("severity") or tags.get("level") or "").lower()
    else:
        v = ""
    mapping = {
        "critical": Severity.P0,
        "high": Severity.P1,
        "warning": Severity.P2,
        "info": Severity.P3,
    }
    if v in mapping:
        return mapping[v]
    status = _status_from_grafana(payload.get("state"))
    return Severity.P2 if status == AlertStatus.FIRING else Severity.P3


class GrafanaAlertingAdapter(BaseAdapter):
    name = "Grafana"

    def can_handle(self, source: str, payload: Dict[str, Any]) -> bool:
        if source.lower() in {"grafana", "grafana_alerting"}:
            return True
        keys = set(payload.keys())
        return "ruleName" in keys or "evalMatches" in keys or ("state" in keys and "message" in keys)

    def parse(self, payload: Dict[str, Any]) -> List[NormalizedIngestEvent]:
        title = str(payload.get("title") or payload.get("ruleName") or "grafana_alert")
        rule_name = str(payload.get("ruleName") or payload.get("rule") or title)
        metric_name = rule_name

        tags = payload.get("tags") if isinstance(payload.get("tags"), dict) else {}
        labels = dict(tags)

        annotations: Dict[str, Any] = {}
        if isinstance(payload.get("message"), str):
            annotations["message"] = payload.get("message")
        if isinstance(payload.get("state"), str):
            annotations["state"] = payload.get("state")
        if isinstance(payload.get("evalMatches"), list):
            annotations["evalMatches"] = payload.get("evalMatches")

        service = str(labels.get("service") or labels.get("app") or payload.get("app") or "unknown_service")
        instance = str(labels.get("instance") or labels.get("host") or "unknown_instance")

        starts_at = _parse_time(payload.get("startsAt") or payload.get("starts_at"))
        ends_at_raw = payload.get("endsAt") or payload.get("ends_at")
        ends_at = _parse_time(ends_at_raw) if ends_at_raw else None

        source_event_id = str(payload.get("ruleId") or payload.get("id") or "")
        if not source_event_id:
            source_event_id = f"grafana-hash-{_stable_hash({'rule': rule_name, 'startsAt': payload.get('startsAt'), 'tags': tags})[:16]}"

        return [
            NormalizedIngestEvent(
                source="Grafana",
                source_event_id=source_event_id,
                title=title,
                service=service,
                metric_name=metric_name,
                severity=_severity_from_grafana(payload, tags),
                status=_status_from_grafana(payload.get("state")),
                instance=instance,
                labels=labels,
                annotations=annotations,
                starts_at=starts_at,
                ends_at=ends_at,
                raw_payload=payload,
            )
        ]

