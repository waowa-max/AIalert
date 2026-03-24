from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.adapters.base import BaseAdapter, NormalizedIngestEvent
from app.core.models import AlertStatus, Severity


def _utc_from_timestamp(value: Any) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    try:
        if isinstance(value, str) and ("T" in value or "-" in value):
            s = value
            if s.endswith("Z"):
                s = s[:-1] + "+00:00"
            return datetime.fromisoformat(s)
        ts = float(value)
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    except Exception:
        return datetime.now(timezone.utc)


def _severity_from_sls(value: Any) -> Severity:
    s = str(value or "").lower()
    mapping = {
        "critical": Severity.P0,
        "p0": Severity.P0,
        "s1": Severity.P0,
        "high": Severity.P1,
        "p1": Severity.P1,
        "s2": Severity.P1,
        "medium": Severity.P2,
        "warning": Severity.P2,
        "warn": Severity.P2,
        "p2": Severity.P2,
        "s3": Severity.P2,
        "low": Severity.P3,
        "info": Severity.P3,
        "p3": Severity.P3,
        "s4": Severity.P3,
    }
    return mapping.get(s, Severity.P2)


def _status_from_sls(value: Any) -> AlertStatus:
    s = str(value or "").lower()
    return AlertStatus.RESOLVED if s == "resolved" else AlertStatus.FIRING


def _stable_hash(payload: Dict[str, Any]) -> str:
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class SlsAdapter(BaseAdapter):
    name = "SLS"

    def can_handle(self, source: str, payload: Dict[str, Any]) -> bool:
        if source.upper() == "SLS":
            return True
        keys = set(payload.keys())
        return (
            {"alert_id", "alert_name"} <= keys
            or {"alertId", "alertName"} <= keys
            or "sls" in source.lower()
        )

    def parse(self, payload: Dict[str, Any]) -> List[NormalizedIngestEvent]:
        source_event_id = str(payload.get("alert_id") or payload.get("alertId") or payload.get("event_id") or payload.get("eventId") or "")
        if not source_event_id:
            source_event_id = f"sls-hash-{_stable_hash(payload)[:16]}"

        alert_name = str(payload.get("alert_name") or payload.get("alertName") or payload.get("rule_name") or payload.get("ruleName") or "unknown_alert")
        service = str(payload.get("service") or payload.get("app") or payload.get("appName") or "unknown_service")
        metric_name = str(payload.get("metric_name") or alert_name)
        instance = str(payload.get("instance") or payload.get("pod") or payload.get("host") or "unknown_instance")

        starts_at = _utc_from_timestamp(payload.get("timestamp") or payload.get("starts_at") or payload.get("startsAt") or payload.get("time"))
        ends_at_raw = payload.get("ends_at") or payload.get("endsAt")
        ends_at = _utc_from_timestamp(ends_at_raw) if ends_at_raw else None

        title = str(payload.get("title") or f"{service} - {alert_name}")

        labels = payload.get("labels") if isinstance(payload.get("labels"), dict) else {}
        annotations = payload.get("annotations") if isinstance(payload.get("annotations"), dict) else {}

        return [
            NormalizedIngestEvent(
                source="SLS",
                source_event_id=source_event_id,
                title=title,
                service=service,
                metric_name=metric_name,
                severity=_severity_from_sls(payload.get("severity")),
                status=_status_from_sls(payload.get("status")),
                instance=instance,
                labels=dict(labels),
                annotations=dict(annotations),
                starts_at=starts_at,
                ends_at=ends_at,
                raw_payload=payload,
            )
        ]
