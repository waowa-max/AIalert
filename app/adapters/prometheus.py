from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.adapters.base import BaseAdapter, NormalizedIngestEvent
from app.core.models import AlertStatus, Severity

logger = logging.getLogger(__name__)


def _parse_rfc3339(value: Any) -> datetime:
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


def _severity_from_prom(labels: Dict[str, Any]) -> Severity:
    v = str(labels.get("severity") or labels.get("level") or "").lower()
    mapping = {
        "critical": Severity.P0,
        "p0": Severity.P0,
        "high": Severity.P1,
        "p1": Severity.P1,
        "warning": Severity.P2,
        "warn": Severity.P2,
        "p2": Severity.P2,
        "info": Severity.P3,
        "p3": Severity.P3,
    }
    return mapping.get(v, Severity.P2)


def _status_from_prom(value: Any) -> AlertStatus:
    s = str(value or "").lower()
    return AlertStatus.FIRING if s == "firing" else AlertStatus.RESOLVED


class PrometheusAlertmanagerAdapter(BaseAdapter):
    name = "Prometheus"

    def can_handle(self, source: str, payload: Dict[str, Any]) -> bool:
        if source.lower() in {"prometheus", "alertmanager", "prometheus_alertmanager", "prometheus-alertmanager"}:
            return True
        return isinstance(payload.get("alerts"), list) and ("groupLabels" in payload or "commonLabels" in payload)

    def parse(self, payload: Dict[str, Any]) -> List[NormalizedIngestEvent]:
        alerts = payload.get("alerts")
        if not isinstance(alerts, list):
            return []

        out: List[NormalizedIngestEvent] = []
        for idx, item in enumerate(alerts):
            try:
                if not isinstance(item, dict):
                    continue
                labels = item.get("labels") if isinstance(item.get("labels"), dict) else {}
                annotations = item.get("annotations") if isinstance(item.get("annotations"), dict) else {}

                alertname = str(labels.get("alertname") or "unknown_alert")
                service = str(labels.get("service") or labels.get("app") or labels.get("job") or "unknown_service")
                metric_name = alertname
                instance = str(labels.get("instance") or labels.get("pod") or labels.get("node") or "unknown_instance")

                summary = str(annotations.get("summary") or annotations.get("message") or "")
                description = str(annotations.get("description") or "")
                title = summary or f"{service} - {alertname}"

                starts_at = _parse_rfc3339(item.get("startsAt"))
                ends_at_raw = item.get("endsAt")
                ends_at = _parse_rfc3339(ends_at_raw) if ends_at_raw else None

                source_event_id = str(item.get("fingerprint") or "")
                if not source_event_id:
                    source_event_id = f"am-hash-{_stable_hash({'labels': labels, 'startsAt': item.get('startsAt')})[:16]}"

                out.append(
                    NormalizedIngestEvent(
                        source="Prometheus",
                        source_event_id=source_event_id,
                        title=title,
                        service=service,
                        metric_name=metric_name,
                        severity=_severity_from_prom(labels),
                        status=_status_from_prom(item.get("status")),
                        instance=instance,
                        labels=dict(labels),
                        annotations={"summary": summary, "description": description, **dict(annotations)},
                        starts_at=starts_at,
                        ends_at=ends_at,
                        raw_payload=payload,
                    )
                )
            except Exception as e:
                logger.warning("skip prometheus alert item idx=%s due to parse error: %s", idx, e)
        return out
