import hashlib
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from app.core.models import NormalizedAlert, IncidentGroup, Severity

# 告警指纹生成工具
class FingerprintGenerator:
    @staticmethod
    def generate(alert: NormalizedAlert) -> str:
        # 指纹策略（MVP）：
        # - 目标：把“同一类问题”的大量告警聚合到同一个 fingerprint
        # - 降维：Pod/Host 级别的告警映射到 Service 级别，避免 50 个 Pod 变成 50 个聚合组
        # - 当前指纹包含 severity：P0/P1 会分到不同组（你们后续可按需求调整）
        service = alert.resource.get("service") or alert.resource.get("app") or "unknown_service"
        metric = alert.metric_name
        severity = alert.severity
        
        fingerprint_data = {
            "service": service,
            "metric": metric,
            "severity": severity,
            # env 作为指纹的一部分：prod 与 pre/prod-test 不应混合聚合
            "env": alert.labels.get("env", "prod")
        }
        
        # 对指纹数据进行哈希
        fp_str = json.dumps(fingerprint_data, sort_keys=True)
        return hashlib.md5(fp_str.encode()).hexdigest()

# 聚合引擎
class AggregationEngine:
    def __init__(self, window_seconds: int = 300):
        self.window_seconds = window_seconds
        # 内存中维护当前活跃的聚合实例: {fingerprint: IncidentGroup}
        self.active_incidents: Dict[str, IncidentGroup] = {}
        self.fp_generator = FingerprintGenerator()

    def process(self, alert: NormalizedAlert) -> IncidentGroup:
        # 1) 生成指纹：决定该告警属于哪个聚合组
        fp = self.fp_generator.generate(alert)
        alert.fingerprint = fp
        
        # 2) 窗口合并：
        # - 在 window_seconds 内：合并到同一个 incident_group
        # - 超过 window_seconds（Quiet Period）：开启新的 incident_group
        now = datetime.now()
        incident = self.active_incidents.get(fp)
        
        if incident:
            # 窗口过期判断：最后一次事件距离现在超过 window_seconds
            if now - incident.last_seen_at > timedelta(seconds=self.window_seconds):
                # 过期：开启新聚合实例
                incident = self._create_new_incident(alert, fp)
            else:
                # 仍在窗口期：合并事件计数，并刷新 last_seen_at
                incident.event_count += 1
                incident.last_seen_at = now
                # MVP：直接把事件追加到列表（生产建议只存摘要/截断，避免内存膨胀）
                incident.alert_events.append(alert)
        else:
            # 没有活跃实例：新建聚合实例
            incident = self._create_new_incident(alert, fp)
            
        self.active_incidents[fp] = incident
        return incident

    def _create_new_incident(self, alert: NormalizedAlert, fp: str) -> IncidentGroup:
        # 生成聚合实例 ID：INC-{fingerprint前8位}-{当前时间戳}
        service = alert.resource.get("service") or alert.resource.get("app") or "unknown_service"
        return IncidentGroup(
            group_id=f"INC-{fp[:8]}-{int(datetime.now().timestamp())}",
            fingerprint=fp,
            title=f"[{alert.severity}] {service} - {alert.metric_name}",
            severity=alert.severity,
            status="open",
            first_seen_at=datetime.now(),
            last_seen_at=datetime.now(),
            event_count=1,
            alert_events=[alert]
        )
