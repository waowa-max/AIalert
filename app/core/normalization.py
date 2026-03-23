from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Dict
from app.core.models import NormalizedAlert, Severity, AlertStatus
import uuid

# 告警标准化适配器接口
class AlertAdapter(ABC):
    # 标准化适配器职责：
    # - 输入：某个告警源的原始 payload（字段名/结构各不相同）
    # - 输出：统一的 NormalizedAlert（标准字段 + resource/labels）
    # 注意：这里的 event_id 仅用于模型完整性；在 Worker 中会用 raw_alert_id 覆盖，做链路追踪/幂等
    @abstractmethod
    def normalize(self, raw_payload: Dict[str, Any]) -> NormalizedAlert:
        pass

# SLS (日志服务) 告警适配器
class SLSAdapter(AlertAdapter):
    def normalize(self, raw_payload: Dict[str, Any]) -> NormalizedAlert:
        # 字段映射说明（示例）：
        # - source_event_id：SLS 的告警唯一 ID（alert_id）
        # - occurred_at：告警触发时间（timestamp 秒级时间戳）
        # - resource：把关键资源维度收敛到统一字典（service/pod/cluster）
        # - metric_name/value：告警规则名/指标值
        # - severity：把源系统的严重度映射到 P0~P3
        # - status：firing/resolved
        severity_map = {
            "critical": Severity.P0,
            "high": Severity.P1,
            "medium": Severity.P2,
            "low": Severity.P3,
        }
        
        return NormalizedAlert(
            event_id=str(uuid.uuid4()),
            source_system="SLS",
            source_event_id=raw_payload.get("alert_id", ""),
            occurred_at=datetime.fromtimestamp(raw_payload.get("timestamp", datetime.now().timestamp())),
            resource={
                "service": raw_payload.get("service", "unknown"),
                "pod": raw_payload.get("pod", "unknown"),
                "cluster": raw_payload.get("cluster", "unknown"),
            },
            metric_name=raw_payload.get("alert_name", "unknown_metric"),
            metric_value=raw_payload.get("value"),
            severity=severity_map.get(raw_payload.get("severity", "medium"), Severity.P2),
            status=AlertStatus.FIRING if raw_payload.get("status") != "resolved" else AlertStatus.RESOLVED,
            labels=raw_payload.get("labels", {}),
            raw_payload=raw_payload
        )

# Sunfire 适配器
class SunfireAdapter(AlertAdapter):
    def normalize(self, raw_payload: Dict[str, Any]) -> NormalizedAlert:
        # 字段映射说明（示例）：
        # - source_event_id：Sunfire 事件 ID（id）
        # - occurred_at：ISO 时间字符串（time）
        # - resource：这里示例取 appName/hostname；生产可按 CMDB 统一映射为 service/cluster 等
        # - metric_name：规则名（ruleName）
        # - severity：S1~S4 映射到 P0~P3
        severity_map = {
            "S1": Severity.P0,
            "S2": Severity.P1,
            "S3": Severity.P2,
            "S4": Severity.P3,
        }
        
        return NormalizedAlert(
            event_id=str(uuid.uuid4()),
            source_system="Sunfire",
            source_event_id=raw_payload.get("id", ""),
            occurred_at=datetime.fromisoformat(raw_payload.get("time", datetime.now().isoformat())),
            resource={
                "app": raw_payload.get("appName", "unknown"),
                "host": raw_payload.get("hostname", "unknown"),
            },
            metric_name=raw_payload.get("ruleName", "unknown_metric"),
            severity=severity_map.get(raw_payload.get("level", "S3"), Severity.P2),
            status=AlertStatus.FIRING,
            raw_payload=raw_payload
        )

# 标准化管理器
class NormalizationManager:
    def __init__(self):
        # 注册不同告警源的适配器（扩展方式：新增 Adapter 并在这里注册）
        self._adapters = {
            "SLS": SLSAdapter(),
            "Sunfire": SunfireAdapter()
        }
    
    def normalize(self, source: str, raw_payload: Dict[str, Any]) -> NormalizedAlert:
        # 根据 source 选择适配器进行标准化
        adapter = self._adapters.get(source)
        if not adapter:
            raise ValueError(f"No adapter found for source system: {source}")
        return adapter.normalize(raw_payload)
