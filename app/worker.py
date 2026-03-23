import os
import time
from datetime import datetime, timezone
from typing import Any, Dict
 
from app.core.normalization import NormalizationManager
from app.core.aggregation import FingerprintGenerator
from app.core.rules import prescreen_drop_reason, silence_candidate
from app.core.storage import Storage
from app.core.ai import build_incident_request, analyze_incident
from app.core.message_bus import MessageBus
from app.infra.inmemory_bus import InMemoryBus
from app.infra.redis_stream_bus import RedisStreamBus
 
# Worker 进程说明：
# - relay_outbox：把 SQLite raw_alert 表中待投递记录写入消息总线（先落库后入队）
# - process_raw_stream：消费 raw_alerts，完成标准化/规则预筛/静默/聚合，产出 incident_events
# - process_incident_stream：消费 incident_events，执行“幂等开单 + 通知”（目前打印模拟）

 
RAW_STREAM = os.environ.get("AIALERT_RAW_STREAM", "raw_alerts")
INCIDENT_STREAM = os.environ.get("AIALERT_INCIDENT_STREAM", "incident_events")
RAW_GROUP = os.environ.get("AIALERT_RAW_GROUP", "normalizer")
INCIDENT_GROUP = os.environ.get("AIALERT_INCIDENT_GROUP", "notifier")
CONSUMER_NAME = os.environ.get("AIALERT_CONSUMER", f"c-{os.getpid()}")
DB_PATH = os.environ.get("AIALERT_DB_PATH", os.path.join("data", "aialert.db"))
AGG_WINDOW_SECONDS = int(os.environ.get("AIALERT_AGG_WINDOW_SECONDS", "300"))
OUTBOX_BATCH = int(os.environ.get("AIALERT_OUTBOX_BATCH", "200"))
BUS_READ_COUNT = int(os.environ.get("AIALERT_BUS_READ_COUNT", "50"))
BUS_BLOCK_MS = int(os.environ.get("AIALERT_BUS_BLOCK_MS", "2000"))
 
 
def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
 
 
def _incident_title(severity: str, service: str, metric_name: str) -> str:
    return f"[{severity}] {service} - {metric_name}"
 
 
def relay_outbox(storage: Storage, bus: MessageBus) -> int:
    # Outbox 扫描：只要 raw_alert.enqueued=0，就投递到 RAW_STREAM
    # 这样即便瞬时流量很大，接入层只要能写入 SQLite，就不会丢数据
    pending = storage.list_pending_raw_alerts(limit=OUTBOX_BATCH)
    if not pending:
        return 0
    n = 0
    for row in pending:
        msg_id = bus.publish(
            RAW_STREAM,
            {"raw_alert_id": row.id, "source_system": row.source_system},
        )
        storage.mark_raw_alert_enqueued(raw_alert_id=row.id, stream=RAW_STREAM, msg_id=msg_id)
        n += 1
    return n
 
 
def process_raw_stream(storage: Storage, bus: MessageBus, normalizer: NormalizationManager) -> int:
    # 标准化消费者：从 RAW_STREAM 读取 raw_alert_id，拉取 raw payload 后做后续处理
    msgs = bus.read_group(
        stream=RAW_STREAM,
        group=RAW_GROUP,
        consumer=CONSUMER_NAME,
        count=BUS_READ_COUNT,
        block_ms=BUS_BLOCK_MS,
    )
    if not msgs:
        return 0
 
    n = 0
    for msg_id, fields in msgs:
        raw_alert_id = fields.get("raw_alert_id")
        if not raw_alert_id:
            bus.ack(RAW_STREAM, RAW_GROUP, msg_id)
            continue
        raw = storage.get_raw_alert(raw_alert_id)
        if not raw:
            bus.ack(RAW_STREAM, RAW_GROUP, msg_id)
            continue
 
        try:
            # 1) 标准化
            alert = normalizer.normalize(raw.source_system, raw.payload)
            # 这里把 event_id 固定为 raw_alert_id，便于链路追踪和幂等
            alert.event_id = raw.id
            # 2) 指纹：用于聚合（service + metric + env 等）
            fp = FingerprintGenerator.generate(alert)
            alert.fingerprint = fp
            severity_val = getattr(alert.severity, "value", str(alert.severity))
            status_val = getattr(alert.status, "value", str(alert.status))
 
            service = alert.resource.get("service") or alert.resource.get("app") or "unknown_service"
            now_iso = _utc_now_iso()
 
            # 3) 规则预筛：快速丢弃明显噪音（示例：非 prod）
            drop_reason = prescreen_drop_reason(alert)
            silenced = False
            silence_rule_id = None
            if not drop_reason:
                # 4) 静默：命中规则则后续不做开单/通知
                silence_rule_id = storage.match_silence_rule(silence_candidate(alert))
                silenced = silence_rule_id is not None
 
            # 5) 标准化事件落库（raw_alert_id UNIQUE，避免重复处理）
            inserted = storage.insert_normalized_event(
                event_id=alert.event_id,
                raw_alert_id=raw.id,
                occurred_at=alert.occurred_at.astimezone(timezone.utc).isoformat(),
                service=service,
                metric_name=alert.metric_name,
                severity=severity_val,
                status=status_val,
                fingerprint=fp,
                labels=alert.labels or {},
                resource=alert.resource or {},
                dropped=bool(drop_reason),
                drop_reason=drop_reason,
                silenced=silenced,
                silence_rule_id=silence_rule_id,
            )
 
            if inserted and not drop_reason:
                # 6) 聚合：窗口内同 fingerprint 合并为 incident_group
                incident, is_new = storage.upsert_incident(
                    fingerprint=fp,
                    title=_incident_title(severity_val, service, alert.metric_name),
                    severity=severity_val,
                    now_iso=now_iso,
                    window_seconds=AGG_WINDOW_SECONDS,
                )
                # 7) 产出 incident 事件：交给后续开单/通知消费者
                bus.publish(
                    INCIDENT_STREAM,
                    {
                        "group_id": incident.group_id,
                        "severity": severity_val,
                        "is_new": "1" if is_new else "0",
                        "silenced": "1" if silenced else "0",
                    },
                )
        finally:
            # ack 放在 finally，避免异常导致消息重复堆积
            bus.ack(RAW_STREAM, RAW_GROUP, msg_id)
            n += 1
 
    return n
 
 
def process_incident_stream(storage: Storage, bus: MessageBus) -> int:
    # 通知消费者：从 INCIDENT_STREAM 读取 group_id，按策略开单/通知
    msgs = bus.read_group(
        stream=INCIDENT_STREAM,
        group=INCIDENT_GROUP,
        consumer=CONSUMER_NAME,
        count=BUS_READ_COUNT,
        block_ms=BUS_BLOCK_MS,
    )
    if not msgs:
        return 0
 
    n = 0
    for msg_id, fields in msgs:
        group_id = fields.get("group_id")
        silenced = fields.get("silenced") == "1"
        severity = fields.get("severity") or "P2"
        if group_id:
            incident = storage.get_incident(group_id)
            ai_decision = None
            ai_status = None
            ai_error = None
            ai_latency_ms = None

            should_analyze = bool(fields.get("is_new") == "1")
            if incident and (incident.event_count % 5 == 0):
                should_analyze = True

            if incident and (not silenced) and should_analyze:
                req = build_incident_request(
                    incident=incident.__dict__,
                    recent_events=storage.list_recent_events_for_group(group_id, limit=20),
                )
                decision, raw_resp, status, error, latency_ms = analyze_incident(req)
                ai_decision = decision
                ai_status = status
                ai_error = error
                ai_latency_ms = latency_ms
                storage.insert_ai_analysis_result(
                    group_id=group_id,
                    model=os.environ.get("AIALERT_LLM_MODEL", "mock"),
                    status=status,
                    request=req,
                    response=raw_resp,
                    is_valid_alert=decision.is_valid_alert,
                    predicted_severity=decision.severity,
                    confidence=decision.confidence,
                    reason=decision.reason,
                    suggested_action=decision.suggested_action,
                    error=error,
                    latency_ms=latency_ms,
                )

            effective_severity = severity
            is_valid_alert = True
            if ai_decision and ai_status == "success":
                effective_severity = ai_decision.severity
                is_valid_alert = ai_decision.is_valid_alert

            if ai_decision and ai_status == "success" and not is_valid_alert:
                payload = {
                    "incident_id": group_id,
                    "severity": effective_severity,
                    "title": incident.title if incident else None,
                    "event_count": incident.event_count if incident else None,
                    "suppressed_by": "ai",
                    "ai_reason": ai_decision.reason,
                    "ai_suggested_action": ai_decision.suggested_action,
                }
                record_id = storage.insert_notify_record(
                    group_id=group_id,
                    ticket_id=None,
                    channel="stdout",
                    status="ai_suppressed",
                    payload=payload,
                )
                storage.insert_operation_log(
                    entity_type="notify_record",
                    entity_id=record_id,
                    action="ai_suppress",
                    actor_type="system",
                    actor_id=None,
                    detail=payload,
                )
                bus.ack(INCIDENT_STREAM, INCIDENT_GROUP, msg_id)
                n += 1
                continue

            if effective_severity in {"P0", "P1"}:
                if silenced:
                    payload = {
                        "incident_id": group_id,
                        "severity": effective_severity,
                        "title": incident.title if incident else None,
                        "event_count": incident.event_count if incident else None,
                        "silenced": True,
                    }
                    record_id = storage.insert_notify_record(
                        group_id=group_id,
                        ticket_id=None,
                        channel="stdout",
                        status="suppressed",
                        payload=payload,
                    )
                    storage.insert_operation_log(
                        entity_type="notify_record",
                        entity_id=record_id,
                        action="suppress",
                        actor_type="system",
                        actor_id=None,
                        detail=payload,
                    )
                else:
                    ticket_id, created = storage.create_ticket_if_needed(
                        group_id=group_id, priority=effective_severity
                    )
                    if created:
                        storage.insert_operation_log(
                            entity_type="ticket",
                            entity_id=ticket_id,
                            action="create",
                            actor_type="system",
                            actor_id=None,
                            detail={"group_id": group_id, "priority": effective_severity},
                        )
                    if incident and (
                        created or fields.get("is_new") == "1" or incident.event_count % 5 == 0
                    ):
                        payload = {
                            "title": incident.title,
                            "severity": incident.severity,
                            "incident_id": incident.group_id,
                            "ticket_id": ticket_id,
                            "event_count": incident.event_count,
                            "first_seen": incident.first_seen_at,
                            "last_seen": incident.last_seen_at,
                            "ai": None if not ai_decision else ai_decision.model_dump(),
                            "ai_status": ai_status,
                        }
                        print(payload)
                        record_id = storage.insert_notify_record(
                            group_id=incident.group_id,
                            ticket_id=ticket_id,
                            channel="stdout",
                            status="sent",
                            payload=payload,
                        )
                        storage.insert_operation_log(
                            entity_type="notify_record",
                            entity_id=record_id,
                            action="send",
                            actor_type="system",
                            actor_id=None,
                            detail=payload,
                        )
        bus.ack(INCIDENT_STREAM, INCIDENT_GROUP, msg_id)
        n += 1
    return n
 
 
def main() -> None:
    storage = Storage(DB_PATH)
    # AIALERT_BUS=redis/memory：默认 redis；memory 仅用于本地演示（不跨进程）
    bus_kind = os.environ.get("AIALERT_BUS", "redis").lower()
    bus: MessageBus = InMemoryBus() if bus_kind == "memory" else RedisStreamBus.from_env()
    # Redis Stream 需要先创建 consumer group（Kafka 二期也会有类似的 group 概念）
    bus.ensure_consumer_group(RAW_STREAM, RAW_GROUP)
    bus.ensure_consumer_group(INCIDENT_STREAM, INCIDENT_GROUP)
    normalizer = NormalizationManager()
 
    while True:
        progressed = 0
        progressed += relay_outbox(storage, bus)
        progressed += process_raw_stream(storage, bus, normalizer)
        progressed += process_incident_stream(storage, bus)
        if progressed == 0:
            time.sleep(LOOP_SLEEP_SECONDS)
 
 
if __name__ == "__main__":
    main()
