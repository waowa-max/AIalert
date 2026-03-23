import hashlib
import json
import os
import threading
import time
from fastapi import Body, FastAPI, HTTPException, Query
from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional
from app.core.storage import Storage
from app.core.normalization import NormalizationManager
from app.core.aggregation import FingerprintGenerator
from app.core.rules import prescreen_drop_reason, silence_candidate
from app.core.ai import build_incident_request, analyze_incident
from app.core.message_bus import MessageBus
from app.infra.inmemory_bus import InMemoryBus
from app.infra.redis_stream_bus import RedisStreamBus
import uvicorn

openapi_tags = [
    {"name": "Health", "description": "平台自检与联通性验证。"},
    {"name": "Ingest", "description": "多源告警接入（仅保证接收与落库，不代表已聚合/AI/开单）。"},
    {"name": "Rules", "description": "规则预筛与静默策略相关能力。"},
    {"name": "Events", "description": "标准化事件查询（用于验证预筛/静默/幂等）。"},
    {"name": "Groups", "description": "聚合实例查询（Incident/Group）。"},
    {"name": "AI", "description": "AI 分析结果查询与测试场景说明。"},
    {"name": "Tickets", "description": "工单查询（用于验证是否正确开单/未开单）。"},
    {"name": "Notifications", "description": "通知发送/抑制记录查询（用于验收通知链路）。"},
    {"name": "Audit", "description": "最小审计流水查询（关键动作留痕）。"},
]

app = FastAPI(
    title="AIalert 调试控制台（MVP）",
    description=(
        "用于联调/验收/演示的调试控制台。\n\n"
        "推荐测试顺序（建议按以下流程逐步确认链路）：\n"
        "1) GET /health\n"
        "2) POST /ingest/{source}\n"
        "3) GET /events\n"
        "4) GET /groups\n"
        "5) GET /ai_results\n"
        "6) GET /tickets\n"
        "7) GET /notify_records\n"
        "8) GET /operation_logs\n"
    ),
    version="0.1.0",
    openapi_tags=openapi_tags,
)


class HealthResponse(BaseModel):
    status: str


class IngestAcceptedResponse(BaseModel):
    status: str = Field(description="accepted 表示已接收并落库，后续处理为异步进行。")
    raw_alert_id: str = Field(description="原始告警落库 ID（接入不丢的凭证）。")
    idempotency_key: str = Field(description="幂等键，用于判断是否重复投递。")
    duplicated: bool = Field(description="true 表示幂等命中，本次未重复入库。")


class SilenceMatch(BaseModel):
    service: Optional[str] = Field(None, description="服务名", example="order-service")
    metric_name: Optional[str] = Field(None, description="规则/指标名", example="CPU_USAGE_HIGH")
    alert_name: Optional[str] = Field(None, description="告警名", example="CPU_USAGE_HIGH")


class SilenceCreateRequest(BaseModel):
    match: SilenceMatch
    duration_seconds: int = Field(
        description="静默持续秒数。",
        gt=0,
        example=30
    )
# class SilenceCreateRequest(BaseModel):
#     match: Dict[str, Any] = Field(description="静默匹配条件（等值匹配）。")
#     duration_seconds: int = Field(description="静默持续秒数。", gt=0)


class SilenceCreateResponse(BaseModel):
    status: str
    rule_id: str


class ListSilenceResponse(BaseModel):
    items: List[Dict[str, Any]]


class NormalizedEventItem(BaseModel):
    event_id: str
    raw_alert_id: str
    occurred_at: str
    service: str
    metric_name: str
    severity: str
    status: str
    fingerprint: Optional[str] = None
    dropped: bool
    drop_reason: Optional[str] = None
    silenced: bool
    silence_rule_id: Optional[str] = None
    created_at: str


class EventsResponse(BaseModel):
    items: List[NormalizedEventItem]


class GroupItem(BaseModel):
    group_id: str
    fingerprint: str
    title: str
    severity: str
    status: str
    first_seen_at: str
    last_seen_at: str
    event_count: int
    ticket_id: Optional[str] = None


class GroupsResponse(BaseModel):
    items: List[GroupItem]


class TicketItem(BaseModel):
    ticket_id: str
    group_id: str
    priority: str
    status: str
    assignee: Optional[str] = None
    created_at: str
    updated_at: str


class TicketsResponse(BaseModel):
    items: List[TicketItem]


class NotifyRecordItem(BaseModel):
    record_id: str
    group_id: Optional[str] = None
    ticket_id: Optional[str] = None
    channel: str
    status: str
    payload: Dict[str, Any]
    created_at: str


class NotifyRecordsResponse(BaseModel):
    items: List[NotifyRecordItem]


class OperationLogItem(BaseModel):
    op_id: str
    entity_type: str
    entity_id: str
    action: str
    actor_type: str
    actor_id: Optional[str] = None
    detail: Dict[str, Any]
    created_at: str


class OperationLogsResponse(BaseModel):
    items: List[OperationLogItem]


class AiResultItem(BaseModel):
    analysis_id: str
    group_id: str
    model: str
    status: str
    is_valid_alert: Optional[bool] = None
    predicted_severity: Optional[str] = None
    confidence: Optional[float] = None
    reason: Optional[str] = None
    suggested_action: Optional[str] = None
    request: Dict[str, Any]
    response: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    latency_ms: Optional[int] = None
    created_at: str


class AiResultsMeta(BaseModel):
    llm_mode: str
    low_conf_threshold: str


class AiResultsResponse(BaseModel):
    meta: AiResultsMeta
    items: List[AiResultItem]

# 运行模式说明：
# - /ingest 只负责“接收 + 落库(不丢) + 返回 accepted”，不会在请求内做标准化/聚合/开单。
# - 后续处理通过 Worker 异步推进（可选择独立进程 app/worker.py 或进程内后台线程）。

# SQLite 数据库路径（最小持久化：raw/normalized/incident/ticket/silence）
DB_PATH = os.environ.get("AIALERT_DB_PATH", os.path.join("data", "aialert.db"))
storage = Storage(DB_PATH)

# 消息总线（默认 Redis Stream；本地演示可切 InMemory）
RAW_STREAM = os.environ.get("AIALERT_RAW_STREAM", "raw_alerts")
INCIDENT_STREAM = os.environ.get("AIALERT_INCIDENT_STREAM", "incident_events")
RAW_GROUP = os.environ.get("AIALERT_RAW_GROUP", "normalizer")
INCIDENT_GROUP = os.environ.get("AIALERT_INCIDENT_GROUP", "notifier")
CONSUMER_NAME = os.environ.get("AIALERT_CONSUMER", f"api-{os.getpid()}")

# 聚合窗口（秒）：用于判定同 fingerprint 是否仍属于同一聚合实例
AGG_WINDOW_SECONDS = int(os.environ.get("AIALERT_AGG_WINDOW_SECONDS", "300"))


def _stable_payload_hash(payload: Dict[str, Any]) -> str:
    # 作为兜底幂等键：当上游没有稳定事件 ID 时，用 payload 的稳定序列化哈希做去重
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _extract_source_event_id(source: str, payload: Dict[str, Any]) -> str:
    # 不同告警源的“原始事件 ID”字段不一致，需要按 source 做映射
    if source == "SLS":
        return str(payload.get("alert_id") or "")
    if source == "Sunfire":
        return str(payload.get("id") or "")
    return ""


def _utc_now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def _incident_title(severity: str, service: str, metric_name: str) -> str:
    return f"[{severity}] {service} - {metric_name}"


def _select_bus() -> MessageBus:
    # 总线抽象：二期可平滑替换 Kafka（保持接口语义一致）
    bus_kind = os.environ.get("AIALERT_BUS", "redis").lower()
    return InMemoryBus() if bus_kind == "memory" else RedisStreamBus.from_env()


def _worker_loop(stop_event: threading.Event) -> None:
    # 进程内 Worker（用于本地快速演示）：把“Outbox -> 总线 -> 标准化/聚合 -> 开单/通知”跑通
    bus = _select_bus()
    bus.ensure_consumer_group(RAW_STREAM, RAW_GROUP)
    bus.ensure_consumer_group(INCIDENT_STREAM, INCIDENT_GROUP)
    normalizer = NormalizationManager()

    while not stop_event.is_set():
        progressed = 0

        # 1) Outbox 投递：扫描 raw_alert.enqueued=0 的记录写入 RAW_STREAM，保证“先落库后入队”
        pending = storage.list_pending_raw_alerts(limit=200)
        for row in pending:
            msg_id = bus.publish(
                RAW_STREAM,
                {"raw_alert_id": row.id, "source_system": row.source_system},
            )
            storage.mark_raw_alert_enqueued(raw_alert_id=row.id, stream=RAW_STREAM, msg_id=msg_id)
            progressed += 1

        # 2) Normalizer 消费：读取 RAW_STREAM，完成标准化/预筛/静默/聚合，并产出 incident 事件
        msgs = bus.read_group(
            stream=RAW_STREAM,
            group=RAW_GROUP,
            consumer=CONSUMER_NAME,
            count=50,
            block_ms=200,
        )
        for msg_id, fields in msgs:
            raw_alert_id = fields.get("raw_alert_id")
            if not raw_alert_id:
                bus.ack(RAW_STREAM, RAW_GROUP, msg_id)
                progressed += 1
                continue
            raw = storage.get_raw_alert(raw_alert_id)
            if not raw:
                bus.ack(RAW_STREAM, RAW_GROUP, msg_id)
                progressed += 1
                continue
            try:
                # 2.1 标准化：把不同来源 payload 统一为 NormalizedAlert
                alert = normalizer.normalize(raw.source_system, raw.payload)
                alert.event_id = raw.id
                fp = FingerprintGenerator.generate(alert)
                alert.fingerprint = fp

                service = alert.resource.get("service") or alert.resource.get("app") or "unknown_service"
                now_iso = _utc_now_iso()
                severity_val = getattr(alert.severity, "value", str(alert.severity))
                status_val = getattr(alert.status, "value", str(alert.status))

                # 2.2 规则预筛：用于快速过滤明显噪音（示例：非 prod）
                drop_reason = prescreen_drop_reason(alert)
                silenced = False
                silence_rule_id = None
                if not drop_reason:
                    # 2.3 静默：命中静默规则时不触发开单/通知（但仍记录标准化结果）
                    silence_rule_id = storage.match_silence_rule(silence_candidate(alert))
                    silenced = silence_rule_id is not None

                # 2.4 标准化事件落库（raw_alert_id UNIQUE，保证同 raw 不会重复处理）
                inserted = storage.insert_normalized_event(
                    event_id=alert.event_id,
                    raw_alert_id=raw.id,
                    occurred_at=alert.occurred_at.isoformat(),
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
                    # 2.5 聚合：按 fingerprint 在时间窗口内合并为 incident_group
                    incident, is_new = storage.upsert_incident(
                        fingerprint=fp,
                        title=_incident_title(severity_val, service, alert.metric_name),
                        severity=severity_val,
                        now_iso=now_iso,
                        window_seconds=AGG_WINDOW_SECONDS,
                    )
                    # 2.6 产出 incident 事件：通知后续“开单/通知”消费者
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
                # 对于 Redis Stream：ack 表示该消息已处理完成
                bus.ack(RAW_STREAM, RAW_GROUP, msg_id)
                progressed += 1

        # 3) Notifier 消费：读取 INCIDENT_STREAM，决定是否开单/通知（目前为打印模拟）
        incident_msgs = bus.read_group(
            stream=INCIDENT_STREAM,
            group=INCIDENT_GROUP,
            consumer=CONSUMER_NAME,
            count=50,
            block_ms=200,
        )
        for msg_id, fields in incident_msgs:
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
                    progressed += 1
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
            progressed += 1

        # 空转时稍微 sleep，降低 CPU 占用
        if progressed == 0:
            time.sleep(0.2)


_worker_stop_event: Optional[threading.Event] = None
_worker_thread: Optional[threading.Thread] = None


@app.on_event("startup")
async def _startup():
    global _worker_stop_event, _worker_thread
    # 本地演示开关：把 worker 跟 API 跑在同一进程；生产建议 worker 独立部署
    run_worker = os.environ.get("AIALERT_RUN_WORKER_IN_PROCESS", "0") == "1"
    if not run_worker:
        return
    _worker_stop_event = threading.Event()
    _worker_thread = threading.Thread(target=_worker_loop, args=(_worker_stop_event,), daemon=True)
    _worker_thread.start()


@app.on_event("shutdown")
async def _shutdown():
    global _worker_stop_event
    if _worker_stop_event:
        _worker_stop_event.set()

# 告警接入网关 (Webhook)
@app.post(
    "/ingest/{source}",
    tags=["Ingest"],
    summary="接入告警（仅接收与落库，不代表已处置）",
    description=(
        "用于接入不同来源的告警 Webhook。该接口**仅保证**接收成功并将原始告警写入存储（接入不丢）。\n\n"
        "注意：返回 accepted 并不代表已完成标准化/规则预筛/聚合/AI 分析/开单/通知，这些都是异步处理。\n\n"
        "建议关注字段：raw_alert_id / idempotency_key / duplicated。"
    ),
    response_model=IngestAcceptedResponse,
)
async def ingest_alert(
    source: str,
    raw_payload: Dict[str, Any] = Body(
        ...,
        openapi_examples={
            "主链路测试样例（SLS）": {
                "summary": "用于验证接入、落库、聚合、开单通知主链路",
                "value": {
                    "alert_id": "sls-main-001",
                    "alert_name": "CPU_USAGE_HIGH",
                    "service": "order-service",
                    "pod": "pod-1",
                    "cluster": "prod-sh-1",
                    "severity": "high",
                    "value": 95.5,
                    "timestamp": 1760000000,
                    "status": "firing",
                    "labels": {"env": "prod"},
                },
            },
            "聚合测试样例（SLS，同服务同规则不同实例）": {
                "summary": "多次发送该样例（仅 alert_id/pod 不同）应聚合到同一 group",
                "value": {
                    "alert_id": "sls-agg-001",
                    "alert_name": "CPU_USAGE_HIGH",
                    "service": "order-service",
                    "pod": "pod-2",
                    "cluster": "prod-sh-1",
                    "severity": "high",
                    "value": 97.1,
                    "timestamp": 1760000001,
                    "status": "firing",
                    "labels": {"env": "prod"},
                },
            },
            "AI 抑制测试样例（SLS）": {
                "summary": "配合 AIALERT_LLM_MOCK_FORCE_INVALID=1 触发 ai_suppressed",
                "value": {
                    "alert_id": "sls-ai-suppress-001",
                    "alert_name": "CPU_USAGE_HIGH",
                    "service": "order-service",
                    "pod": "pod-3",
                    "cluster": "prod-sh-1",
                    "severity": "high",
                    "value": 99.0,
                    "timestamp": 1760000002,
                    "status": "firing",
                    "labels": {"env": "prod"},
                },
            },
        },
    ),
):
    try:
        # 只接收 JSON Object：上游 webhook payload 必须是 dict
        if not isinstance(raw_payload, dict):
            raise HTTPException(status_code=400, detail="payload must be a JSON object")

        # 幂等键：优先使用源系统事件 ID；若缺失则用 payload hash 兜底
        source_event_id = _extract_source_event_id(source, raw_payload)
        idempotency_key = (
            f"{source}:{source_event_id}"
            if source_event_id
            else f"{source}:hash:{_stable_payload_hash(raw_payload)}"
        )

        # 先落库：接入不丢（即使后续队列/worker 不可用，raw 仍保留，可回放）
        raw_alert_id, duplicated = storage.insert_raw_alert(
            source_system=source,
            source_event_id=source_event_id,
            idempotency_key=idempotency_key,
            payload=raw_payload,
        )

        return {
            "status": "accepted",
            "raw_alert_id": raw_alert_id,
            "idempotency_key": idempotency_key,
            "duplicated": duplicated,
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        print(f"Error processing alert: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get(
    "/health",
    tags=["Health"],
    summary="健康检查",
    description="用于验证服务进程可用与基础联通性。建议作为所有联调的第一步。",
    response_model=HealthResponse,
)
async def health():
    return {"status": "ok"}


@app.post(
    "/silence",
    tags=["Rules"],
    summary="创建静默规则（防打扰）",
    description=(
        "用于临时屏蔽某类告警的开单/通知（仍保留接入与事件记录，便于追溯）。\n\n"
        "建议关注字段：rule_id。"
    ),
    response_model=SilenceCreateResponse,
)
async def create_silence(
    body: SilenceCreateRequest = Body(
        ...,
        examples={
            "静默某服务某规则（30秒）": {
                "summary": "按 service + metric_name 等值匹配",
                "value": {"match": {"service": "order-service", "metric_name": "CPU_USAGE_HIGH"}, "duration_seconds": 30},
            }
        },
    )
):
    match = body.match
    duration_seconds = body.duration_seconds
    rule_id = storage.add_silence_rule(match=match, duration_seconds=duration_seconds)
    storage.insert_operation_log(
        entity_type="silence_rule",
        entity_id=rule_id,
        action="create",
        actor_type="user",
        actor_id=None,
        detail={"match": match, "duration_seconds": duration_seconds},
    )
    return {"status": "success", "rule_id": rule_id}


@app.get(
    "/silence",
    tags=["Rules"],
    summary="查询当前有效静默规则",
    description="用于确认静默是否创建成功、是否仍在有效期内。",
    response_model=ListSilenceResponse,
)
async def list_silence():
    return {"items": storage.list_active_silence_rules()}


@app.get(
    "/events",
    tags=["Events"],
    summary="查询标准化事件",
    description=(
        "用于查看原始告警经过标准化后的事件记录，可用于验证：规则预筛是否丢弃、静默是否命中、指纹是否一致。\n\n"
        "建议关注字段：fingerprint / dropped / drop_reason / silenced / silence_rule_id / created_at。"
    ),
    response_model=EventsResponse,
)
async def list_events(
    limit: int = Query(50, ge=1, le=500),
    silenced: Optional[bool] = None,
    dropped: Optional[bool] = None,
):
    items = storage.list_normalized_events(limit=limit, silenced=silenced, dropped=dropped)
    return {"items": items}


@app.get(
    "/groups",
    tags=["Groups"],
    summary="查询聚合实例（Groups/Incidents）",
    description=(
        "用于查看告警聚合结果，每条记录代表一个聚合实例。\n\n"
        "建议关注字段：group_id / fingerprint / event_count / first_seen_at / last_seen_at / ticket_id。"
    ),
    response_model=GroupsResponse,
)
async def list_groups(limit: int = Query(50, ge=1, le=500)):
    items = storage.list_groups(limit=limit)
    return {"items": items}


@app.get(
    "/tickets",
    tags=["Tickets"],
    summary="查询工单列表",
    description=(
        "用于验证开单是否发生，以及是否满足幂等（同 group_id 只应有一张工单）。\n\n"
        "建议关注字段：ticket_id / group_id / priority / status / created_at。"
    ),
    response_model=TicketsResponse,
)
async def list_tickets(limit: int = Query(50, ge=1, le=500)):
    items = storage.list_tickets(limit=limit)
    return {"items": items}


@app.get(
    "/notify_records",
    tags=["Notifications"],
    summary="查询通知发送/抑制记录",
    description=(
        "用于验证通知链路是否触发，以及是否被静默/AI 抑制。\n\n"
        "建议关注字段：status / channel / payload.title / payload.ticket_id / created_at。"
    ),
    response_model=NotifyRecordsResponse,
)
async def list_notify_records(
    limit: int = Query(50, ge=1, le=500),
    group_id: Optional[str] = None,
    ticket_id: Optional[str] = None,
    status: Optional[str] = None,
):
    items = storage.list_notify_records(limit=limit, group_id=group_id, ticket_id=ticket_id, status=status)
    return {"items": items}


@app.get(
    "/operation_logs",
    tags=["Audit"],
    summary="查询操作审计流水",
    description=(
        "用于验收关键动作留痕，例如：静默创建、工单创建、通知发送/抑制等。\n\n"
        "建议关注字段：action / entity_type / entity_id / created_at。"
    ),
    response_model=OperationLogsResponse,
)
async def list_operation_logs(
    limit: int = Query(100, ge=1, le=1000),
    entity_type: Optional[str] = None,
    entity_id: Optional[str] = None,
    action: Optional[str] = None,
):
    items = storage.list_operation_logs(limit=limit, entity_type=entity_type, entity_id=entity_id, action=action)
    return {"items": items}


@app.get(
    "/ai_results",
    tags=["AI"],
    summary="查询 AI 分析结果",
    description=(
        "用于查看 AI 对聚合实例的分析结果，覆盖 success / fallback / suppress 等场景。\n\n"
        "建议关注字段：status / is_valid_alert / predicted_severity / confidence / error / latency_ms。\n\n"
        "当前支持的测试场景（可通过环境变量模拟）：\n"
        "- AI success：AIALERT_LLM_MODE=mock（默认）\n"
        "- low-confidence fallback：提高 AIALERT_LLM_LOW_CONFIDENCE\n"
        "- exception fallback：AIALERT_LLM_MODE=openai 且 endpoint 不可用/超时/返回格式异常\n"
        "- AI suppress：AIALERT_LLM_MODE=mock 且 AIALERT_LLM_MOCK_FORCE_INVALID=1\n"
    ),
    response_model=AiResultsResponse,
)
async def list_ai_results(
    limit: int = Query(50, ge=1, le=500),
    group_id: Optional[str] = None,
    status: Optional[str] = None,
    error: Optional[str] = None,
):
    items = storage.list_ai_analysis_results(limit=limit, group_id=group_id, status=status, error=error)
    return {
        "meta": {
            "llm_mode": os.environ.get("AIALERT_LLM_MODE", "mock"),
            "low_conf_threshold": os.environ.get("AIALERT_LLM_LOW_CONFIDENCE", "0.6"),
        },
        "items": items,
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
