import json
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
 
 
def _utc_now() -> str:
    # 统一使用 UTC 时间，避免多机部署/时区导致的比较问题
    return datetime.now(timezone.utc).isoformat()
 
 
def _json_dumps(value: Any) -> str:
    # JSON 统一序列化策略：确保 hash/比较/落库一致性
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
 
 
def _json_loads(value: str) -> Any:
    return json.loads(value) if value else None
 
 
@dataclass(frozen=True)
class RawAlertRow:
    # raw_alert 表的读取视图（供 outbox/worker 使用）
    id: str
    source_system: str
    source_event_id: str
    idempotency_key: str
    received_at: str
    payload: Dict[str, Any]
    enqueued: bool
    enqueue_stream: Optional[str]
    enqueue_msg_id: Optional[str]
 
 
@dataclass(frozen=True)
class IncidentRow:
    # incident_group 表的读取视图
    group_id: str
    fingerprint: str
    title: str
    severity: str
    status: str
    first_seen_at: str
    last_seen_at: str
    event_count: int
    ticket_id: Optional[str]
 
 
class Storage:
    def __init__(self, db_path: str):
        # 最小持久化存储：
        # - raw_alert：原始告警（接入不丢）
        # - normalized_event：标准化事件（幂等处理）
        # - incident_group：聚合实例（窗口内合并）
        # - ticket：工单（幂等开单）
        # - silence_rule：静默规则（防打扰）
        self._db_path = str(db_path)
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
 
    def _connect(self) -> sqlite3.Connection:
        # 使用 WAL 提升并发写入能力；synchronous=NORMAL 是演示/试运行的折中配置
        conn = sqlite3.connect(self._db_path, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        return conn
 
    def _init_db(self) -> None:
        # 初始化所有核心表（首次启动自动建表）
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS raw_alert (
                  id TEXT PRIMARY KEY,
                  source_system TEXT NOT NULL,
                  source_event_id TEXT NOT NULL,
                  idempotency_key TEXT NOT NULL UNIQUE,
                  received_at TEXT NOT NULL,
                  payload_json TEXT NOT NULL,
                  enqueued INTEGER NOT NULL DEFAULT 0,
                  enqueue_stream TEXT,
                  enqueue_msg_id TEXT
                );
 
                CREATE TABLE IF NOT EXISTS normalized_event (
                  event_id TEXT PRIMARY KEY,
                  raw_alert_id TEXT NOT NULL UNIQUE,
                  occurred_at TEXT NOT NULL,
                  service TEXT NOT NULL,
                  metric_name TEXT NOT NULL,
                  severity TEXT NOT NULL,
                  status TEXT NOT NULL,
                  fingerprint TEXT,
                  labels_json TEXT NOT NULL,
                  resource_json TEXT NOT NULL,
                  dropped INTEGER NOT NULL DEFAULT 0,
                  drop_reason TEXT,
                  created_at TEXT NOT NULL,
                  FOREIGN KEY(raw_alert_id) REFERENCES raw_alert(id)
                );
 
                CREATE TABLE IF NOT EXISTS incident_group (
                  group_id TEXT PRIMARY KEY,
                  fingerprint TEXT NOT NULL,
                  title TEXT NOT NULL,
                  severity TEXT NOT NULL,
                  status TEXT NOT NULL,
                  first_seen_at TEXT NOT NULL,
                  last_seen_at TEXT NOT NULL,
                  event_count INTEGER NOT NULL,
                  ticket_id TEXT
                );
 
                CREATE INDEX IF NOT EXISTS idx_incident_open_fp ON incident_group(fingerprint, status);
 
                CREATE TABLE IF NOT EXISTS ticket (
                  ticket_id TEXT PRIMARY KEY,
                  group_id TEXT NOT NULL UNIQUE,
                  priority TEXT NOT NULL,
                  status TEXT NOT NULL,
                  assignee TEXT,
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL,
                  FOREIGN KEY(group_id) REFERENCES incident_group(group_id)
                );
 
                CREATE TABLE IF NOT EXISTS silence_rule (
                  rule_id TEXT PRIMARY KEY,
                  match_json TEXT NOT NULL,
                  enabled INTEGER NOT NULL DEFAULT 1,
                  created_at TEXT NOT NULL,
                  expires_at TEXT NOT NULL
                );
 
                CREATE INDEX IF NOT EXISTS idx_silence_enabled_expires ON silence_rule(enabled, expires_at);
                """
            )
            self._migrate(conn)

    def _migrate(self, conn: sqlite3.Connection) -> None:
        # 轻量迁移：用于本地/试运行阶段快速演进字段
        self._ensure_column(conn, "normalized_event", "silenced", "INTEGER NOT NULL DEFAULT 0")
        self._ensure_column(conn, "normalized_event", "silence_rule_id", "TEXT")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_norm_created_at ON normalized_event(created_at)"
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS notify_record (
              record_id TEXT PRIMARY KEY,
              group_id TEXT,
              ticket_id TEXT,
              channel TEXT NOT NULL,
              status TEXT NOT NULL,
              payload_json TEXT NOT NULL,
              created_at TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_notify_created_at ON notify_record(created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_notify_group ON notify_record(group_id)")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS operation_log (
              op_id TEXT PRIMARY KEY,
              entity_type TEXT NOT NULL,
              entity_id TEXT NOT NULL,
              action TEXT NOT NULL,
              actor_type TEXT NOT NULL,
              actor_id TEXT,
              detail_json TEXT NOT NULL,
              created_at TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_op_created_at ON operation_log(created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_op_entity ON operation_log(entity_type, entity_id)")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ai_analysis_result (
              analysis_id TEXT PRIMARY KEY,
              group_id TEXT NOT NULL,
              model TEXT NOT NULL,
              status TEXT NOT NULL,
              is_valid_alert INTEGER,
              predicted_severity TEXT,
              confidence REAL,
              reason TEXT,
              suggested_action TEXT,
              request_json TEXT NOT NULL,
              response_json TEXT,
              error TEXT,
              latency_ms INTEGER,
              created_at TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ai_created_at ON ai_analysis_result(created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_ai_group ON ai_analysis_result(group_id)")

    def _ensure_column(self, conn: sqlite3.Connection, table: str, column: str, ddl: str) -> None:
        cols = conn.execute(f"PRAGMA table_info({table})").fetchall()
        for c in cols:
            if str(c["name"]) == column:
                return
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")
 
    def insert_raw_alert(
        self,
        source_system: str,
        source_event_id: str,
        idempotency_key: str,
        payload: Dict[str, Any],
    ) -> Tuple[str, bool]:
        # 接入幂等去重：idempotency_key UNIQUE
        # 返回 (raw_alert_id, duplicated)
        raw_id = str(uuid.uuid4())
        received_at = _utc_now()
        payload_json = _json_dumps(payload)
        with self._connect() as conn:
            try:
                conn.execute(
                    """
                    INSERT INTO raw_alert(id, source_system, source_event_id, idempotency_key, received_at, payload_json)
                    VALUES(?, ?, ?, ?, ?, ?)
                    """,
                    (raw_id, source_system, source_event_id, idempotency_key, received_at, payload_json),
                )
                return raw_id, False
            except sqlite3.IntegrityError:
                # 幂等命中：直接返回既有 raw_alert.id
                row = conn.execute(
                    "SELECT id FROM raw_alert WHERE idempotency_key = ?",
                    (idempotency_key,),
                ).fetchone()
                return str(row["id"]), True
 
    def get_raw_alert(self, raw_alert_id: str) -> Optional[RawAlertRow]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM raw_alert WHERE id = ?",
                (raw_alert_id,),
            ).fetchone()
            if not row:
                return None
            return RawAlertRow(
                id=str(row["id"]),
                source_system=str(row["source_system"]),
                source_event_id=str(row["source_event_id"]),
                idempotency_key=str(row["idempotency_key"]),
                received_at=str(row["received_at"]),
                payload=_json_loads(str(row["payload_json"])) or {},
                enqueued=bool(row["enqueued"]),
                enqueue_stream=row["enqueue_stream"],
                enqueue_msg_id=row["enqueue_msg_id"],
            )
 
    def list_pending_raw_alerts(self, limit: int = 200) -> List[RawAlertRow]:
        # Outbox 扫描：查找尚未投递到消息总线的 raw_alert（enqueued=0）
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM raw_alert WHERE enqueued = 0 ORDER BY received_at ASC LIMIT ?",
                (limit,),
            ).fetchall()
            result: List[RawAlertRow] = []
            for row in rows:
                result.append(
                    RawAlertRow(
                        id=str(row["id"]),
                        source_system=str(row["source_system"]),
                        source_event_id=str(row["source_event_id"]),
                        idempotency_key=str(row["idempotency_key"]),
                        received_at=str(row["received_at"]),
                        payload=_json_loads(str(row["payload_json"])) or {},
                        enqueued=bool(row["enqueued"]),
                        enqueue_stream=row["enqueue_stream"],
                        enqueue_msg_id=row["enqueue_msg_id"],
                    )
                )
            return result
 
    def mark_raw_alert_enqueued(self, raw_alert_id: str, stream: str, msg_id: str) -> None:
        # Outbox 投递完成标记：避免同一 raw_alert 被重复投递
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE raw_alert
                SET enqueued = 1, enqueue_stream = ?, enqueue_msg_id = ?
                WHERE id = ?
                """,
                (stream, msg_id, raw_alert_id),
            )
 
    def insert_normalized_event(
        self,
        event_id: str,
        raw_alert_id: str,
        occurred_at: str,
        service: str,
        metric_name: str,
        severity: str,
        status: str,
        fingerprint: Optional[str],
        labels: Dict[str, Any],
        resource: Dict[str, Any],
        dropped: bool,
        drop_reason: Optional[str],
        silenced: bool = False,
        silence_rule_id: Optional[str] = None,
    ) -> bool:
        # 标准化事件幂等：normalized_event.raw_alert_id UNIQUE
        # 返回 True 表示首次插入；False 表示重复处理（可忽略）
        with self._connect() as conn:
            try:
                conn.execute(
                    """
                    INSERT INTO normalized_event(
                      event_id, raw_alert_id, occurred_at, service, metric_name, severity, status, fingerprint,
                      labels_json, resource_json, dropped, drop_reason, silenced, silence_rule_id, created_at
                    )
                    VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event_id,
                        raw_alert_id,
                        occurred_at,
                        service,
                        metric_name,
                        severity,
                        status,
                        fingerprint,
                        _json_dumps(labels),
                        _json_dumps(resource),
                        1 if dropped else 0,
                        drop_reason,
                        1 if silenced else 0,
                        silence_rule_id,
                        _utc_now(),
                    ),
                )
                return True
            except sqlite3.IntegrityError:
                return False

    def list_normalized_events(
        self,
        limit: int = 50,
        silenced: Optional[bool] = None,
        dropped: Optional[bool] = None,
    ) -> List[Dict[str, Any]]:
        where = []
        params: List[Any] = []
        if silenced is not None:
            where.append("silenced = ?")
            params.append(1 if silenced else 0)
        if dropped is not None:
            where.append("dropped = ?")
            params.append(1 if dropped else 0)
        where_sql = (" WHERE " + " AND ".join(where)) if where else ""
        sql = (
            "SELECT event_id, raw_alert_id, occurred_at, service, metric_name, severity, status, fingerprint, "
            "dropped, drop_reason, silenced, silence_rule_id, created_at "
            "FROM normalized_event"
            f"{where_sql} "
            "ORDER BY created_at DESC "
            "LIMIT ?"
        )
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(sql, tuple(params)).fetchall()
            out: List[Dict[str, Any]] = []
            for r in rows:
                out.append(
                    {
                        "event_id": str(r["event_id"]),
                        "raw_alert_id": str(r["raw_alert_id"]),
                        "occurred_at": str(r["occurred_at"]),
                        "service": str(r["service"]),
                        "metric_name": str(r["metric_name"]),
                        "severity": str(r["severity"]),
                        "status": str(r["status"]),
                        "fingerprint": r["fingerprint"],
                        "dropped": bool(r["dropped"]),
                        "drop_reason": r["drop_reason"],
                        "silenced": bool(r["silenced"]),
                        "silence_rule_id": r["silence_rule_id"],
                        "created_at": str(r["created_at"]),
                    }
                )
            return out
 
    def upsert_incident(
        self,
        fingerprint: str,
        title: str,
        severity: str,
        now_iso: str,
        window_seconds: int,
    ) -> Tuple[IncidentRow, bool]:
        # 聚合逻辑：
        # - 查询同 fingerprint 且 open 的最新 incident_group
        # - 若超过窗口则新建；否则更新 last_seen_at/event_count
        # 返回 (incident, is_new)
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM incident_group
                WHERE fingerprint = ? AND status = 'open'
                ORDER BY last_seen_at DESC
                LIMIT 1
                """,
                (fingerprint,),
            ).fetchone()
 
            if not row:
                group_id = f"INC-{fingerprint[:8]}-{int(datetime.now(timezone.utc).timestamp())}"
                conn.execute(
                    """
                    INSERT INTO incident_group(
                      group_id, fingerprint, title, severity, status,
                      first_seen_at, last_seen_at, event_count, ticket_id
                    )
                    VALUES(?, ?, ?, ?, 'open', ?, ?, 1, NULL)
                    """,
                    (group_id, fingerprint, title, severity, now_iso, now_iso),
                )
                return (
                    IncidentRow(
                        group_id=group_id,
                        fingerprint=fingerprint,
                        title=title,
                        severity=severity,
                        status="open",
                        first_seen_at=now_iso,
                        last_seen_at=now_iso,
                        event_count=1,
                        ticket_id=None,
                    ),
                    True,
                )
 
            last_seen = datetime.fromisoformat(str(row["last_seen_at"]))
            now_dt = datetime.fromisoformat(now_iso)
            expired = (now_dt - last_seen).total_seconds() > window_seconds
            if expired:
                group_id = f"INC-{fingerprint[:8]}-{int(datetime.now(timezone.utc).timestamp())}"
                conn.execute(
                    """
                    INSERT INTO incident_group(
                      group_id, fingerprint, title, severity, status,
                      first_seen_at, last_seen_at, event_count, ticket_id
                    )
                    VALUES(?, ?, ?, ?, 'open', ?, ?, 1, NULL)
                    """,
                    (group_id, fingerprint, title, severity, now_iso, now_iso),
                )
                return (
                    IncidentRow(
                        group_id=group_id,
                        fingerprint=fingerprint,
                        title=title,
                        severity=severity,
                        status="open",
                        first_seen_at=now_iso,
                        last_seen_at=now_iso,
                        event_count=1,
                        ticket_id=None,
                    ),
                    True,
                )
 
            group_id = str(row["group_id"])
            new_count = int(row["event_count"]) + 1
            conn.execute(
                """
                UPDATE incident_group
                SET last_seen_at = ?, event_count = ?, severity = ?
                WHERE group_id = ?
                """,
                (now_iso, new_count, severity, group_id),
            )
            updated = conn.execute(
                "SELECT * FROM incident_group WHERE group_id = ?",
                (group_id,),
            ).fetchone()
            return (
                IncidentRow(
                    group_id=str(updated["group_id"]),
                    fingerprint=str(updated["fingerprint"]),
                    title=str(updated["title"]),
                    severity=str(updated["severity"]),
                    status=str(updated["status"]),
                    first_seen_at=str(updated["first_seen_at"]),
                    last_seen_at=str(updated["last_seen_at"]),
                    event_count=int(updated["event_count"]),
                    ticket_id=updated["ticket_id"],
                ),
                False,
            )
 
    def get_incident(self, group_id: str) -> Optional[IncidentRow]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM incident_group WHERE group_id = ?",
                (group_id,),
            ).fetchone()
            if not row:
                return None
            return IncidentRow(
                group_id=str(row["group_id"]),
                fingerprint=str(row["fingerprint"]),
                title=str(row["title"]),
                severity=str(row["severity"]),
                status=str(row["status"]),
                first_seen_at=str(row["first_seen_at"]),
                last_seen_at=str(row["last_seen_at"]),
                event_count=int(row["event_count"]),
                ticket_id=row["ticket_id"],
            )
 
    def create_ticket_if_needed(self, group_id: str, priority: str) -> Tuple[str, bool]:
        # 幂等开单：
        # - ticket.group_id UNIQUE，保证每个 incident_group 只对应一张工单
        # 返回 (ticket_id, created)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT ticket_id FROM ticket WHERE group_id = ?",
                (group_id,),
            ).fetchone()
            if row and row["ticket_id"]:
                return str(row["ticket_id"]), False
 
            ticket_id = f"TKT-{int(datetime.now(timezone.utc).timestamp())}"
            now = _utc_now()
            conn.execute(
                """
                INSERT INTO ticket(ticket_id, group_id, priority, status, assignee, created_at, updated_at)
                VALUES(?, ?, ?, 'NEW', NULL, ?, ?)
                """,
                (ticket_id, group_id, priority, now, now),
            )
            conn.execute(
                "UPDATE incident_group SET ticket_id = ? WHERE group_id = ?",
                (ticket_id, group_id),
            )
            return ticket_id, True
 
    def update_ticket_status(self, ticket_id: str, status: str) -> bool:
        with self._connect() as conn:
            now = _utc_now()
            cur = conn.execute(
                "UPDATE ticket SET status = ?, updated_at = ? WHERE ticket_id = ?",
                (status, now, ticket_id),
            )
            return cur.rowcount > 0
 
    def add_silence_rule(self, match: Dict[str, Any], duration_seconds: int) -> str:
        # 添加静默规则（match 为等值匹配；expires_at 到期后自动失效）
        rule_id = f"SL-{uuid.uuid4().hex[:12]}"
        created_at = _utc_now()
        expires_at = (datetime.now(timezone.utc).timestamp() + duration_seconds)
        expires_iso = datetime.fromtimestamp(expires_at, tz=timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO silence_rule(rule_id, match_json, enabled, created_at, expires_at)
                VALUES(?, ?, 1, ?, ?)
                """,
                (rule_id, _json_dumps(match), created_at, expires_iso),
            )
        return rule_id
 
    def list_active_silence_rules(self) -> List[Dict[str, Any]]:
        # 查询当前仍有效的静默规则
        now = _utc_now()
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT rule_id, match_json, created_at, expires_at
                FROM silence_rule
                WHERE enabled = 1 AND expires_at > ?
                ORDER BY created_at DESC
                """,
                (now,),
            ).fetchall()
            result: List[Dict[str, Any]] = []
            for r in rows:
                result.append(
                    {
                        "rule_id": str(r["rule_id"]),
                        "match": _json_loads(str(r["match_json"])) or {},
                        "created_at": str(r["created_at"]),
                        "expires_at": str(r["expires_at"]),
                    }
                )
            return result
 
    def match_silence_rule(self, candidate: Dict[str, Any]) -> Optional[str]:
        # 返回命中的 rule_id；若未命中返回 None
        now = _utc_now()
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT rule_id, match_json
                FROM silence_rule
                WHERE enabled = 1 AND expires_at > ?
                """,
                (now,),
            ).fetchall()
            for r in rows:
                match = _json_loads(str(r["match_json"])) or {}
                ok = True
                for k, v in match.items():
                    if candidate.get(k) != v:
                        ok = False
                        break
                if ok:
                    return str(r["rule_id"])
            return None

    def is_silenced(self, candidate: Dict[str, Any]) -> bool:
        # 静默命中判断：candidate 必须包含 match 中的所有键且值相等
        return self.match_silence_rule(candidate) is not None

    def insert_notify_record(
        self,
        group_id: Optional[str],
        ticket_id: Optional[str],
        channel: str,
        status: str,
        payload: Dict[str, Any],
    ) -> str:
        record_id = f"NR-{uuid.uuid4().hex}"
        now = _utc_now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO notify_record(record_id, group_id, ticket_id, channel, status, payload_json, created_at)
                VALUES(?, ?, ?, ?, ?, ?, ?)
                """,
                (record_id, group_id, ticket_id, channel, status, _json_dumps(payload), now),
            )
        return record_id

    def list_notify_records(
        self,
        limit: int = 50,
        group_id: Optional[str] = None,
        ticket_id: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        where = []
        params: List[Any] = []
        if group_id:
            where.append("group_id = ?")
            params.append(group_id)
        if ticket_id:
            where.append("ticket_id = ?")
            params.append(ticket_id)
        if status:
            where.append("status = ?")
            params.append(status)
        where_sql = (" WHERE " + " AND ".join(where)) if where else ""
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT record_id, group_id, ticket_id, channel, status, payload_json, created_at
                FROM notify_record
                """
                + where_sql
                + """
                ORDER BY created_at DESC
                LIMIT ?
                """,
                tuple(params + [limit]),
            ).fetchall()
            out: List[Dict[str, Any]] = []
            for r in rows:
                out.append(
                    {
                        "record_id": str(r["record_id"]),
                        "group_id": r["group_id"],
                        "ticket_id": r["ticket_id"],
                        "channel": str(r["channel"]),
                        "status": str(r["status"]),
                        "payload": _json_loads(str(r["payload_json"])) or {},
                        "created_at": str(r["created_at"]),
                    }
                )
            return out

    def insert_operation_log(
        self,
        entity_type: str,
        entity_id: str,
        action: str,
        actor_type: str,
        actor_id: Optional[str],
        detail: Dict[str, Any],
    ) -> str:
        op_id = f"OP-{uuid.uuid4().hex}"
        now = _utc_now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO operation_log(op_id, entity_type, entity_id, action, actor_type, actor_id, detail_json, created_at)
                VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (op_id, entity_type, entity_id, action, actor_type, actor_id, _json_dumps(detail), now),
            )
        return op_id

    def list_operation_logs(
        self,
        limit: int = 100,
        entity_type: Optional[str] = None,
        entity_id: Optional[str] = None,
        action: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        where = []
        params: List[Any] = []
        if entity_type:
            where.append("entity_type = ?")
            params.append(entity_type)
        if entity_id:
            where.append("entity_id = ?")
            params.append(entity_id)
        if action:
            where.append("action = ?")
            params.append(action)
        where_sql = (" WHERE " + " AND ".join(where)) if where else ""
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT op_id, entity_type, entity_id, action, actor_type, actor_id, detail_json, created_at
                FROM operation_log
                """
                + where_sql
                + """
                ORDER BY created_at DESC
                LIMIT ?
                """,
                tuple(params + [limit]),
            ).fetchall()
            out: List[Dict[str, Any]] = []
            for r in rows:
                out.append(
                    {
                        "op_id": str(r["op_id"]),
                        "entity_type": str(r["entity_type"]),
                        "entity_id": str(r["entity_id"]),
                        "action": str(r["action"]),
                        "actor_type": str(r["actor_type"]),
                        "actor_id": r["actor_id"],
                        "detail": _json_loads(str(r["detail_json"])) or {},
                        "created_at": str(r["created_at"]),
                    }
                )
            return out

    def list_groups(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT group_id, fingerprint, title, severity, status, first_seen_at, last_seen_at, event_count, ticket_id
                FROM incident_group
                ORDER BY last_seen_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            out: List[Dict[str, Any]] = []
            for r in rows:
                out.append(
                    {
                        "group_id": str(r["group_id"]),
                        "fingerprint": str(r["fingerprint"]),
                        "title": str(r["title"]),
                        "severity": str(r["severity"]),
                        "status": str(r["status"]),
                        "first_seen_at": str(r["first_seen_at"]),
                        "last_seen_at": str(r["last_seen_at"]),
                        "event_count": int(r["event_count"]),
                        "ticket_id": r["ticket_id"],
                    }
                )
            return out

    def list_tickets(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT ticket_id, group_id, priority, status, assignee, created_at, updated_at
                FROM ticket
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            out: List[Dict[str, Any]] = []
            for r in rows:
                out.append(
                    {
                        "ticket_id": str(r["ticket_id"]),
                        "group_id": str(r["group_id"]),
                        "priority": str(r["priority"]),
                        "status": str(r["status"]),
                        "assignee": r["assignee"],
                        "created_at": str(r["created_at"]),
                        "updated_at": str(r["updated_at"]),
                    }
                )
            return out

    def insert_ai_analysis_result(
        self,
        group_id: str,
        model: str,
        status: str,
        request: Dict[str, Any],
        response: Optional[Dict[str, Any]],
        is_valid_alert: Optional[bool],
        predicted_severity: Optional[str],
        confidence: Optional[float],
        reason: Optional[str],
        suggested_action: Optional[str],
        error: Optional[str],
        latency_ms: Optional[int],
    ) -> str:
        analysis_id = f"AI-{uuid.uuid4().hex}"
        now = _utc_now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO ai_analysis_result(
                  analysis_id, group_id, model, status, is_valid_alert, predicted_severity, confidence,
                  reason, suggested_action, request_json, response_json, error, latency_ms, created_at
                )
                VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    analysis_id,
                    group_id,
                    model,
                    status,
                    None if is_valid_alert is None else (1 if is_valid_alert else 0),
                    predicted_severity,
                    confidence,
                    reason,
                    suggested_action,
                    _json_dumps(request),
                    None if response is None else _json_dumps(response),
                    error,
                    latency_ms,
                    now,
                ),
            )
        return analysis_id

    def list_ai_analysis_results(
        self,
        limit: int = 50,
        group_id: Optional[str] = None,
        status: Optional[str] = None,
        error: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            where = []
            params: List[Any] = []
            if group_id:
                where.append("group_id = ?")
                params.append(group_id)
            if status:
                where.append("status = ?")
                params.append(status)
            if error:
                where.append("error = ?")
                params.append(error)
            where_sql = (" WHERE " + " AND ".join(where)) if where else ""
            sql = (
                """
                SELECT analysis_id, group_id, model, status, is_valid_alert, predicted_severity, confidence,
                       reason, suggested_action, request_json, response_json, error, latency_ms, created_at
                FROM ai_analysis_result
                """
                + where_sql
                + """
                ORDER BY created_at DESC
                LIMIT ?
                """
            )
            rows = conn.execute(sql, tuple(params + [limit])).fetchall()
            out: List[Dict[str, Any]] = []
            for r in rows:
                out.append(
                    {
                        "analysis_id": str(r["analysis_id"]),
                        "group_id": str(r["group_id"]),
                        "model": str(r["model"]),
                        "status": str(r["status"]),
                        "is_valid_alert": None if r["is_valid_alert"] is None else bool(r["is_valid_alert"]),
                        "predicted_severity": r["predicted_severity"],
                        "confidence": r["confidence"],
                        "reason": r["reason"],
                        "suggested_action": r["suggested_action"],
                        "request": _json_loads(str(r["request_json"])) or {},
                        "response": _json_loads(str(r["response_json"])) if r["response_json"] else None,
                        "error": r["error"],
                        "latency_ms": r["latency_ms"],
                        "created_at": str(r["created_at"]),
                    }
                )
            return out

    def list_recent_events_for_group(self, group_id: str, limit: int = 20) -> List[Dict[str, Any]]:
        row = self.get_incident(group_id)
        if not row:
            return []
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT event_id, occurred_at, service, metric_name, severity, status, fingerprint, dropped, drop_reason, silenced, silence_rule_id, created_at
                FROM normalized_event
                WHERE fingerprint = ? AND created_at >= ? AND created_at <= ?
                ORDER BY created_at DESC
                LIMIT ?
                """,
                (row.fingerprint, row.first_seen_at, row.last_seen_at, limit),
            ).fetchall()
            out: List[Dict[str, Any]] = []
            for r in rows:
                out.append(
                    {
                        "event_id": str(r["event_id"]),
                        "occurred_at": str(r["occurred_at"]),
                        "service": str(r["service"]),
                        "metric_name": str(r["metric_name"]),
                        "severity": str(r["severity"]),
                        "status": str(r["status"]),
                        "fingerprint": r["fingerprint"],
                        "dropped": bool(r["dropped"]),
                        "drop_reason": r["drop_reason"],
                        "silenced": bool(r["silenced"]),
                        "silence_rule_id": r["silence_rule_id"],
                        "created_at": str(r["created_at"]),
                    }
                )
            return out
