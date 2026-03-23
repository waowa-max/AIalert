# 智能告警聚合与处置平台（AIAlert）

面向运维告警场景的智能告警中枢系统，围绕“接入 → 标准化 → 聚合 → AI 分析 → 工单 → 通知 → 审计”构建可运行、可演示、可审计的端到端链路。

## 目标

- 统一多源告警格式，形成标准事件视图
- 收敛告警风暴（fingerprint 聚合）并提供静默防打扰
- 以 incident/group 为单位接入 AI，输出结构化决策（success/fallback/suppress）
- 自动驱动工单与通知，并可查询、可回放、可审计

## 当前已实现能力（MVP）

- 多源接入：`POST /ingest/{source}` 统一入口，原始告警落库 `raw_alert`
- 接入幂等：生成幂等键，重复告警不重复入库
- 标准化事件：写入 `normalized_event`，支持 dropped/silenced 标记与原因
- 告警聚合：按 `fingerprint` 聚合为 `incident_group`，维护 `event_count/first_seen_at/last_seen_at`
- 静默规则：`POST /silence` 创建静默，抑制开单/通知但保留留痕
- 工单：对满足条件的聚合事件自动创建 `ticket`（幂等）
- 通知留痕：写入 `notify_record`（sent/suppressed/ai_suppressed）
- 操作审计：写入 `operation_log`（静默创建、工单创建、通知发送/抑制、AI 抑制等）
- AI 分析：对 incident 构造结构化摘要输入，输出 `is_valid_alert/severity/confidence/reason/suggested_action`，落库 `ai_analysis_result`

## 架构概览

```mermaid
flowchart LR
  A[POST /ingest/{source}\n接收+落库(raw_alert)] --> B[Outbox 投递\nraw_alert.enqueued=0]
  B --> C[消息总线\nRedis Stream / InMemory]
  C --> D[标准化+规则+静默\nnormalized_event]
  D --> E[聚合\nincident_group]
  E --> F[AI 分析\nai_analysis_result]
  E --> G[工单\nticket]
  G --> H[通知\nnotify_record]
  H --> I[审计\noperation_log]
```

## 快速开始（本地演示推荐：不依赖 Redis）

在项目根目录：

```powershell
python -m pip install -r requirements.txt
$env:AIALERT_RUN_WORKER_IN_PROCESS="1"
$env:AIALERT_BUS="memory"
python -m uvicorn app.main:app --host 0.0.0.0 --port 8001
```

打开调试控制台（Swagger）：

- http://localhost:8001/docs

运行演示脚本：

```powershell
python demo.py
```

## 使用方式（推荐演示顺序）

建议按以下顺序联调/验收（与 `/docs` 首页描述一致）：

1. `GET /health`
2. `POST /ingest/{source}`（选择示例一键发送）
3. `GET /events`（验证标准化、预筛 dropped、静默 silenced）
4. `GET /groups`（验证聚合结果与 event_count）
5. `GET /ai_results`（验证 AI success/fallback/suppress）
6. `GET /tickets`（验证是否开单、是否幂等）
7. `GET /notify_records`（验证 sent/suppressed/ai_suppressed）
8. `GET /operation_logs`（验证关键动作留痕）

## 调试控制台（/docs）

项目对 FastAPI Swagger 做了联调友好化改造：

- 按业务流程分组：Health / Ingest / Rules / Events / Groups / AI / Tickets / Notifications / Audit
- 关键写接口提供可选示例（Request body examples），便于“一键发送”联调样例
- 关键查询接口提示建议关注字段，并提供常用过滤参数（如 group_id/status/error）

## AI 测试场景

AI 以 incident/group 为输入（而不是单条 raw alert），并且结果结构化、可查询、可复盘。

- AI success：默认 `AIALERT_LLM_MODE=mock`
- low-confidence fallback：提高 `AIALERT_LLM_LOW_CONFIDENCE`（例如 0.95）
- exception fallback：设置 `AIALERT_LLM_MODE=openai` 且 endpoint 不可用/超时/格式异常
- AI suppress：`AIALERT_LLM_MODE=mock` 且 `AIALERT_LLM_MOCK_FORCE_INVALID=1`

## 环境变量

- `AIALERT_DB_PATH`：SQLite 路径（默认 `data/aialert.db`）
- `AIALERT_RUN_WORKER_IN_PROCESS`：是否在 API 进程内启动 Worker（`1/0`）
- `AIALERT_BUS`：`memory`（本地演示）/ `redis`（Redis Stream）
- `REDIS_URL`：Redis 连接串（`redis://localhost:6379/0`）
- `AIALERT_AGG_WINDOW_SECONDS`：聚合窗口秒数（默认 300）

AI：
- `AIALERT_LLM_MODE`：`mock` / `openai` / `disabled`
- `AIALERT_LLM_LOW_CONFIDENCE`：低置信度阈值（默认 0.6）
- `AIALERT_LLM_TIMEOUT_SECONDS`：调用超时（默认 3）
- `AIALERT_LLM_ENDPOINT`：OpenAI 兼容 Chat Completions endpoint
- `AIALERT_LLM_API_KEY`：API Key
- `AIALERT_LLM_MODEL`：模型名（用于记录/标识）
- `AIALERT_LLM_MOCK_FORCE_INVALID`：mock 强制 is_valid_alert=false（`1/0`）
- `AIALERT_LLM_MOCK_INVALID_CONFIDENCE`：mock 强制无效告警的 confidence（默认 0.95）

## 数据表（SQLite）

- `raw_alert`：原始接入告警 + 幂等信息（接入不丢基础）
- `normalized_event`：标准化事件（dropped/silenced/原因）
- `incident_group`：聚合实例（后续工单与 AI 的核心对象）
- `ticket`：自动工单
- `notify_record`：通知留痕（sent/suppressed/ai_suppressed）
- `operation_log`：关键操作审计流水
- `silence_rule`：静默规则
- `ai_analysis_result`：AI 结构化分析结果（success/fallback/suppress 等）

## Redis Stream 模式（可选）

如需使用 Redis Stream（更贴近生产的异步解耦），设置：

```powershell
$env:AIALERT_BUS="redis"
$env:REDIS_URL="redis://localhost:6379/0"
```

并启动独立 Worker：

```powershell
python -m app.worker
```

## 路线图（后续规划）

- 更完整的聚合窗口与乱序处理
- 相似工单去重
- 基于历史案例的检索增强（RAG）
- 真实飞书/钉钉/企业微信互动通知
- 更完整的工单状态机与人工反馈闭环
- 指标与监控（Prometheus/metrics）
- 消息总线演进到 Kafka（Topic/Partition/Lag/回放）
