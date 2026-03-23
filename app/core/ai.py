import json
import os
import time
from typing import Any, Dict, Optional, Tuple

import requests
from pydantic import BaseModel, Field, ValidationError


class AiDecision(BaseModel):
    is_valid_alert: bool
    severity: str
    confidence: float = Field(ge=0.0, le=1.0)
    reason: str
    suggested_action: str


def _llm_mode() -> str:
    return os.environ.get("AIALERT_LLM_MODE", "mock").lower()


def _timeout_seconds() -> float:
    try:
        return float(os.environ.get("AIALERT_LLM_TIMEOUT_SECONDS", "3"))
    except ValueError:
        return 3.0


def _low_conf_threshold() -> float:
    try:
        return float(os.environ.get("AIALERT_LLM_LOW_CONFIDENCE", "0.6"))
    except ValueError:
        return 0.6


def _mock_force_invalid() -> bool:
    return os.environ.get("AIALERT_LLM_MOCK_FORCE_INVALID", "0") == "1"


def _mock_invalid_confidence() -> float:
    try:
        return float(os.environ.get("AIALERT_LLM_MOCK_INVALID_CONFIDENCE", "0.95"))
    except ValueError:
        return 0.95


def _fallback_decision(incident: Dict[str, Any], reason: str) -> AiDecision:
    return AiDecision(
        is_valid_alert=True,
        severity=str(incident.get("severity") or "P2"),
        confidence=0.0,
        reason=reason,
        suggested_action="请值班同学确认告警影响面，必要时查看服务与依赖链路日志/指标。",
    )


def build_incident_request(incident: Dict[str, Any], recent_events: Optional[list] = None) -> Dict[str, Any]:
    req = {
        "incident": {
            "group_id": incident.get("group_id"),
            "title": incident.get("title"),
            "severity": incident.get("severity"),
            "status": incident.get("status"),
            "event_count": incident.get("event_count"),
            "first_seen_at": incident.get("first_seen_at"),
            "last_seen_at": incident.get("last_seen_at"),
            "fingerprint": incident.get("fingerprint"),
        },
        "recent_events": recent_events or [],
    }
    return req


def analyze_incident(request_payload: Dict[str, Any]) -> Tuple[AiDecision, Dict[str, Any], str, Optional[str], Optional[int]]:
    mode = _llm_mode()
    started = time.time()
    low_conf_threshold = _low_conf_threshold()
    request_payload.setdefault("meta", {})
    if isinstance(request_payload["meta"], dict):
        request_payload["meta"].update(
            {
                "llm_mode": mode,
                "low_conf_threshold": low_conf_threshold,
                "timeout_seconds": _timeout_seconds(),
            }
        )

    if mode == "disabled":
        return _fallback_decision(request_payload.get("incident", {}), "ai_disabled"), {}, "fallback", "ai_disabled", 0

    if mode == "mock":
        inc = request_payload.get("incident", {})
        sev = str(inc.get("severity") or "P2")
        event_count = int(inc.get("event_count") or 1)
        if _mock_force_invalid():
            decision = AiDecision(
                is_valid_alert=False,
                severity="P3",
                confidence=_mock_invalid_confidence(),
                reason="mock 模式：强制判定为无效告警，用于测试 ai_suppressed 路径。",
                suggested_action="无需创建工单与通知；建议记录并观察是否持续复发。",
            )
        else:
            confidence = 0.8 if event_count >= 3 else 0.6
            decision = AiDecision(
                is_valid_alert=True,
                severity=sev,
                confidence=confidence,
                reason="mock 模式：基于聚合计数与当前严重度生成建议。",
                suggested_action="mock 建议：检查近期变更与核心指标，必要时回滚或扩容。",
            )
        latency_ms = int((time.time() - started) * 1000)
        if decision.confidence < low_conf_threshold:
            return (
                _fallback_decision(request_payload.get("incident", {}), "ai_low_confidence"),
                {"decision": decision.model_dump(), "low_conf_threshold": low_conf_threshold},
                "fallback",
                "ai_low_confidence",
                latency_ms,
            )
        return decision, decision.model_dump(), "success", None, latency_ms

    endpoint = os.environ.get("AIALERT_LLM_ENDPOINT", "").strip()
    api_key = os.environ.get("AIALERT_LLM_API_KEY", "").strip()
    model = os.environ.get("AIALERT_LLM_MODEL", "gpt-4o-mini")

    if not endpoint:
        latency_ms = int((time.time() - started) * 1000)
        return _fallback_decision(request_payload.get("incident", {}), "ai_no_endpoint"), {}, "fallback", "ai_no_endpoint", latency_ms

    system_prompt = (
        "你是运维告警分析助手。请仅输出 JSON，不要输出其它文本。"
        "JSON 格式固定为："
        "{\"is_valid_alert\":bool,\"severity\":\"P0|P1|P2|P3\",\"confidence\":0~1,\"reason\":string,\"suggested_action\":string}"
    )
    user_prompt = json.dumps(request_payload, ensure_ascii=False)

    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.0,
    }

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    try:
        resp = requests.post(endpoint, json=body, headers=headers, timeout=_timeout_seconds())
        resp.raise_for_status()
        raw = resp.json()
        content = (
            raw.get("choices", [{}])[0]
            .get("message", {})
            .get("content", "")
        )
        parsed = json.loads(content)
        decision = AiDecision.model_validate(parsed)
        latency_ms = int((time.time() - started) * 1000)
        if decision.confidence < low_conf_threshold:
            return (
                _fallback_decision(request_payload.get("incident", {}), "ai_low_confidence"),
                {"decision": parsed, "low_conf_threshold": low_conf_threshold},
                "fallback",
                "ai_low_confidence",
                latency_ms,
            )
        return decision, parsed, "success", None, latency_ms
    except (requests.Timeout,) as e:
        latency_ms = int((time.time() - started) * 1000)
        return _fallback_decision(request_payload.get("incident", {}), "ai_timeout"), {}, "fallback", "ai_timeout", latency_ms
    except (requests.RequestException, json.JSONDecodeError, ValidationError) as e:
        latency_ms = int((time.time() - started) * 1000)
        return _fallback_decision(request_payload.get("incident", {}), "ai_bad_response"), {}, "fallback", "ai_bad_response", latency_ms
