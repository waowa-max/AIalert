from typing import Any, Dict, Optional, Tuple
 
from app.core.models import NormalizedAlert
 
 
def prescreen_drop_reason(alert: NormalizedAlert) -> Optional[str]:
    # 规则预筛（MVP）：
    # - 返回 None 表示“保留继续处理”
    # - 返回字符串表示“丢弃原因”（仍会记录 normalized_event.dropped/drop_reason）
    env = (alert.labels or {}).get("env")
    if env and str(env).lower() not in {"prod", "production"}:
        return f"env_not_prod:{env}"
    return None
 
 
def silence_candidate(alert: NormalizedAlert) -> Dict[str, Any]:
    # 从标准化告警中提取“静默匹配”字段
    # 当前策略是等值匹配（match 中的 key 都必须相等才算命中）
    service = alert.resource.get("service") or alert.resource.get("app") or "unknown_service"
    return {
        "service": service,
        "metric_name": alert.metric_name,
        "fingerprint": alert.fingerprint,
    }
