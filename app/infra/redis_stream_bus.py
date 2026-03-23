import os
from typing import Dict, List, Tuple
 
import redis
 
from app.core.message_bus import MessageBus
 
 
class RedisStreamBus(MessageBus):
    # Redis Stream 版本的消息总线：
    # - publish -> XADD
    # - ensure_consumer_group -> XGROUP CREATE (mkstream)
    # - read_group -> XREADGROUP (>)
    # - ack -> XACK
    def __init__(self, redis_url: str):
        self._redis = redis.Redis.from_url(redis_url, decode_responses=True)
 
    @staticmethod
    def from_env() -> "RedisStreamBus":
        # 默认使用本地 Redis，便于快速演示
        redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
        return RedisStreamBus(redis_url=redis_url)
 
    def publish(self, stream: str, fields: Dict[str, str]) -> str:
        return self._redis.xadd(stream, fields)
 
    def ensure_consumer_group(self, stream: str, group: str) -> None:
        try:
            self._redis.xgroup_create(stream, group, id="0", mkstream=True)
        except redis.ResponseError as e:
            if "BUSYGROUP" in str(e):
                return
            raise
 
    def read_group(
        self,
        stream: str,
        group: str,
        consumer: str,
        count: int,
        block_ms: int,
    ) -> List[Tuple[str, Dict[str, str]]]:
        resp = self._redis.xreadgroup(
            groupname=group,
            consumername=consumer,
            streams={stream: ">"},
            count=count,
            block=block_ms,
        )
        if not resp:
            return []
        out: List[Tuple[str, Dict[str, str]]] = []
        for _, messages in resp:
            for msg_id, fields in messages:
                out.append((msg_id, {str(k): str(v) for k, v in fields.items()}))
        return out
 
    def ack(self, stream: str, group: str, msg_id: str) -> None:
        self._redis.xack(stream, group, msg_id)
