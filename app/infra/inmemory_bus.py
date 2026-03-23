import threading
from collections import defaultdict, deque
from typing import Deque, Dict, List, Tuple
 
from app.core.message_bus import MessageBus
 
 
class InMemoryBus(MessageBus):
    # 进程内内存总线（仅用于本地演示）：
    # - 不依赖 Redis
    # - 不支持跨进程/重启恢复
    # - 不支持消费组语义的完整一致性（这里只做最小模拟）
    def __init__(self):
        self._lock = threading.Lock()
        self._streams: Dict[str, Deque[Tuple[str, Dict[str, str]]]] = defaultdict(deque)
        self._seq = 0
 
    def publish(self, stream: str, fields: Dict[str, str]) -> str:
        with self._lock:
            self._seq += 1
            msg_id = str(self._seq)
            self._streams[stream].append((msg_id, dict(fields)))
            return msg_id
 
    def ensure_consumer_group(self, stream: str, group: str) -> None:
        return
 
    def read_group(
        self,
        stream: str,
        group: str,
        consumer: str,
        count: int,
        block_ms: int,
    ) -> List[Tuple[str, Dict[str, str]]]:
        with self._lock:
            out: List[Tuple[str, Dict[str, str]]] = []
            q = self._streams[stream]
            while q and len(out) < count:
                out.append(q.popleft())
            return out
 
    def ack(self, stream: str, group: str, msg_id: str) -> None:
        return
