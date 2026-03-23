from abc import ABC, abstractmethod
from typing import Any, Dict, Iterable, List, Optional, Tuple
 
 
class MessageBus(ABC):
    # 消息总线抽象层：
    # - 首期用 Redis Stream 过渡（便于快速落地/本地演示）
    # - 二期可以实现 KafkaBus 并替换注入（接口语义保持一致）
    @abstractmethod
    def publish(self, stream: str, fields: Dict[str, str]) -> str:
        # 发布一条消息到指定 stream/topic，返回消息 ID（Redis: xadd id）
        raise NotImplementedError
 
    @abstractmethod
    def ensure_consumer_group(self, stream: str, group: str) -> None:
        # 确保消费组存在（Redis Stream: XGROUP CREATE；Kafka: consumer group 自动创建）
        raise NotImplementedError
 
    @abstractmethod
    def read_group(
        self,
        stream: str,
        group: str,
        consumer: str,
        count: int,
        block_ms: int,
    ) -> List[Tuple[str, Dict[str, str]]]:
        # 以消费组方式读取消息：
        # - stream/topic：消息流
        # - group：消费组
        # - consumer：消费实例名
        # 返回 [(msg_id, fields), ...]
        raise NotImplementedError
 
    @abstractmethod
    def ack(self, stream: str, group: str, msg_id: str) -> None:
        # 确认消息已处理完成（Redis Stream: XACK；Kafka: commit offset）
        raise NotImplementedError
