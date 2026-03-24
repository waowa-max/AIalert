from __future__ import annotations

from typing import Any, Dict, List

from app.adapters.base import BaseAdapter, NormalizedIngestEvent
from app.adapters.grafana import GrafanaAlertingAdapter
from app.adapters.prometheus import PrometheusAlertmanagerAdapter
from app.adapters.sls import SlsAdapter


class AdapterRegistry:
    def __init__(self):
        self._adapters: List[BaseAdapter] = [
            SlsAdapter(),
            PrometheusAlertmanagerAdapter(),
            GrafanaAlertingAdapter(),
        ]

    def resolve(self, source: str, payload: Dict[str, Any]) -> BaseAdapter:
        for ad in self._adapters:
            if ad.can_handle(source, payload):
                return ad
        raise ValueError(f"No adapter found for source={source}")

    def parse_events(self, source: str, payload: Dict[str, Any]) -> List[NormalizedIngestEvent]:
        adapter = self.resolve(source, payload)
        return adapter.parse(payload)


registry = AdapterRegistry()


def resolve_adapter(source: str, payload: Dict[str, Any]) -> BaseAdapter:
    return registry.resolve(source, payload)


def parse_events(source: str, payload: Dict[str, Any]) -> List[NormalizedIngestEvent]:
    return registry.parse_events(source, payload)


__all__ = [
    "AdapterRegistry",
    "BaseAdapter",
    "NormalizedIngestEvent",
    "registry",
    "resolve_adapter",
    "parse_events",
]
