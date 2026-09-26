"""來源收集器。

每個 collector 都必須「自己吞掉例外」並回傳 CollectResult，
任何單一來源失敗都不可影響整期產出。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ..config import Settings
from ..models import VulnItem
from ..util import log  # noqa: F401  (便於子模組共用 logging)


@dataclass
class CollectResult:
    name: str
    label: str = ""
    ok: bool = True
    items: list[VulnItem] = field(default_factory=list)
    error: str | None = None
    warnings: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    def status(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "label": self.label or self.name,
            "ok": self.ok,
            "items": len(self.items),
            "error": self.error,
        }


def kev_index_of(results: list[CollectResult]) -> dict[str, dict[str, Any]]:
    """從 KEV 收集結果取出完整目錄索引（cveID -> entry）。"""
    for result in results:
        if result.name in ("kev", "cisa_kev") and result.ok:
            index = result.extra.get("index")
            if isinstance(index, dict) and index:
                return index
    return {}


def run_safely(fn: Any, settings: Settings, window_from: datetime, window_to: datetime, name: str, label: str) -> CollectResult:
    """執行單一 collector，任何例外都轉成 ok=False 的結果。"""
    try:
        result = fn(settings, window_from, window_to)
        if not isinstance(result, CollectResult):
            raise TypeError(f"{name} 回傳型別錯誤：{type(result)!r}")
        return result
    except Exception as exc:  # noqa: BLE001 - 來源隔離是刻意的設計
        log.error("來源 %s 失敗（已隔離）：%s", name, exc)
        return CollectResult(name=name, label=label, ok=False, error=f"{type(exc).__name__}: {exc}")
