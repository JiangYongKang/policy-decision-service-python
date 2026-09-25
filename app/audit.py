"""判定记录：线程安全地保存请求、版本与结论的对应关系。"""
from __future__ import annotations

import threading

from app.models import DecisionRecord


class DecisionLog:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: list[DecisionRecord] = []

    def append(self, record: DecisionRecord) -> None:
        with self._lock:
            self._records.append(record)

    def all(self) -> list[DecisionRecord]:
        with self._lock:
            return list(self._records)
