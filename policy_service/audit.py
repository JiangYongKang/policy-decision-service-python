"""判定日志：记录请求输入、策略版本与结论，线程安全。"""
from __future__ import annotations

import threading

from .models import DecisionRecord, DecisionRequest, DecisionResult


class DecisionLog:
    """追加式判定记录存储。

    记录在服务层完成评估后原子追加，保证记录与结论一一对应，
    并发评估与策略更新不会导致记录丢失或错配。
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: list[DecisionRecord] = []

    def record(self, request: DecisionRequest, result: DecisionResult) -> DecisionRecord:
        entry = DecisionRecord.new(request=request, result=result)
        with self._lock:
            self._records.append(entry)
        return entry

    def all(self) -> list[DecisionRecord]:
        with self._lock:
            return list(self._records)
