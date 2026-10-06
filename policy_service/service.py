"""决策服务：串联快照获取、评估与日志记录。"""
from __future__ import annotations

from .audit import DecisionLog
from .evaluator import evaluate
from .models import DecisionRequest, DecisionResult
from .store import PolicyStore


class NoPolicyBundleError(Exception):
    """尚未加载任何策略包时请求评估。"""


class PolicyDecisionService:
    """对每次评估固定使用同一策略版本快照。

    流程：先取快照 -> 基于该快照评估 -> 将请求、版本、结论一并写入日志。
    快照引用在评估期间不变，因此并发更新不会造成版本混杂；
    评估与记录在同一调用内完成，记录与结论不会错配。
    """

    def __init__(self, store: PolicyStore, log: DecisionLog) -> None:
        self._store = store
        self._log = log

    def decide(self, request: DecisionRequest) -> DecisionResult:
        bundle = self._store.snapshot()
        if bundle is None:
            raise NoPolicyBundleError("尚未加载策略包，无法评估")
        result = evaluate(bundle, request)
        self._log.record(request, result)
        return result
