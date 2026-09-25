"""策略决策服务：组合存储、引擎与审计。"""
from __future__ import annotations

from app.audit import DecisionLog
from app.bundle import BundleStore
from app.engine import evaluate
from app.models import DecisionRecord, DecisionRequest, DecisionResult, PolicyBundle


class PolicyDecisionService:
    """离线策略决策服务。

    - decide() 先取一次版本快照，整个评估只使用该快照，保证版本一致；
    - 评估完成后将「请求 + 版本 + 结论」作为一条不可变记录写入日志，
      记录与结论天然一一对应，不会因并发更新而错配。
    """

    def __init__(self) -> None:
        self._store = BundleStore()
        self._log = DecisionLog()

    def update_bundle(self, raw: str | bytes) -> PolicyBundle:
        """原子更新策略包；解析或校验失败时旧版本继续生效。"""
        return self._store.load(raw)

    def decide(self, request: DecisionRequest) -> DecisionResult:
        bundle = self._store.snapshot()
        result = evaluate(bundle, request)
        self._log.append(DecisionRecord(request=request, result=result))
        return result

    def records(self) -> list[DecisionRecord]:
        return self._log.all()
