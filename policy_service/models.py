"""策略决策服务的核心数据类型定义。"""
from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Effect(str, Enum):
    """策略效果：允许或显式拒绝。"""

    ALLOW = "allow"
    DENY = "deny"


class Decision(str, Enum):
    """最终判定结论。"""

    ALLOW = "allow"                  # 至少一条允许且无显式拒绝
    DENY = "deny"                    # 存在显式拒绝（优先级最高）
    INDETERMINATE = "indeterminate"  # 信息不足，无法判定（不等同于允许）


@dataclass(frozen=True)
class PolicyRule:
    """单条策略规则。"""

    rule_id: str
    effect: Effect
    resource: str
    action: str
    subject: str = "*"
    conditions: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PolicyBundle:
    """不可变的策略包快照，评估期间整体引用以保证版本一致。"""

    version: str
    rules: tuple[PolicyRule, ...]


@dataclass(frozen=True)
class DecisionRequest:
    """一次授权请求输入。"""

    subject: str
    action: str
    resource: str
    context: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class MatchedRule:
    """评估过程中命中的规则及其贡献。"""

    rule_id: str
    effect: Effect
    reason: str


@dataclass(frozen=True)
class DecisionResult:
    """评估输出：结论 + 可读判定依据 + 所用策略版本。"""

    decision: Decision
    allowed: bool
    reasons: tuple[str, ...]
    matched: tuple[MatchedRule, ...]
    policy_version: str


@dataclass(frozen=True)
class DecisionRecord:
    """可追溯的判定记录。"""

    record_id: str
    timestamp: float
    request: DecisionRequest
    result: DecisionResult

    @staticmethod
    def new(request: DecisionRequest, result: DecisionResult) -> "DecisionRecord":
        return DecisionRecord(
            record_id=uuid.uuid4().hex,
            timestamp=time.time(),
            request=request,
            result=result,
        )
