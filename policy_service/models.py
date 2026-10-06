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
    INDETERMINATE = "indeterminate"  # 判不了（不等同于允许，默认拒绝）


class ReasonCode(str, Enum):
    """判定依据的机器可读代码，细分两种「判不了」。

    - matched_allow / matched_deny：属性给全后的常规结论；
    - no_applicable_policy：真的没有任何适用策略，补属性也没用；
    - missing_attributes：有适用策略，但所需属性缺失，补齐后可重新评估。
    """

    MATCHED_ALLOW = "matched_allow"
    MATCHED_DENY = "matched_deny"
    NO_APPLICABLE_POLICY = "no_applicable_policy"
    MISSING_ATTRIBUTES = "missing_attributes"


@dataclass(frozen=True)
class MissingAttribute:
    """一条「信息不足」证据：规则 rule_id 评估时缺少属性 attribute。"""

    rule_id: str
    attribute: str


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
    """评估输出：结论 + 可读判定依据 + 所用策略版本。

    - reason_code：机器可读的判定依据代码，可区分两种信息不足；
    - missing_attributes：信息不足（缺属性）时，被卡住的规则及所缺属性
      的结构化清单，供调用方补齐后重试；其他结论下为空元组；
    - required_attributes：去重后的缺失属性名清单（取并集，方便直接回填）。
    """

    decision: Decision
    allowed: bool
    reasons: tuple[str, ...]
    matched: tuple[MatchedRule, ...]
    policy_version: str
    reason_code: ReasonCode | None = None
    missing_attributes: tuple[MissingAttribute, ...] = ()
    required_attributes: tuple[str, ...] = ()


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
