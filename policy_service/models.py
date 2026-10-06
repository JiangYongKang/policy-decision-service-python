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


class IndeterminateReason(str, Enum):
    """indeterminate 的两类成因，调用方可据此决定是否补属性重试。"""

    NO_APPLICABLE_POLICY = "no_applicable_policy"  # 确实没有任何适用策略
    MISSING_ATTRIBUTES = "missing_attributes"      # 有策略本可适用，但请求缺属性，补齐或可判定


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
class MissingAttribute:
    """单个缺失属性：键名 + 该策略期望的值（便于调用方补齐）。"""

    key: str
    expected: Any


@dataclass(frozen=True)
class MissingAttributesEntry:
    """按策略归集的缺失属性清单：说明请求被哪条策略、缺了哪些属性卡住。"""

    rule_id: str
    effect: Effect
    missing: tuple[MissingAttribute, ...]


@dataclass(frozen=True)
class DecisionResult:
    """评估输出：结论 + 可读判定依据 + 所用策略版本。

    indeterminate 时 indeterminate_reason 区分两类成因：
    - NO_APPLICABLE_POLICY：没有任何适用策略；
    - MISSING_ATTRIBUTES：有策略因缺属性无法评估，missing_attributes
      给出结构化的补属性清单，两种情况下 allowed 均为 False。
    """

    decision: Decision
    allowed: bool
    reasons: tuple[str, ...]
    matched: tuple[MatchedRule, ...]
    policy_version: str
    indeterminate_reason: IndeterminateReason | None = None
    missing_attributes: tuple[MissingAttributesEntry, ...] = ()

    def required_attribute_keys(self) -> tuple[str, ...]:
        """所有卡住策略要求补齐的属性键（去重、保序），供调用方直接取用。"""
        seen: dict[str, None] = {}
        for entry in self.missing_attributes:
            for item in entry.missing:
                seen.setdefault(item.key, None)
        return tuple(seen.keys())


@dataclass(frozen=True)
class DecisionRecord:
    """可追溯的判定记录。"""

    record_id: str
    timestamp: float
    request: DecisionRequest
    result: DecisionResult

    @staticmethod
    def new(request: DecisionRequest, result: DecisionResult) -> DecisionRecord:
        return DecisionRecord(
            record_id=uuid.uuid4().hex,
            timestamp=time.time(),
            request=request,
            result=result,
        )
