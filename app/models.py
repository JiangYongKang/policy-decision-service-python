"""核心数据类型定义。"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Effect(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    INDETERMINATE = "indeterminate"


@dataclass(frozen=True)
class Condition:
    """对请求属性的等值匹配条件；属性缺失时该条件无法判定。"""

    attribute: str
    equals: Any


@dataclass(frozen=True)
class Policy:
    id: str
    resource: str
    action: str
    effect: Effect
    conditions: tuple[Condition, ...] = ()


@dataclass(frozen=True)
class PolicyBundle:
    version: str
    policies: tuple[Policy, ...]


@dataclass(frozen=True)
class DecisionRequest:
    subject: str
    action: str
    resource: str
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class DecisionResult:
    decision: Decision
    reasons: tuple[str, ...]
    policy_version: str
    matched_policy_ids: tuple[str, ...]


@dataclass(frozen=True)
class DecisionRecord:
    request: DecisionRequest
    result: DecisionResult
    timestamp: float = field(default_factory=time.time)
