"""评估器：综合命中同一资源的全部策略得出可解释结论。

合并规则：
- 显式拒绝（deny）优先级最高：任一命中 deny 即最终拒绝；
- 无 deny 且至少一条 allow：允许；
- 无任何规则命中：信息不足（indeterminate），不等同于允许，
  服务层按默认拒绝处理，但结论与显式拒绝可区分。
"""
from __future__ import annotations

from typing import Any

from .models import (
    Decision,
    DecisionRequest,
    DecisionResult,
    Effect,
    MatchedRule,
    PolicyBundle,
    PolicyRule,
)


def evaluate(bundle: PolicyBundle, request: DecisionRequest) -> DecisionResult:
    """基于同一策略包快照评估请求。"""
    matched = [
        rule for rule in bundle.rules if _matches(rule, request)
    ]

    denies = [r for r in matched if r.effect is Effect.DENY]
    allows = [r for r in matched if r.effect is Effect.ALLOW]

    matched_view = tuple(
        MatchedRule(
            rule_id=r.rule_id,
            effect=r.effect,
            reason=_rule_reason(r, request),
        )
        for r in matched
    )

    reasons: list[str] = []
    if denies:
        decision = Decision.DENY
        ids = "、".join(r.rule_id for r in denies)
        reasons.append(f"命中显式拒绝规则 {ids}，显式拒绝优先级最高")
        if allows:
            allow_ids = "、".join(r.rule_id for r in allows)
            reasons.append(f"同时命中允许规则 {allow_ids}，冲突按拒绝处理")
    elif allows:
        decision = Decision.ALLOW
        ids = "、".join(r.rule_id for r in allows)
        reasons.append(f"命中允许规则 {ids}，且无显式拒绝")
    else:
        decision = Decision.INDETERMINATE
        reasons.append("无任何策略命中，信息不足，无法判定（默认按拒绝处理）")

    return DecisionResult(
        decision=decision,
        allowed=decision is Decision.ALLOW,
        reasons=tuple(reasons),
        matched=matched_view,
        policy_version=bundle.version,
    )


def _matches(rule: PolicyRule, request: DecisionRequest) -> bool:
    return (
        _match_field(rule.resource, request.resource)
        and _match_field(rule.action, request.action)
        and _match_field(rule.subject, request.subject)
        and _match_conditions(rule.conditions, request.context)
    )


def _match_field(pattern: str, value: str) -> bool:
    return pattern == "*" or pattern == value


def _match_conditions(conditions: dict[str, Any], context: dict[str, Any]) -> bool:
    """条件全部满足才命中；请求上下文缺失对应键则视为不满足。"""
    for key, expected in conditions.items():
        if key not in context or context[key] != expected:
            return False
    return True


def _rule_reason(rule: PolicyRule, request: DecisionRequest) -> str:
    parts = [
        f"规则 {rule.rule_id}（{rule.effect.value}）命中 "
        f"subject={request.subject} action={request.action} resource={request.resource}"
    ]
    if rule.conditions:
        parts.append(f"条件 {rule.conditions} 均满足")
    return "，".join(parts)
