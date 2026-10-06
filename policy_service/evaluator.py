"""评估器：综合同一资源相关的全部策略得出可解释结论。

单条规则的三态评估：
- 命中：资源/动作/主体匹配，且条件引用的属性齐全且全部相等；
- 明确不命中：目标字段不匹配，或某个**已提供**的属性值与期望值不一致
  （条件明确不成立，补齐别的属性也不会改变结论）；
- 无法评估：目标字段匹配，但条件引用的属性在请求中缺失——
  补齐之后该规则可能命中，不能当成不命中放行。

合并优先级（deny-overrides，并保证缺属性绝不放行）：
1. 任一规则明确命中 deny：最终 deny（显式拒绝优先级最高，即使同时命中 allow）；
2. 否则，任一规则因缺属性无法评估：indeterminate/missing_attributes，
   默认拒绝，并在 missing_attributes 中给出按策略归集的补属性清单；
3. 否则，至少一条规则明确命中 allow：allow；
4. 否则：indeterminate/no_applicable_policy（确实没有任何适用策略）。
"""
from __future__ import annotations

from enum import Enum

from .models import (
    Decision,
    DecisionRequest,
    DecisionResult,
    Effect,
    IndeterminateReason,
    MatchedRule,
    MissingAttribute,
    MissingAttributesEntry,
    PolicyBundle,
    PolicyRule,
)


class _RuleStatus(Enum):
    MATCH = "match"
    NOT_MATCH = "not_match"
    INDETERMINATE = "indeterminate"


def evaluate(bundle: PolicyBundle, request: DecisionRequest) -> DecisionResult:
    """基于同一策略包快照评估请求。"""
    matched: list[PolicyRule] = []
    indeterminate: list[tuple[PolicyRule, tuple[MissingAttribute, ...]]] = []

    for rule in bundle.rules:
        status, missing = _evaluate_rule(rule, request)
        if status is _RuleStatus.MATCH:
            matched.append(rule)
        elif status is _RuleStatus.INDETERMINATE:
            indeterminate.append((rule, missing))

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
    missing_view = tuple(
        MissingAttributesEntry(
            rule_id=r.rule_id,
            effect=r.effect,
            missing=missing,
        )
        for r, missing in indeterminate
    )

    reasons: list[str] = []
    decision: Decision
    indeterminate_reason: IndeterminateReason | None = None

    if denies:
        decision = Decision.DENY
        ids = "、".join(r.rule_id for r in denies)
        reasons.append(f"命中显式拒绝规则 {ids}，显式拒绝优先级最高")
        if allows:
            allow_ids = "、".join(r.rule_id for r in allows)
            reasons.append(f"同时命中允许规则 {allow_ids}，冲突按拒绝处理")
    elif indeterminate:
        decision = Decision.INDETERMINATE
        indeterminate_reason = IndeterminateReason.MISSING_ATTRIBUTES
        for rule, missing in indeterminate:
            keys = "、".join(
                f"{item.key}（期望值 {item.expected!r}）" for item in missing
            )
            reasons.append(
                f"规则 {rule.rule_id}（{rule.effect.value}）缺少属性无法评估："
                f"{keys}；信息不足，默认拒绝，补齐属性后可重试"
            )
    elif allows:
        decision = Decision.ALLOW
        ids = "、".join(r.rule_id for r in allows)
        reasons.append(f"命中允许规则 {ids}，且无显式拒绝")
    else:
        decision = Decision.INDETERMINATE
        indeterminate_reason = IndeterminateReason.NO_APPLICABLE_POLICY
        reasons.append("无任何适用策略，信息不足，无法判定（默认按拒绝处理）")

    # 即便显式拒绝已经定论，仍把缺属性策略写进依据，保证可追溯
    if denies and indeterminate:
        for rule, missing in indeterminate:
            keys = "、".join(item.key for item in missing)
            reasons.append(
                f"另有规则 {rule.rule_id}（{rule.effect.value}）因缺少属性 "
                f"{keys} 无法评估，不影响本次显式拒绝结论"
            )

    return DecisionResult(
        decision=decision,
        allowed=decision is Decision.ALLOW,
        reasons=tuple(reasons),
        matched=matched_view,
        policy_version=bundle.version,
        indeterminate_reason=indeterminate_reason,
        missing_attributes=missing_view,
    )


def _evaluate_rule(
    rule: PolicyRule, request: DecisionRequest
) -> tuple[_RuleStatus, tuple[MissingAttribute, ...]]:
    """三态评估单条规则，无法评估时一并返回缺失属性。"""
    if not (
        _match_field(rule.resource, request.resource)
        and _match_field(rule.action, request.action)
        and _match_field(rule.subject, request.subject)
    ):
        return _RuleStatus.NOT_MATCH, ()

    # 条件是 AND 关系：任一已提供属性明确不符，整条规则即明确不成立，
    # 即使其它属性缺失也无需再报缺失。
    missing: list[MissingAttribute] = []
    for key, expected in rule.conditions.items():
        if key not in request.context:
            missing.append(MissingAttribute(key=key, expected=expected))
        elif request.context[key] != expected:
            return _RuleStatus.NOT_MATCH, ()

    if missing:
        return _RuleStatus.INDETERMINATE, tuple(missing)
    return _RuleStatus.MATCH, ()


def _match_field(pattern: str, value: str) -> bool:
    return pattern == "*" or pattern == value


def _rule_reason(rule: PolicyRule, request: DecisionRequest) -> str:
    parts = [
        (
            f"规则 {rule.rule_id}（{rule.effect.value}）命中 "
            f"subject={request.subject} action={request.action} resource={request.resource}"
        )
    ]
    if rule.conditions:
        parts.append(f"条件 {rule.conditions} 均满足")
    return "，".join(parts)
