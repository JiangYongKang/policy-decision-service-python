"""评估器：综合命中同一资源的全部策略得出可解释结论。

每条 selector（resource/action/subject）适用的规则，其条件评估有三种结果：
- 条件全部满足：规则确定命中；
- 已给出的属性中有值与要求不符：条件明确不成立，规则确定不命中；
- 已给出的属性都相符，但仍有条件属性缺失：条件无法评估，规则处于
  「信息不足」状态，补齐属性后可能命中也可能不命中。

合并规则（按优先级）：
1. 只要存在信息不足的适用规则：结论即 indeterminate + 默认拒绝，
   即使同时有确定命中的 allow/deny 也绝不放行——缺资料时不允许放行；
2. 显式拒绝（deny）优先级最高：任一确定命中 deny 即最终拒绝；
3. 无 deny 且至少一条 allow 确定命中：允许；
4. 连一条适用规则都没有（selector 不匹配，或条件均明确不成立）：
   indeterminate，但原因为 no_applicable_policy，与缺属性情形可区分。
"""
from __future__ import annotations

from typing import Any

from .models import (
    Decision,
    DecisionRequest,
    DecisionResult,
    Effect,
    MatchedRule,
    MissingAttribute,
    PolicyBundle,
    PolicyRule,
    ReasonCode,
)

# 条件评估三态中的两个哨兵
_SATISFIED = "satisfied"  # 条件全部满足，规则确定命中
_NOT_MET = "not_met"      # 已给属性中存在值不符，明确不成立


def evaluate(bundle: PolicyBundle, request: DecisionRequest) -> DecisionResult:
    """基于同一策略包快照评估请求。"""
    matched: list[PolicyRule] = []
    # 信息不足的适用规则及其缺少的条件属性（保持策略包内顺序）
    indeterminate: list[tuple[PolicyRule, tuple[str, ...]]] = []

    for rule in bundle.rules:
        if not _selectors_match(rule, request):
            continue
        outcome = _evaluate_conditions(rule.conditions, request.context)
        if outcome is _SATISFIED:
            matched.append(rule)
        elif outcome is _NOT_MET:
            continue
        else:
            indeterminate.append((rule, outcome))

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

    if indeterminate:
        missing, required = _missing_view(indeterminate)
        stuck_ids = "、".join(rule.rule_id for rule, _ in indeterminate)
        attr_names = "、".join(required)
        reasons = [
            (
                f"适用规则 {stuck_ids} 缺少属性 {attr_names}，信息不足无法判定，"
                "默认按拒绝处理（缺资料不放行）"
            )
        ]
        for rule, keys in indeterminate:
            reasons.append(
                f"规则 {rule.rule_id}（{rule.effect.value}）缺少属性: "
                + "、".join(keys)
            )
        if matched:
            hit_ids = "、".join(r.rule_id for r in matched)
            reasons.append(
                f"尽管规则 {hit_ids} 已确定命中，但存在信息不足的适用规则，"
                "结论仍为信息不足 + 默认拒绝"
            )
        return DecisionResult(
            decision=Decision.INDETERMINATE,
            allowed=False,
            reasons=tuple(reasons),
            matched=matched_view,
            policy_version=bundle.version,
            reason_code=ReasonCode.MISSING_ATTRIBUTES,
            missing_attributes=missing,
            required_attributes=required,
        )

    reasons: list[str] = []
    if denies:
        decision = Decision.DENY
        reason_code = ReasonCode.MATCHED_DENY
        ids = "、".join(r.rule_id for r in denies)
        reasons.append(f"命中显式拒绝规则 {ids}，显式拒绝优先级最高")
        if allows:
            allow_ids = "、".join(r.rule_id for r in allows)
            reasons.append(f"同时命中允许规则 {allow_ids}，冲突按拒绝处理")
    elif allows:
        decision = Decision.ALLOW
        reason_code = ReasonCode.MATCHED_ALLOW
        ids = "、".join(r.rule_id for r in allows)
        reasons.append(f"命中允许规则 {ids}，且无显式拒绝")
    else:
        decision = Decision.INDETERMINATE
        reason_code = ReasonCode.NO_APPLICABLE_POLICY
        reasons.append(
            "无任何适用策略（无 selector 匹配的规则，或其条件均明确不成立），"
            "信息不足，无法判定（默认按拒绝处理）"
        )

    return DecisionResult(
        decision=decision,
        allowed=decision is Decision.ALLOW,
        reasons=tuple(reasons),
        matched=matched_view,
        policy_version=bundle.version,
        reason_code=reason_code,
    )


def _missing_view(
    indeterminate: list[tuple[PolicyRule, tuple[str, ...]]],
) -> tuple[tuple[MissingAttribute, ...], tuple[str, ...]]:
    """生成结构化缺失清单：逐条证据 + 去重后的属性名并集（按首次出现顺序）。"""
    details = tuple(
        MissingAttribute(rule_id=rule.rule_id, attribute=key)
        for rule, keys in indeterminate
        for key in keys
    )
    required = tuple(dict.fromkeys(item.attribute for item in details))
    return details, required


def _selectors_match(rule: PolicyRule, request: DecisionRequest) -> bool:
    return (
        _match_field(rule.resource, request.resource)
        and _match_field(rule.action, request.action)
        and _match_field(rule.subject, request.subject)
    )


def _evaluate_conditions(
    conditions: dict[str, Any], context: dict[str, Any]
) -> str | tuple[str, ...]:
    """评估条件，返回三态：

    - _SATISFIED：所有条件键都存在且相等（含无条件）；
    - _NOT_MET：已给出的键中存在值不符——条件明确不成立，
      其余键是否缺失不再影响结论（AND 已确定为假）；
    - 元组：已给出的键都相符但仍有键缺失，返回缺失键名（无法评估）。
    """
    missing: list[str] = []
    for key, expected in conditions.items():
        if key not in context:
            missing.append(key)
        elif context[key] != expected:
            return _NOT_MET
    if missing:
        return tuple(missing)
    return _SATISFIED


def _match_field(pattern: str, value: str) -> bool:
    return pattern == "*" or pattern == value


def _rule_reason(rule: PolicyRule, request: DecisionRequest) -> str:
    parts = [
        f"规则 {rule.rule_id}（{rule.effect.value}）命中 "
        f"subject={request.subject} action={request.action} resource={request.resource}"
    ]
    if rule.conditions:
        parts.append(f"条件 {rule.conditions} 均满足")
    return "，".join(parts)
