"""决策引擎：综合命中策略，区分拒绝 / 允许 / 信息不足。

合并规则（针对同一资源命中的全部策略）：
1. 任一策略显式拒绝（条件全部满足）→ 结论为拒绝，优先级最高；
2. 否则，任一策略因请求缺少判定所需属性而无法判定 → 信息不足；
3. 否则，任一策略显式允许 → 允许；
4. 否则（没有任何策略适用）→ 信息不足。
信息不足视同不确定，绝不等同于允许；调用方应按默认拒绝处理。
"""
from __future__ import annotations

from enum import Enum

from app.models import Decision, DecisionRequest, DecisionResult, Effect, Policy, PolicyBundle


class _Applicability(Enum):
    APPLIES = "applies"
    NOT_APPLICABLE = "not_applicable"
    INDETERMINATE = "indeterminate"


def _matches(policy: Policy, request: DecisionRequest) -> bool:
    resource_ok = policy.resource == "*" or policy.resource == request.resource
    action_ok = policy.action == "*" or policy.action == request.action
    return resource_ok and action_ok


def _applicability(policy: Policy, request: DecisionRequest) -> tuple[_Applicability, str]:
    missing: list[str] = []
    for condition in policy.conditions:
        if condition.attribute not in request.attributes:
            missing.append(condition.attribute)
        elif request.attributes[condition.attribute] != condition.equals:
            return (
                _Applicability.NOT_APPLICABLE,
                f"策略 {policy.id}：条件 {condition.attribute}=={condition.equals!r} 不满足，不适用",
            )
    if missing:
        return (
            _Applicability.INDETERMINATE,
            f"策略 {policy.id}：请求缺少属性 {missing}，无法判定",
        )
    return _Applicability.APPLIES, f"策略 {policy.id}：条件全部满足，生效（{policy.effect.value}）"


def evaluate(bundle: PolicyBundle, request: DecisionRequest) -> DecisionResult:
    """基于同一策略包快照完成一次评估，保证版本一致。"""
    reasons: list[str] = []
    matched_ids: list[str] = []
    saw_deny = False
    saw_allow = False
    saw_indeterminate = False

    for policy in bundle.policies:
        if not _matches(policy, request):
            continue
        matched_ids.append(policy.id)
        applicability, reason = _applicability(policy, request)
        reasons.append(reason)
        if applicability is _Applicability.INDETERMINATE:
            saw_indeterminate = True
        elif applicability is _Applicability.APPLIES:
            if policy.effect is Effect.DENY:
                saw_deny = True
            else:
                saw_allow = True

    if saw_deny:
        decision = Decision.DENY
        reasons.append("存在显式拒绝策略，结论：拒绝（显式拒绝优先级最高）")
    elif saw_indeterminate:
        decision = Decision.INDETERMINATE
        reasons.append("存在无法判定的策略，信息不足，结论不确定（不等同于允许）")
    elif saw_allow:
        decision = Decision.ALLOW
        reasons.append("存在显式允许策略且无拒绝、无不确定项，结论：允许")
    else:
        decision = Decision.INDETERMINATE
        reasons.append("没有适用该请求的策略，信息不足，结论不确定（不等同于允许）")

    return DecisionResult(
        decision=decision,
        reasons=tuple(reasons),
        policy_version=bundle.version,
        matched_policy_ids=tuple(matched_ids),
    )
