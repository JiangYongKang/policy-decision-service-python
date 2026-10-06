"""缺属性导致信息不足的评估语义：

- 缺属性时绝不放行，即使已有 allow 确定命中；
- 属性给了但值不符 = 条件明确不成立，不拖成信息不足；
- 缺失属性清单结构化、可程序化解析；
- 「无适用策略」与「缺属性」两类信息不足可区分。
"""
import pytest

from policy_service.audit import DecisionLog
from policy_service.bundle_loader import load_bundle
from policy_service.models import Decision, DecisionRequest, ReasonCode
from policy_service.service import PolicyDecisionService
from policy_service.store import PolicyStore

from .conftest import log_decision

# 一个不看条件的放行策略 + 一个要求 region=cn 的拒绝策略，
# 正是需求中给出的范例组合。
REGION_BUNDLE = {
    "version": "v-region",
    "policies": [
        {"id": "allow-all", "effect": "allow", "resource": "doc", "action": "read"},
        {
            "id": "deny-cn",
            "effect": "deny",
            "resource": "doc",
            "action": "read",
            "conditions": {"region": "cn"},
        },
    ],
}

# 多条规则分别依赖不同属性，用于校验跨规则属性清单聚合。
MULTI_BUNDLE = {
    "version": "v-multi",
    "policies": [
        {
            "id": "allow-eng",
            "effect": "allow",
            "resource": "doc",
            "action": "read",
            "conditions": {"dept": "eng"},
        },
        {
            "id": "deny-low",
            "effect": "deny",
            "resource": "doc",
            "action": "read",
            "conditions": {"region": "cn", "tier": "low"},
        },
    ],
}


@pytest.fixture
def region_service():
    return PolicyDecisionService(PolicyStore(load_bundle(REGION_BUNDLE)), DecisionLog())


@pytest.fixture
def multi_service():
    return PolicyDecisionService(PolicyStore(load_bundle(MULTI_BUNDLE)), DecisionLog())


def test_missing_attribute_blocks_allow_even_when_allow_matches(region_service):
    """缺 region：allow-all 已确定命中，但 deny-cn 无法评估，
    结论必须是信息不足 + 默认拒绝，绝不能放行。"""
    req = DecisionRequest(subject="alice", action="read", resource="doc")
    result = region_service.decide(req)
    log_decision(req, result)

    assert result.decision is Decision.INDETERMINATE
    assert result.allowed is False
    assert result.reason_code is ReasonCode.MISSING_ATTRIBUTES
    # allow-all 确实确定命中，但仍未放行
    assert [m.rule_id for m in result.matched] == ["allow-all"]
    assert result.required_attributes == ("region",)
    assert any("deny-cn" in r and "region" in r for r in result.reasons)
    assert any("不放行" in r for r in result.reasons)


def test_attribute_present_but_value_mismatch_allows_normally(region_service):
    """region=eu（值不符）：deny-cn 条件明确不成立，不应拖成信息不足，
    请求按 allow-all 正常放行。"""
    req = DecisionRequest(
        subject="alice", action="read", resource="doc", context={"region": "eu"}
    )
    result = region_service.decide(req)
    log_decision(req, result)

    assert result.decision is Decision.ALLOW
    assert result.allowed is True
    assert result.reason_code is ReasonCode.MATCHED_ALLOW
    assert result.missing_attributes == ()
    assert result.required_attributes == ()


def test_attribute_present_and_matching_triggers_deny(region_service):
    """region=cn：deny-cn 条件满足，显式拒绝优先。"""
    req = DecisionRequest(
        subject="alice", action="read", resource="doc", context={"region": "cn"}
    )
    result = region_service.decide(req)
    log_decision(req, result)

    assert result.decision is Decision.DENY
    assert result.allowed is False
    assert result.reason_code is ReasonCode.MATCHED_DENY
    assert result.required_attributes == ()


def test_missing_attributes_list_structured_and_aggregated(multi_service):
    """跨规则缺失属性清单：逐条证据（规则+属性）+ 去重并集。"""
    req = DecisionRequest(subject="alice", action="read", resource="doc")
    result = multi_service.decide(req)
    log_decision(req, result)

    assert result.decision is Decision.INDETERMINATE
    assert result.reason_code is ReasonCode.MISSING_ATTRIBUTES
    assert result.required_attributes == ("dept", "region", "tier")

    evidence = {(m.rule_id, m.attribute) for m in result.missing_attributes}
    assert evidence == {
        ("allow-eng", "dept"),
        ("deny-low", "region"),
        ("deny-low", "tier"),
    }


def test_partial_context_still_reports_only_truly_missing(multi_service):
    """给出的属性值相符时，只报真正还缺的属性；值不符的规则明确不命中。"""
    # dept=eng 满足 allow-eng；deny-low 的 region 给了但值不符 -> 明确不成立，
    # 只缺 tier 不影响（AND 已为假），因此 allow-eng 应正常放行。
    req = DecisionRequest(
        subject="alice",
        action="read",
        resource="doc",
        context={"dept": "eng", "region": "eu"},
    )
    result = multi_service.decide(req)
    log_decision(req, result)
    assert result.decision is Decision.ALLOW
    assert result.required_attributes == ()


def test_value_mismatch_and_missing_in_same_rule_is_not_met(multi_service):
    """同一规则：一个已给属性值不符、另一个缺失 —— AND 已确定为假，
    属于明确不成立，而非信息不足。"""
    req = DecisionRequest(
        subject="alice",
        action="read",
        resource="doc",
        context={"region": "eu"},  # region 不符（deny-low）；allow-eng 缺 dept
    )
    result = multi_service.decide(req)
    log_decision(req, result)
    # allow-eng 仍因缺 dept 信息不足，整体仍是 missing_attributes
    assert result.decision is Decision.INDETERMINATE
    assert result.reason_code is ReasonCode.MISSING_ATTRIBUTES
    # 证据里只能有 allow-eng/dept；deny-low 因 region 已明确不符，不产生缺失证据
    assert set(result.required_attributes) == {"dept"}
    assert all(
        m.rule_id != "deny-low" for m in result.missing_attributes
    )


def test_missing_attributes_indeterminate_distinct_from_no_applicable(
    multi_service,
):
    """两种「判不了」必须可区分：缺属性 vs 真的没有适用策略。"""
    # 1) 属性给全但都不符 -> 条件明确不成立 -> 无适用策略
    req_met = DecisionRequest(
        subject="alice",
        action="read",
        resource="doc",
        context={"dept": "sales", "region": "eu", "tier": "high"},
    )
    r_met = multi_service.decide(req_met)
    log_decision(req_met, r_met)
    assert r_met.decision is Decision.INDETERMINATE
    assert r_met.reason_code is ReasonCode.NO_APPLICABLE_POLICY
    assert r_met.missing_attributes == ()
    assert r_met.required_attributes == ()

    # 2) selector 根本不匹配 -> 同样是无适用策略
    req_selector = DecisionRequest(
        subject="alice",
        action="delete",
        resource="doc",
        context={},
    )
    r_sel = multi_service.decide(req_selector)
    log_decision(req_selector, r_sel)
    assert r_sel.reason_code is ReasonCode.NO_APPLICABLE_POLICY

    # 3) 属性缺失 -> missing_attributes
    req_miss = DecisionRequest(subject="alice", action="read", resource="doc")
    r_miss = multi_service.decide(req_miss)
    log_decision(req_miss, r_miss)
    assert r_miss.decision is Decision.INDETERMINATE
    assert r_miss.reason_code is ReasonCode.MISSING_ATTRIBUTES
    assert r_miss.required_attributes

    # 两者顶层结论相同，但 reason_code 不同，调用方可据此决定是否补属性重试
    assert r_met.decision is r_miss.decision
    assert r_met.reason_code is not r_miss.reason_code
