"""缺属性导致「信息不足」的判定语义测试。

覆盖：
- 缺属性绝不放行（即使存在无条件放行策略）；
- 属性已给但值不符属于明确不命中，请求正常放行；
- 缺失属性清单结构化、按策略归集、可程序化解析；
- 两类信息不足（无适用策略 / 缺属性）可区分；
- 显式拒绝定论时缺属性策略仍可追溯；
- HTTP 响应与审计记录暴露新字段，且结论绑定单一策略版本。
"""
import pytest
from fastapi.testclient import TestClient

from policy_service.app import create_app
from policy_service.audit import DecisionLog
from policy_service.bundle_loader import load_bundle
from policy_service.models import Decision, DecisionRequest, IndeterminateReason
from policy_service.service import PolicyDecisionService
from policy_service.store import PolicyStore

from .conftest import log_decision

# 无条件放行 + region=cn 的条件拒绝 + 双条件条件放行
BUNDLE_GUARD = {
    "version": "v-guard",
    "policies": [
        {"id": "allow-read", "effect": "allow", "resource": "doc", "action": "read"},
        {
            "id": "deny-region-cn",
            "effect": "deny",
            "resource": "doc",
            "action": "read",
            "conditions": {"region": "cn"},
        },
        {
            "id": "allow-write-eng-gold",
            "effect": "allow",
            "resource": "doc",
            "action": "write",
            "conditions": {"dept": "eng", "tier": "gold"},
        },
    ],
}


@pytest.fixture
def guard_service() -> PolicyDecisionService:
    store = PolicyStore(load_bundle(BUNDLE_GUARD))
    return PolicyDecisionService(store, DecisionLog())


def _read_req(**context) -> DecisionRequest:
    return DecisionRequest(
        subject="alice", action="read", resource="doc", context=dict(context)
    )


def test_missing_attribute_is_never_allowed(guard_service):
    """存在无条件放行策略，但拒绝策略缺 region 无法评估 -> 不放行。"""
    req = _read_req()  # 不带 region
    result = guard_service.decide(req)
    log_decision(req, result)

    assert result.decision is Decision.INDETERMINATE
    assert result.allowed is False
    assert result.indeterminate_reason is IndeterminateReason.MISSING_ATTRIBUTES
    assert result.policy_version == "v-guard"
    assert [e.rule_id for e in result.missing_attributes] == ["deny-region-cn"]
    missing = result.missing_attributes[0].missing
    assert [(m.key, m.expected) for m in missing] == [("region", "cn")]
    assert result.required_attribute_keys() == ("region",)
    assert any("信息不足" in r and "deny-region-cn" in r for r in result.reasons)


def test_wrong_attribute_value_still_allows(guard_service):
    """region=eu 与条件要求不符 -> 拒绝策略明确不命中，放行策略照常放行。"""
    req = _read_req(region="eu")
    result = guard_service.decide(req)
    log_decision(req, result)

    assert result.decision is Decision.ALLOW
    assert result.allowed is True
    assert result.indeterminate_reason is None
    assert result.missing_attributes == ()


def test_correct_value_triggers_explicit_deny(guard_service):
    """对照组：region=cn 条件成立 -> 显式拒绝优先于放行。"""
    req = _read_req(region="cn")
    result = guard_service.decide(req)
    log_decision(req, result)

    assert result.decision is Decision.DENY
    assert result.allowed is False
    assert result.missing_attributes == ()


def test_missing_attributes_list_is_structured_and_complete(guard_service):
    """多条件全缺：按策略给出每个缺失键及期望值，合并键去重保序。"""
    req = DecisionRequest(subject="alice", action="write", resource="doc")
    result = guard_service.decide(req)
    log_decision(req, result)

    assert result.decision is Decision.INDETERMINATE
    assert result.indeterminate_reason is IndeterminateReason.MISSING_ATTRIBUTES
    entry = result.missing_attributes[0]
    assert entry.rule_id == "allow-write-eng-gold"
    assert entry.effect.value == "allow"
    assert [(m.key, m.expected) for m in entry.missing] == [
        ("dept", "eng"),
        ("tier", "gold"),
    ]
    assert result.required_attribute_keys() == ("dept", "tier")


def test_only_truly_missing_keys_are_reported(guard_service):
    """补了 dept 但缺 tier：清单只列 tier。"""
    req = DecisionRequest(
        subject="alice", action="write", resource="doc", context={"dept": "eng"}
    )
    result = guard_service.decide(req)
    log_decision(req, result)

    assert result.indeterminate_reason is IndeterminateReason.MISSING_ATTRIBUTES
    assert [(m.key, m.expected) for m in result.missing_attributes[0].missing] == [
        ("tier", "gold")
    ]
    assert result.required_attribute_keys() == ("tier",)


def test_explicit_mismatch_beats_missing_other_key(guard_service):
    """dept 值明确不符，即使 tier 缺失，该规则也属明确不命中，
    不拖成缺属性信息不足 -> 落到无适用策略。"""
    req = DecisionRequest(
        subject="alice", action="write", resource="doc", context={"dept": "sales"}
    )
    result = guard_service.decide(req)
    log_decision(req, result)

    assert result.decision is Decision.INDETERMINATE
    assert result.indeterminate_reason is IndeterminateReason.NO_APPLICABLE_POLICY
    assert result.missing_attributes == ()
    assert result.allowed is False


def test_two_kinds_of_indeterminate_are_distinguishable(guard_service):
    """无适用策略 vs 缺属性：结论同为 indeterminate，但成因可区分。"""
    missing_req = _read_req()  # 拒绝策略缺 region
    missing_result = guard_service.decide(missing_req)
    log_decision(missing_req, missing_result)

    none_req = DecisionRequest(subject="alice", action="delete", resource="doc")
    none_result = guard_service.decide(none_req)
    log_decision(none_req, none_result)

    assert missing_result.decision is none_result.decision is Decision.INDETERMINATE
    assert (
        missing_result.indeterminate_reason
        is IndeterminateReason.MISSING_ATTRIBUTES
    )
    assert (
        none_result.indeterminate_reason
        is IndeterminateReason.NO_APPLICABLE_POLICY
    )
    # 序列化为可程序化解析的稳定字符串值，且互不相同
    assert missing_result.indeterminate_reason.value == "missing_attributes"
    assert none_result.indeterminate_reason.value == "no_applicable_policy"
    assert missing_result.missing_attributes  # 缺属性：有清单
    assert none_result.missing_attributes == ()  # 无策略：清单为空


def test_deny_conclusion_keeps_indeterminate_rules_traceable():
    """明确 deny 定论时，另一条因缺属性无法评估的规则仍出现在依据与清单中。"""
    bundle = load_bundle({
        "version": "v-mix",
        "policies": [
            {"id": "deny-secret", "effect": "deny",
             "resource": "secret", "action": "read"},
            {"id": "allow-secret-dept", "effect": "allow",
             "resource": "secret", "action": "read",
             "conditions": {"dept": "eng"}},
        ],
    })
    service = PolicyDecisionService(PolicyStore(bundle), DecisionLog())
    req = DecisionRequest(subject="alice", action="read", resource="secret")
    result = service.decide(req)
    log_decision(req, result)

    assert result.decision is Decision.DENY  # 显式拒绝优先，结论不被拖成信息不足
    assert result.indeterminate_reason is None
    assert [e.rule_id for e in result.missing_attributes] == ["allow-secret-dept"]
    assert any("allow-secret-dept" in r and "dept" in r for r in result.reasons)


def test_indeterminate_result_bound_to_single_snapshot_version():
    """缺属性结论绑定评估时的版本；更新后旧结论对象不被新版本污染。"""
    store = PolicyStore(load_bundle(BUNDLE_GUARD))
    service = PolicyDecisionService(store, DecisionLog())
    req = _read_req()
    old = service.decide(req)
    log_decision(req, old)
    assert old.policy_version == "v-guard"
    assert old.decision is Decision.INDETERMINATE

    store.update(load_bundle({
        "version": "v-next",
        "policies": [
            {"id": "deny-read", "effect": "deny",
             "resource": "doc", "action": "read"},
        ],
    }))
    new = service.decide(req)
    log_decision(req, new)
    assert new.policy_version == "v-next"
    assert new.decision is Decision.DENY
    # 旧结论对象不可变，未被新版本污染
    assert old.policy_version == "v-guard"
    assert old.decision is Decision.INDETERMINATE


@pytest.fixture
def client():
    return TestClient(create_app())


def test_api_exposes_structured_missing_attributes(client):
    resp = client.post("/policies", json={"bundle": BUNDLE_GUARD})
    assert resp.status_code == 200

    # 缺属性：结构化清单可直接被调用方解析并补齐重试
    resp = client.post("/decide", json={
        "subject": "alice", "action": "read", "resource": "doc"})
    body = resp.json()
    print(f"\n[api-log] missing-attributes response={body}")
    assert resp.status_code == 200
    assert body["decision"] == "indeterminate"
    assert body["allowed"] is False
    assert body["policy_version"] == "v-guard"
    assert body["indeterminate_reason"] == "missing_attributes"
    assert body["missing_attributes"] == [
        {
            "rule_id": "deny-region-cn",
            "effect": "deny",
            "missing": [{"key": "region", "expected": "cn"}],
        }
    ]

    # 补齐且值不符的正常放行请求不带缺属性信息
    resp = client.post("/decide", json={
        "subject": "alice", "action": "read", "resource": "doc",
        "context": {"region": "eu"}})
    ok_body = resp.json()
    print(f"[api-log] wrong-value response={ok_body}")
    assert ok_body["decision"] == "allow"
    assert ok_body["indeterminate_reason"] is None
    assert ok_body["missing_attributes"] == []

    # 无适用策略：成因与缺属性不同
    resp = client.post("/decide", json={
        "subject": "alice", "action": "delete", "resource": "doc"})
    none_body = resp.json()
    print(f"[api-log] no-policy response={none_body}")
    assert none_body["decision"] == "indeterminate"
    assert none_body["indeterminate_reason"] == "no_applicable_policy"
    assert none_body["missing_attributes"] == []


def test_api_audit_record_contains_missing_attributes(client):
    client.post("/policies", json={"bundle": BUNDLE_GUARD})
    client.post("/decide", json={
        "subject": "alice", "action": "read", "resource": "doc"})
    records = client.get("/audit").json()
    rec = records[0]
    print(f"\n[api-log] audit missing-attributes record={rec}")
    assert rec["policy_version"] == "v-guard"
    assert rec["decision"] == "indeterminate"
    assert rec["indeterminate_reason"] == "missing_attributes"
    assert rec["missing_attributes"][0]["rule_id"] == "deny-region-cn"
    assert rec["missing_attributes"][0]["missing"][0]["key"] == "region"
