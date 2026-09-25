"""策略决策服务测试：冲突合并、版本稳定性、非法策略包拒绝。"""
from __future__ import annotations

import json
import threading

import pytest

from app.errors import BundleParseError, BundleValidationError
from app.models import Decision, DecisionRequest
from app.service import PolicyDecisionService

BUNDLE_V1 = {
    "version": "v1",
    "policies": [
        {"id": "allow-read-doc", "resource": "doc:1", "action": "read", "effect": "allow"},
        {
            "id": "deny-intern-delete",
            "resource": "doc:1",
            "action": "delete",
            "effect": "deny",
            "conditions": [{"attribute": "role", "equals": "intern"}],
        },
        {
            "id": "allow-delete-admin",
            "resource": "doc:1",
            "action": "delete",
            "effect": "allow",
            "conditions": [{"attribute": "role", "equals": "admin"}],
        },
    ],
}

BUNDLE_V2 = {
    "version": "v2",
    "policies": [
        {"id": "deny-read-doc", "resource": "doc:1", "action": "read", "effect": "deny"},
    ],
}


def make_service(bundle=BUNDLE_V1) -> PolicyDecisionService:
    service = PolicyDecisionService()
    service.update_bundle(json.dumps(bundle))
    return service


def log_result(tag: str, request: DecisionRequest, result) -> None:
    print(f"\n[{tag}] 请求输入: {request}")
    print(f"[{tag}] 命中策略版本: {result.policy_version}, 命中策略: {result.matched_policy_ids}")
    print(f"[{tag}] 结论: {result.decision.value}")
    for reason in result.reasons:
        print(f"[{tag}] 判定依据: {reason}")


# ---------- 冲突与不确定性 ----------

def test_explicit_deny_beats_allow():
    service = make_service()
    # 同一请求同时命中显式允许与显式拒绝
    bundle = {
        "version": "conflict",
        "policies": [
            {"id": "a", "resource": "r", "action": "read", "effect": "allow"},
            {"id": "d", "resource": "r", "action": "read", "effect": "deny"},
        ],
    }
    service.update_bundle(json.dumps(bundle))
    req = DecisionRequest(subject="u1", action="read", resource="r")
    result = service.decide(req)
    log_result("deny-beats-allow", req, result)
    assert result.decision is Decision.DENY
    assert set(result.matched_policy_ids) == {"a", "d"}


def test_allow_when_only_allow_applies():
    service = make_service()
    req = DecisionRequest(subject="u1", action="read", resource="doc:1")
    result = service.decide(req)
    log_result("allow", req, result)
    assert result.decision is Decision.ALLOW
    assert result.policy_version == "v1"


def test_missing_attribute_is_indeterminate_not_allow():
    service = make_service()
    # delete 请求命中两条带条件策略，但请求未提供 role 属性
    req = DecisionRequest(subject="u1", action="delete", resource="doc:1")
    result = service.decide(req)
    log_result("indeterminate-missing-attr", req, result)
    assert result.decision is Decision.INDETERMINATE
    assert result.decision is not Decision.ALLOW


def test_no_applicable_policy_is_indeterminate():
    service = make_service()
    req = DecisionRequest(subject="u1", action="write", resource="doc:9")
    result = service.decide(req)
    log_result("indeterminate-no-policy", req, result)
    assert result.decision is Decision.INDETERMINATE


def test_condition_satisfied_deny():
    service = make_service()
    req = DecisionRequest(subject="u1", action="delete", resource="doc:1", attributes={"role": "intern"})
    result = service.decide(req)
    log_result("deny-intern", req, result)
    assert result.decision is Decision.DENY


# ---------- 版本更新语义 ----------

def test_atomic_update_and_version_stability_under_concurrency():
    service = make_service()  # v1: read doc:1 -> allow
    errors: list[str] = []
    stop = threading.Event()

    def updater() -> None:
        # 在 v1 与 v2 之间反复原子切换，直至评估线程完成
        while not stop.is_set():
            service.update_bundle(json.dumps(BUNDLE_V2))
            service.update_bundle(json.dumps(BUNDLE_V1))

    def decider() -> None:
        for _ in range(200):
            req = DecisionRequest(subject="u", action="read", resource="doc:1")
            result = service.decide(req)
            # 同一次评估必须完整基于同一版本：结论必须与该版本语义一致
            if result.policy_version == "v1" and result.decision is not Decision.ALLOW:
                errors.append(f"v1 版本下出现异常结论 {result.decision}")
            if result.policy_version == "v2" and result.decision is not Decision.DENY:
                errors.append(f"v2 版本下出现异常结论 {result.decision}")

    threads = [threading.Thread(target=updater)] + [
        threading.Thread(target=decider) for _ in range(4)
    ]
    for t in threads:
        t.start()
    for t in threads[1:]:
        t.join()
    stop.set()
    threads[0].join()

    assert errors == []
    # 记录与结论一一对应：每条记录的版本与其结论必须符合该版本语义
    records = service.records()
    assert len(records) > 0
    versions_seen = set()
    for record in records:
        versions_seen.add(record.result.policy_version)
        if record.result.policy_version == "v1":
            assert record.result.decision is Decision.ALLOW
        elif record.result.policy_version == "v2":
            assert record.result.decision is Decision.DENY
        else:
            pytest.fail(f"记录出现未知版本 {record.result.policy_version}")
    print(f"\n[concurrency] 共 {len(records)} 条记录，涉及版本: {sorted(versions_seen)}")
    sample = records[0]
    print(f"[concurrency] 样例记录 请求: {sample.request}")
    print(f"[concurrency] 样例记录 版本: {sample.result.policy_version}, 结论: {sample.result.decision.value}")


def test_failed_update_keeps_old_version():
    service = make_service()
    with pytest.raises(BundleValidationError):
        service.update_bundle(json.dumps({"policies": []}))  # 缺 version
    req = DecisionRequest(subject="u", action="read", resource="doc:1")
    result = service.decide(req)
    log_result("failed-update-keeps-old", req, result)
    assert result.policy_version == "v1"
    assert result.decision is Decision.ALLOW


# ---------- 非法策略包：失败原因可区分 ----------

def test_malformed_json_rejected_as_parse_error():
    service = make_service()
    with pytest.raises(BundleParseError) as exc_info:
        service.update_bundle("{not json")
    print(f"\n[parse-error] reason={exc_info.value.reason} detail={exc_info.value}")
    assert exc_info.value.reason == "parse_error"


def test_non_object_bundle_rejected_as_parse_error():
    service = make_service()
    with pytest.raises(BundleParseError) as exc_info:
        service.update_bundle(json.dumps([1, 2, 3]))
    print(f"\n[parse-error-list] reason={exc_info.value.reason} detail={exc_info.value}")
    assert exc_info.value.reason == "parse_error"


@pytest.mark.parametrize(
    "bundle,field",
    [
        ({"policies": []}, "version"),  # 缺版本
        ({"version": "v", "policies": {}}, "policies"),  # policies 不是数组
        ({"version": "v", "policies": [{"id": "p", "resource": "r", "action": "a", "effect": "maybe"}]}, "policies[0].effect"),  # 非法 effect
        ({"version": "v", "policies": [
            {"id": "p", "resource": "r", "action": "a", "effect": "allow"},
            {"id": "p", "resource": "r", "action": "a", "effect": "deny"},
        ]}, "policies.id"),  # id 重复
        ({"version": "v", "policies": [
            {"id": "p", "resource": "r", "action": "a", "effect": "allow",
             "conditions": [{"equals": 1}]},
        ]}, "policies[p].conditions[0]"),  # 条件缺 attribute
    ],
)
def test_semantically_invalid_bundles_rejected_as_validation_error(bundle, field):
    service = make_service()
    with pytest.raises(BundleValidationError) as exc_info:
        service.update_bundle(json.dumps(bundle))
    print(f"\n[validation-error] field={exc_info.value.field} reason={exc_info.value.reason} detail={exc_info.value}")
    assert exc_info.value.reason == "validation_error"
    assert exc_info.value.field == field
    # 两类失败原因可区分
    assert BundleParseError.reason != BundleValidationError.reason
