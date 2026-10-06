import pytest

from policy_service.audit import DecisionLog
from policy_service.bundle_loader import load_bundle
from policy_service.service import PolicyDecisionService
from policy_service.store import PolicyStore

BUNDLE_V1 = {
    "version": "v1",
    "policies": [
        {"id": "allow-read", "effect": "allow", "resource": "doc", "action": "read"},
        {
            "id": "deny-mallory",
            "effect": "deny",
            "resource": "doc",
            "action": "read",
            "subject": "mallory",
        },
        {
            "id": "allow-write-eng",
            "effect": "allow",
            "resource": "doc",
            "action": "write",
            "conditions": {"dept": "eng"},
        },
    ],
}

BUNDLE_V2 = {
    "version": "v2",
    "policies": [
        {"id": "deny-read", "effect": "deny", "resource": "doc", "action": "read"},
    ],
}


@pytest.fixture
def store() -> PolicyStore:
    return PolicyStore(load_bundle(BUNDLE_V1))


@pytest.fixture
def log() -> DecisionLog:
    return DecisionLog()


@pytest.fixture
def service(store, log) -> PolicyDecisionService:
    return PolicyDecisionService(store, log)


def log_decision(request, result) -> None:
    """测试日志：打印请求输入、命中策略版本与判定依据（含缺失属性）。"""
    code = result.reason_code.value if result.reason_code is not None else "-"
    print(
        f"\n[decision-log] request={request} "
        f"policy_version={result.policy_version} "
        f"decision={result.decision.value} reason_code={code} "
        f"allowed={result.allowed} required_attributes={list(result.required_attributes)}"
    )
    for reason in result.reasons:
        print(f"[decision-log]   reason: {reason}")
    for m in result.matched:
        print(f"[decision-log]   matched: {m.rule_id} ({m.effect.value}) {m.reason}")
    for miss in result.missing_attributes:
        print(
            f"[decision-log]   missing: rule={miss.rule_id} "
            f"attribute={miss.attribute}"
        )
