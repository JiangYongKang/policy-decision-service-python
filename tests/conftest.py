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
    print(
        f"\n[decision-log] request={request} "
        f"policy_version={result.policy_version} "
        f"decision={result.decision.value} allowed={result.allowed} "
        f"indeterminate_reason="
        f"{result.indeterminate_reason.value if result.indeterminate_reason else None}"
    )
    for reason in result.reasons:
        print(f"[decision-log]   reason: {reason}")
    for m in result.matched:
        print(f"[decision-log]   matched: {m.rule_id} ({m.effect.value}) {m.reason}")
    for entry in result.missing_attributes:
        keys = ", ".join(f"{item.key}->expected {item.expected!r}" for item in entry.missing)
        print(
            f"[decision-log]   missing-attributes: rule={entry.rule_id} "
            f"({entry.effect.value}) [{keys}]"
        )
