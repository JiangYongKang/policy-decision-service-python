"""显式拒绝与允许冲突、信息不足等评估语义测试。"""
from policy_service.models import Decision, DecisionRequest

from .conftest import log_decision


def test_allow_when_only_allow_matches(service):
    req = DecisionRequest(subject="alice", action="read", resource="doc")
    result = service.decide(req)
    log_decision(req, result)
    assert result.decision is Decision.ALLOW
    assert result.allowed is True
    assert result.policy_version == "v1"


def test_explicit_deny_beats_allow(service):
    """mallory 同时命中 allow-read 与 deny-mallory，显式拒绝优先。"""
    req = DecisionRequest(subject="mallory", action="read", resource="doc")
    result = service.decide(req)
    log_decision(req, result)
    assert result.decision is Decision.DENY
    assert result.allowed is False
    effects = {m.effect.value for m in result.matched}
    assert effects == {"allow", "deny"}
    assert any("显式拒绝" in r for r in result.reasons)
    assert any("冲突" in r for r in result.reasons)


def test_indeterminate_when_no_rule_matches(service):
    """无任何命中 -> 信息不足，不得等同于允许。"""
    req = DecisionRequest(subject="alice", action="delete", resource="doc")
    result = service.decide(req)
    log_decision(req, result)
    assert result.decision is Decision.INDETERMINATE
    assert result.allowed is False
    assert result.decision is not Decision.ALLOW
    assert any("信息不足" in r for r in result.reasons)


def test_indeterminate_when_condition_context_missing(service):
    """条件所需上下文缺失 -> 规则不命中 -> 信息不足。"""
    req = DecisionRequest(subject="alice", action="write", resource="doc")
    result = service.decide(req)
    log_decision(req, result)
    assert result.decision is Decision.INDETERMINATE
    assert result.allowed is False


def test_allow_when_condition_satisfied(service):
    req = DecisionRequest(
        subject="alice", action="write", resource="doc", context={"dept": "eng"}
    )
    result = service.decide(req)
    log_decision(req, result)
    assert result.decision is Decision.ALLOW


def test_audit_record_matches_conclusion(service, log):
    req = DecisionRequest(subject="mallory", action="read", resource="doc")
    result = service.decide(req)
    log_decision(req, result)
    records = log.all()
    assert len(records) == 1
    rec = records[0]
    assert rec.request == req
    assert rec.result is result
    assert rec.result.policy_version == "v1"
