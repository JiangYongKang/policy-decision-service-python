"""HTTP 接口：决策、策略包更新的错误区分与判定记录查询。"""
import pytest
from fastapi.testclient import TestClient

from policy_service.app import create_app

from .conftest import BUNDLE_V1, log_decision


@pytest.fixture
def client():
    return TestClient(create_app())


def test_decide_before_any_bundle_returns_503(client):
    resp = client.post("/decide", json={
        "subject": "a", "action": "read", "resource": "doc"})
    assert resp.status_code == 503


def test_decide_and_audit_flow(client):
    resp = client.post("/policies", json={"bundle": BUNDLE_V1})
    assert resp.status_code == 200
    assert resp.json() == {"status": "updated", "version": "v1"}

    resp = client.post("/decide", json={
        "subject": "mallory", "action": "read", "resource": "doc"})
    assert resp.status_code == 200
    body = resp.json()
    print(f"\n[api-log] response={body}")
    assert body["decision"] == "deny"
    assert body["allowed"] is False
    assert body["policy_version"] == "v1"
    assert body["reasons"]

    records = client.get("/audit").json()
    assert len(records) == 1
    rec = records[0]
    print(f"[api-log] audit_record={rec}")
    assert rec["request"]["subject"] == "mallory"
    assert rec["policy_version"] == "v1"
    assert rec["decision"] == "deny"


def test_parse_error_and_validation_error_distinguishable_over_http(client):
    # 顶层不是对象 -> parse_error (400)
    resp = client.post("/policies", json={"bundle": ["not-an-object"]})
    assert resp.status_code == 400
    assert resp.json()["detail"]["error"] == "parse_error"
    print(f"\n[api-log] parse_error: {resp.json()['detail']['message']}")

    # 结构合法但语义非法 -> validation_error (422)
    resp = client.post("/policies", json={"bundle": {
        "version": "v1",
        "policies": [{"id": "p", "effect": "maybe",
                      "resource": "r", "action": "a"}],
    }})
    assert resp.status_code == 422
    assert resp.json()["detail"]["error"] == "validation_error"
    print(f"[api-log] validation_error: {resp.json()['detail']['message']}")

    # 非法包被拒绝后，服务仍无策略可评估
    resp = client.post("/decide", json={
        "subject": "a", "action": "read", "resource": "doc"})
    assert resp.status_code == 503


def test_service_keeps_serving_during_update(client):
    client.post("/policies", json={"bundle": BUNDLE_V1})
    before = client.post("/decide", json={
        "subject": "alice", "action": "read", "resource": "doc"}).json()
    log_decision("alice/read/doc", type("R", (), {
        "policy_version": before["policy_version"],
        "decision": type("D", (), {"value": before["decision"]})(),
        "allowed": before["allowed"],
        "reason_code": type("C", (), {"value": before.get("reason_code")})(),
        "reasons": before["reasons"],
        "matched": [],
        "missing_attributes": [],
        "required_attributes": before.get("required_attributes", []),
    })())
    # 更新期间（此处以连续调用模拟）旧请求已按 v1 完成，新请求按 v2
    client.post("/policies", json={"bundle": {
        "version": "v2",
        "policies": [{"id": "deny-read", "effect": "deny",
                      "resource": "doc", "action": "read"}],
    }})
    after = client.post("/decide", json={
        "subject": "alice", "action": "read", "resource": "doc"}).json()
    assert before["policy_version"] == "v1" and before["decision"] == "allow"
    assert after["policy_version"] == "v2" and after["decision"] == "deny"


def test_missing_attributes_fields_exposed_over_http(client):
    """缺属性时响应携带 reason_code 与结构化缺失清单，可供程序化解析。"""
    client.post("/policies", json={"bundle": {
        "version": "v-region",
        "policies": [
            {"id": "allow-all", "effect": "allow",
             "resource": "doc", "action": "read"},
            {"id": "deny-cn", "effect": "deny",
             "resource": "doc", "action": "read",
             "conditions": {"region": "cn"}},
        ],
    }})

    # 缺 region -> missing_attributes，不放行
    resp = client.post("/decide", json={
        "subject": "alice", "action": "read", "resource": "doc"})
    body = resp.json()
    print(f"\n[api-log] missing-attrs response={body}")
    assert resp.status_code == 200
    assert body["decision"] == "indeterminate"
    assert body["allowed"] is False
    assert body["reason_code"] == "missing_attributes"
    assert body["required_attributes"] == ["region"]
    assert body["missing_attributes"] == [
        {"rule_id": "deny-cn", "attribute": "region"}
    ]

    # 值不符 -> 明确不成立 -> 正常放行，无缺失清单
    resp = client.post("/decide", json={
        "subject": "alice", "action": "read", "resource": "doc",
        "context": {"region": "eu"}})
    body = resp.json()
    print(f"[api-log] value-mismatch response={body}")
    assert body["decision"] == "allow"
    assert body["reason_code"] == "matched_allow"
    assert body["missing_attributes"] == []
    assert body["required_attributes"] == []

    # 完全无适用策略 -> no_applicable_policy，与缺属性可区分
    resp = client.post("/decide", json={
        "subject": "alice", "action": "delete", "resource": "doc"})
    body = resp.json()
    print(f"[api-log] no-applicable response={body}")
    assert body["decision"] == "indeterminate"
    assert body["reason_code"] == "no_applicable_policy"
    assert body["missing_attributes"] == []

    # 审计记录同样带新字段
    rec = client.get("/audit").json()[0]
    print(f"[api-log] first audit_record={rec}")
    assert "reason_code" in rec and "missing_attributes" in rec
