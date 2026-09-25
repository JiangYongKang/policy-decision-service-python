"""畸形或语义非法策略包被拒绝，且失败原因可区分。"""
import pytest

from policy_service.bundle_loader import (
    BundleParseError,
    BundleValidationError,
    load_bundle,
)


def test_malformed_json_rejected_as_parse_error():
    with pytest.raises(BundleParseError) as exc_info:
        load_bundle("{not valid json")
    print(f"\n[reject-log] parse_error: {exc_info.value}")


def test_non_object_top_level_rejected_as_parse_error():
    with pytest.raises(BundleParseError) as exc_info:
        load_bundle('["not", "an", "object"]')
    print(f"\n[reject-log] parse_error: {exc_info.value}")


def test_unsupported_input_type_rejected_as_parse_error():
    with pytest.raises(BundleParseError) as exc_info:
        load_bundle(42)
    print(f"\n[reject-log] parse_error: {exc_info.value}")


@pytest.mark.parametrize(
    "bundle",
    [
        {"policies": []},  # 缺 version
        {"version": "", "policies": []},  # 空 version
        {"version": 1, "policies": []},  # version 类型非法
        {"version": "v1"},  # 缺 policies
        {"version": "v1", "policies": {}},  # policies 不是数组
        {"version": "v1", "policies": [{"effect": "allow", "resource": "r", "action": "a"}]},  # 缺 id
        {"version": "v1", "policies": [{"id": "p", "effect": "maybe", "resource": "r", "action": "a"}]},  # effect 非法
        {"version": "v1", "policies": [{"id": "p", "effect": "allow", "action": "a"}]},  # 缺 resource
        {"version": "v1", "policies": [{"id": "p", "effect": "allow", "resource": "r"}]},  # 缺 action
        {"version": "v1", "policies": [  # id 重复
            {"id": "p", "effect": "allow", "resource": "r", "action": "a"},
            {"id": "p", "effect": "deny", "resource": "r", "action": "a"},
        ]},
        {"version": "v1", "policies": [{"id": "p", "effect": "allow", "resource": "r", "action": "a", "conditions": [1]}]},  # conditions 非法
    ],
    ids=[
        "missing-version", "empty-version", "bad-version-type",
        "missing-policies", "policies-not-list", "missing-id",
        "bad-effect", "missing-resource", "missing-action",
        "duplicate-id", "bad-conditions",
    ],
)
def test_semantically_invalid_bundles_rejected_as_validation_error(bundle):
    with pytest.raises(BundleValidationError) as exc_info:
        load_bundle(bundle)
    print(f"\n[reject-log] validation_error: {exc_info.value}")


def test_parse_and_validation_errors_are_distinguishable():
    """两类失败原因属于不同异常类型，可区分。"""
    assert not issubclass(BundleValidationError, BundleParseError)
    assert not issubclass(BundleParseError, BundleValidationError)


def test_valid_bundle_accepted():
    bundle = load_bundle(
        '{"version": "v9", "policies": [{"id": "p", "effect": "deny", '
        '"resource": "doc", "action": "read", "subject": "*", '
        '"conditions": {"env": "prod"}}]}'
    )
    assert bundle.version == "v9"
    assert len(bundle.rules) == 1
    assert bundle.rules[0].conditions == {"env": "prod"}
