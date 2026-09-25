"""策略包解析与校验：区分解析失败与语义非法两类错误。"""
from __future__ import annotations

import json
from typing import Any

from .models import Effect, PolicyBundle, PolicyRule


class BundleParseError(Exception):
    """策略包无法解析（如 JSON 语法错误、非对象结构）。"""


class BundleValidationError(Exception):
    """策略包可解析但语义非法（缺字段、效果值非法、版本缺失等）。"""


def load_bundle(raw: str | bytes | dict) -> PolicyBundle:
    """解析并校验策略包，返回不可变快照。

    失败原因可区分：
    - BundleParseError：输入不是合法 JSON，或顶层不是对象；
    - BundleValidationError：结构可解析但缺少必填字段或取值非法。
    """
    data = _parse(raw)
    return _validate(data)


def _parse(raw: str | bytes | dict) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, (str, bytes)):
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise BundleParseError(f"策略包不是合法 JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise BundleParseError("策略包顶层必须是 JSON 对象")
        return data
    raise BundleParseError(f"不支持的策略包输入类型: {type(raw).__name__}")


def _validate(data: dict[str, Any]) -> PolicyBundle:
    version = data.get("version")
    if not isinstance(version, str) or not version.strip():
        raise BundleValidationError("策略包缺少非空字符串字段 'version'")

    policies = data.get("policies")
    if not isinstance(policies, list):
        raise BundleValidationError("策略包缺少数组字段 'policies'")

    rules: list[PolicyRule] = []
    seen_ids: set[str] = set()
    for index, item in enumerate(policies):
        rules.append(_validate_rule(index, item, seen_ids))
    return PolicyBundle(version=version.strip(), rules=tuple(rules))


def _validate_rule(index: int, item: Any, seen_ids: set[str]) -> PolicyRule:
    where = f"policies[{index}]"
    if not isinstance(item, dict):
        raise BundleValidationError(f"{where} 必须是对象")

    rule_id = item.get("id")
    if not isinstance(rule_id, str) or not rule_id.strip():
        raise BundleValidationError(f"{where} 缺少非空字符串字段 'id'")
    rule_id = rule_id.strip()
    if rule_id in seen_ids:
        raise BundleValidationError(f"{where} 规则 id 重复: '{rule_id}'")
    seen_ids.add(rule_id)

    raw_effect = item.get("effect")
    try:
        effect = Effect(raw_effect)
    except ValueError:
        raise BundleValidationError(
            f"{where} 字段 'effect' 取值非法: {raw_effect!r}，仅允许 'allow'/'deny'"
        ) from None

    resource = item.get("resource")
    if not isinstance(resource, str) or not resource:
        raise BundleValidationError(f"{where} 缺少非空字符串字段 'resource'")

    action = item.get("action")
    if not isinstance(action, str) or not action:
        raise BundleValidationError(f"{where} 缺少非空字符串字段 'action'")

    subject = item.get("subject", "*")
    if not isinstance(subject, str) or not subject:
        raise BundleValidationError(f"{where} 字段 'subject' 必须是非空字符串")

    conditions = item.get("conditions", {})
    if not isinstance(conditions, dict) or not all(
        isinstance(k, str) for k in conditions
    ):
        raise BundleValidationError(f"{where} 字段 'conditions' 必须是字符串键的对象")

    return PolicyRule(
        rule_id=rule_id,
        effect=effect,
        resource=resource,
        action=action,
        subject=subject,
        conditions=dict(conditions),
    )
