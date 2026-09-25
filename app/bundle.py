"""策略包解析、校验与原子版本存储。"""
from __future__ import annotations

import json
import threading
from typing import Any

from app.errors import BundleParseError, BundleValidationError
from app.models import Condition, Effect, Policy, PolicyBundle

_VALID_EFFECTS = {e.value for e in Effect}


def _fail(message: str, field: str) -> BundleValidationError:
    return BundleValidationError(message, field=field)


def _parse_condition(raw: Any, policy_id: str, index: int) -> Condition:
    where = f"policies[{policy_id}].conditions[{index}]"
    if not isinstance(raw, dict):
        raise _fail("条件必须是对象", where)
    attribute = raw.get("attribute")
    if not isinstance(attribute, str) or not attribute:
        raise _fail("条件缺少合法的 attribute 字段", where)
    if "equals" not in raw:
        raise _fail("条件缺少 equals 字段", where)
    return Condition(attribute=attribute, equals=raw["equals"])


def _parse_policy(raw: Any, index: int) -> Policy:
    where = f"policies[{index}]"
    if not isinstance(raw, dict):
        raise _fail("策略必须是对象", where)
    policy_id = raw.get("id")
    if not isinstance(policy_id, str) or not policy_id:
        raise _fail("策略缺少合法的 id 字段", f"{where}.id")
    resource = raw.get("resource")
    if not isinstance(resource, str) or not resource:
        raise _fail("策略缺少合法的 resource 字段", f"{where}.resource")
    action = raw.get("action")
    if not isinstance(action, str) or not action:
        raise _fail("策略缺少合法的 action 字段", f"{where}.action")
    effect = raw.get("effect")
    if effect not in _VALID_EFFECTS:
        raise _fail(
            f"effect 必须是 {sorted(_VALID_EFFECTS)} 之一，得到 {effect!r}",
            f"{where}.effect",
        )
    raw_conditions = raw.get("conditions", [])
    if not isinstance(raw_conditions, list):
        raise _fail("conditions 必须是数组", f"{where}.conditions")
    conditions = tuple(
        _parse_condition(c, str(policy_id), i) for i, c in enumerate(raw_conditions)
    )
    return Policy(
        id=policy_id,
        resource=resource,
        action=action,
        effect=Effect(effect),
        conditions=conditions,
    )


def parse_bundle(raw: str | bytes) -> PolicyBundle:
    """解析并校验策略包。

    - 无法解析（非 JSON、顶层不是对象）抛出 :class:`BundleParseError`；
    - 可解析但语义非法抛出 :class:`BundleValidationError`。
    """
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise BundleParseError(f"策略包不是合法 JSON：{exc}") from exc
    if not isinstance(data, dict):
        raise BundleParseError("策略包顶层必须是 JSON 对象")

    version = data.get("version")
    if not isinstance(version, str) or not version:
        raise _fail("策略包缺少合法的 version 字段", "version")

    raw_policies = data.get("policies")
    if not isinstance(raw_policies, list):
        raise _fail("policies 必须是数组", "policies")

    policies = tuple(_parse_policy(p, i) for i, p in enumerate(raw_policies))

    seen: set[str] = set()
    for policy in policies:
        if policy.id in seen:
            raise _fail(f"策略 id 重复：{policy.id}", "policies.id")
        seen.add(policy.id)

    return PolicyBundle(version=version, policies=policies)


class BundleStore:
    """持有当前生效策略包，支持原子切换。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._current: PolicyBundle | None = None

    def load(self, raw: str | bytes) -> PolicyBundle:
        """解析并原子替换当前策略包；失败时保持旧版本不变。"""
        bundle = parse_bundle(raw)
        with self._lock:
            self._current = bundle
        return bundle

    def snapshot(self) -> PolicyBundle:
        """获取当前版本快照；同一次评估必须始终使用同一快照。"""
        with self._lock:
            current = self._current
        if current is None:
            raise BundleValidationError("尚未加载任何策略包", field="version")
        return current
