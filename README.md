# 策略决策服务（policy-decision-service）

一套可完全离线运行的策略决策服务：在请求进入业务处理前，基于本地策略包给出可解释的授权结论（允许 / 拒绝 / 信息不足），并保留可追溯的判定记录。

## 策略表达形式

策略包为 JSON 文档，包含版本标识与策略列表：

```json
{
  "version": "v1",
  "policies": [
    {
      "id": "allow-read-doc",
      "resource": "doc:1",
      "action": "read",
      "effect": "allow"
    },
    {
      "id": "deny-intern-delete",
      "resource": "doc:1",
      "action": "delete",
      "effect": "deny",
      "conditions": [{"attribute": "role", "equals": "intern"}]
    }
  ]
}
```

- `version`：必填，非空字符串，策略包版本标识。
- `policies[].resource` / `action`：匹配目标，支持 `"*"` 通配。
- `policies[].effect`：必填，`"allow"` 或 `"deny"`。
- `policies[].conditions`：可选，对请求属性（`attributes`）的等值匹配条件列表，全部满足时策略才生效。

决策请求：

```json
{"subject": "u1", "action": "read", "resource": "doc:1", "attributes": {"role": "admin"}}
```

## 冲突与不确定性处理规则

评估时综合命中同一资源（含通配）的全部策略，按以下优先级合并：

1. **显式拒绝优先**：任一命中策略条件全部满足且 `effect=deny` → 结论 `deny`；
2. **信息不足次之**：任一命中策略因请求缺少条件所需属性而无法判定 → 结论 `indeterminate`；
3. **显式允许**：存在条件全部满足的 `allow` 策略且无拒绝、无不确定项 → 结论 `allow`；
4. **无适用策略**：没有任何策略命中或条件不满足 → 结论 `indeterminate`。

关键约定：**信息不足（indeterminate）绝不等同于允许**；存在冲突或无法判定的请求应按默认拒绝处理。每次评估的响应都包含可读的判定依据（`reasons`）、命中的策略 ID 与所用策略版本。

## 版本更新语义

- 策略包通过 `update_bundle`（或 `POST /bundles`）原子替换：替换是单次引用切换，更新期间服务不中断。
- **同一次评估始终基于同一版本快照**：`decide()` 先取一次快照，整个评估只使用该快照，不会出现新旧版本混合的结果。
- 解析失败（`parse_error`）或语义非法（`validation_error`）的策略包被拒绝，**旧版本继续生效**；两类失败通过异常的 `reason` 字段（及 HTTP 响应的 `error` 字段）区分，语义错误还带有定位字段 `field`。
- 每次判定都会写入一条不可变记录（请求输入 + 策略版本 + 结论 + 时间戳），记录在评估完成后一次性写入，并发请求与并发更新下记录与结论保持一一对应。

## HTTP 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/bundles` | 原子更新策略包（请求体为策略包 JSON）；非法包返回 422，`error` 为 `parse_error` 或 `validation_error` |
| POST | `/decide` | 决策评估，返回 `decision` / `policy_version` / `matched_policy_ids` / `reasons` |
| GET | `/records` | 查询全部判定记录 |

## 本地验证方式

```bash
# 安装依赖
uv sync

# 运行测试（日志中打印请求输入、命中策略版本与判定依据）
uv run pytest -q -s

# 本地启动服务（离线，监听随机端口）
uv run python main.py
```

也可在 Python 中直接使用：

```python
import json
from app.models import DecisionRequest
from app.service import PolicyDecisionService

service = PolicyDecisionService()
service.update_bundle(json.dumps({
    "version": "v1",
    "policies": [{"id": "p1", "resource": "doc:1", "action": "read", "effect": "allow"}],
}))
result = service.decide(DecisionRequest(subject="u1", action="read", resource="doc:1"))
print(result.decision.value, result.policy_version, result.reasons)
```

## 测试覆盖

- 显式拒绝与允许冲突时拒绝优先；仅允许生效时允许；缺属性 / 无适用策略时为信息不足且不等同于允许；
- 并发评估与并发更新下，每条结论与记录都完整基于单一版本（v1→allow、v2→deny 严格对应）；
- 畸形 JSON（`parse_error`）与语义非法包（`validation_error`，含缺版本、非法 effect、重复 id、非法条件等）均被拒绝且原因可区分，失败更新不影响旧版本。
