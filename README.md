# 策略决策服务（policy-decision-service）

可离线运行的策略决策服务：在请求进入业务处理前，基于**本地策略包**给出可解释的授权结论（允许 / 显式拒绝 / 信息不足），并保留可追溯的判定记录。

## 策略表达形式

策略包为 JSON 对象，包含版本标识与规则数组：

```json
{
  "version": "v1",
  "policies": [
    {
      "id": "allow-read",
      "effect": "allow",
      "resource": "doc",
      "action": "read",
      "subject": "*",
      "conditions": {"dept": "eng"}
    }
  ]
}
```

字段说明：

| 字段 | 必填 | 说明 |
| --- | --- | --- |
| `version` | 是 | 非空字符串，策略包版本标识 |
| `policies[].id` | 是 | 规则 ID，包内唯一 |
| `policies[].effect` | 是 | `allow` 或 `deny` |
| `policies[].resource` / `action` | 是 | 匹配目标；`"*"` 表示通配 |
| `policies[].subject` | 否 | 默认 `"*"` |
| `policies[].conditions` | 否 | 键值对：对应键存在且相等才算条件满足；值不符为明确不命中，键缺失则规则无法评估（见下文） |

评估请求形如 `{subject, action, resource, context}`。规则的评估是**三态**的：

- **命中（match）**：`resource`/`action`/`subject` 相等或为 `"*"`，且全部 `conditions`
  引用的属性在 `context` 中**存在且相等**；
- **明确不命中（not match）**：目标字段不匹配，或某个**已提供**的属性值与期望值不一致。
  这是条件明确不成立，补齐其他属性不会改变结论；
- **无法评估（indeterminate）**：目标字段匹配，但条件引用的属性在 `context` 中
  **确实缺失**。补齐属性后该规则可能命中，因此不能当成“不命中”放行。

> 注意区分：`context` 里给了 `region=eu` 而策略要求 `region=cn`，属于明确不命中；
> 请求里根本没有 `region`，才属于无法评估。条件为 AND 关系时，只要有一个已提供
> 属性明确不符，整条规则即明确不命中，不再报其他缺失属性。

## 冲突与不确定性处理规则

对同一请求相关的**全部**规则按以下优先级合并（deny-overrides，且缺属性绝不放行）：

1. **显式拒绝优先**：任一规则明确命中 `deny`，最终结论即 `deny`，即使同时命中
   `allow`（冲突按拒绝处理）；
2. **缺属性 → 信息不足**：没有明确 `deny`，但存在因缺属性**无法评估**的规则时，
   结论为 `indeterminate`，成因 `missing_attributes`，`allowed=false` 默认拒绝。
   即使已有 `allow` 命中也不放行——因为那条无法评估的规则（尤其可能是 `deny`）
   补齐属性后也许会推翻结论；
3. **允许**：无 `deny`、无无法评估规则，且至少一条 `allow` 明确命中，结论为 `allow`；
4. **无适用策略 → 信息不足**：所有规则都明确不命中时，结论为 `indeterminate`，
   成因 `no_applicable_policy`，`allowed=false` 默认拒绝。

### 两种「判不了」如何区分

两种情况结论都是 `indeterminate`、`allowed=false`，但响应字段
`indeterminate_reason` 把它们区分开：

| `indeterminate_reason` | 含义 | 调用方该怎么做 |
| --- | --- | --- |
| `no_applicable_policy` | 确实没有任何适用策略（条件明确不成立或字段不匹配） | 补属性重试无意义 |
| `missing_attributes` | 有策略本可适用，但请求缺属性 | 按 `missing_attributes` 补齐后重试 |

### 缺失属性如何呈现

`missing_attributes` 为结构化数组，**按策略归集**，说明请求被哪些策略、缺了哪些
属性卡住，可直接程序化解析；每个缺失项同时给出该策略的期望值，方便调用方补齐：

```json
{
  "decision": "indeterminate",
  "allowed": false,
  "indeterminate_reason": "missing_attributes",
  "missing_attributes": [
    {
      "rule_id": "deny-region-cn",
      "effect": "deny",
      "missing": [{"key": "region", "expected": "cn"}]
    }
  ],
  "reasons": ["规则 deny-region-cn（deny）缺少属性无法评估：region（期望值 'cn'）；信息不足，默认拒绝，补齐属性后可重试"]
}
```

说明：

- 多条策略卡住时数组含多个元素；一条策略缺多个属性时 `missing` 含多个元素；
- SDK 侧可用 `DecisionResult.required_attribute_keys()` 拿到去重保序后的待补属性键；
- 当明确 `deny` 已经定论时，结论仍是 `deny`（`indeterminate_reason` 为 `null`），
  但无法评估的规则照样保留在 `missing_attributes` 与 `reasons` 中，保证可追溯。

每次响应都包含可读的判定依据（`reasons`）、命中的规则明细（`matched`）与上述
缺属性信息。

## 版本更新语义

- 策略包必须携带 `version`；更新通过 `POST /policies` 提交完整新包。
- **原子更新**：已校验通过的新包整体替换旧包引用；更新期间旧版本继续对外服务，不会中断。
- **单次评估版本一致**：每次评估先取得当前快照，整个评估只基于该快照，不会出现新旧版本规则混合的结果。新增的缺属性结论与缺失属性清单同样全部来自同一次评估的单一版本；版本更新与并发请求同时发生时，每次结论及其 `policy_version`、`missing_attributes` 严格自洽。
- **非法包拒绝**且原因可区分：
  - `BundleParseError`（HTTP 400，`parse_error`）：JSON 语法错误、顶层非对象等无法解析的情形；
  - `BundleValidationError`（HTTP 422，`validation_error`）：缺必填字段、`effect` 取值非法、规则 ID 重复等语义非法情形。
  - 被拒绝的包不会影响当前生效版本。

## 判定记录

每次评估都会追加一条判定记录，包含请求输入、所用策略版本与最终结论
（`GET /audit` 查询，也包含 `indeterminate_reason` 与 `missing_attributes`）。
评估与记录在同一调用内完成，并发请求与策略更新
同时发生时，记录与结论保持一一对应，不丢失、不错配。

## 向后兼容

本次仅**新增**判定语义与响应字段，对属性给全的正常请求，原有的
允许 / 显式拒绝 / 无适用策略三种结果保持不变：

- `/decide` 与 `/audit` 响应在原有字段之外**新增** `indeterminate_reason`
  （allow/deny 时为 `null`）与 `missing_attributes`（没有无法评估的规则时为 `[]`）；
  原字段 `decision`、`allowed`、`reasons`、`matched`、`policy_version` 的含义与
  取值均未改变，旧调用方无需改动；
- 原“无任何规则命中”场景的结论仍是 `indeterminate`，只是现在可通过
  `indeterminate_reason=no_applicable_policy` 与缺属性场景区分；
- **行为收紧点**（语义变化，需注意）：此前“条件所需属性缺失”被当作规则不命中，
  若此时另有 `allow` 命中会放行；现在改为结论 `indeterminate/missing_attributes`
  且默认拒绝——这是“缺资料绝对不放行”的刻意收紧，而非兼容字段层面的破坏。

## HTTP 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `POST` | `/decide` | 评估请求，返回结论、版本、判定依据 |
| `POST` | `/policies` | 原子更新策略包（`{"bundle": {...}}`） |
| `GET` | `/policies/version` | 查询当前生效版本 |
| `GET` | `/audit` | 查询判定记录 |

## 本地验证

```bash
# 安装依赖（uv）
uv sync

# 运行测试（覆盖冲突合并、缺属性不放行、两类信息不足区分、版本稳定性、
# 非法包拒绝；-s 日志打印请求输入、策略版本、判定依据与缺失属性）
uv run pytest tests -q -s

# 启动服务
uv run python main.py

# 手工验证：无条件放行 + 要求 region=cn 的拒绝
curl -X POST localhost:8000/policies -H 'content-type: application/json' -d '{
  "bundle": {"version": "v1", "policies": [
    {"id": "allow-read", "effect": "allow", "resource": "doc", "action": "read"},
    {"id": "deny-cn", "effect": "deny", "resource": "doc", "action": "read",
     "conditions": {"region": "cn"}}
  ]}}'

# 不带 region -> indeterminate / missing_attributes，默认拒绝并给出待补属性
curl -X POST localhost:8000/decide -H 'content-type: application/json' -d '{
  "subject": "alice", "action": "read", "resource": "doc"}'

# region=eu（值不符，条件明确不成立）-> 正常 allow
curl -X POST localhost:8000/decide -H 'content-type: application/json' -d '{
  "subject": "alice", "action": "read", "resource": "doc",
  "context": {"region": "eu"}}'

curl localhost:8000/audit
```

## 代码结构

```
policy_service/
  models.py         # 数据类型：规则、策略包、请求、结论、判定记录
  bundle_loader.py  # 策略包解析与校验（区分解析错误 / 语义错误）
  store.py          # 原子版本切换的不可变快照存储
  evaluator.py      # 规则三态评估（命中/明确不命中/缺属性无法评估）与合并
  audit.py          # 线程安全的判定日志
  service.py        # 快照 -> 评估 -> 记录 的完整决策流程
  app.py            # FastAPI HTTP 接口层
tests/              # 评估语义、缺属性不放行与缺失清单、版本稳定性、非法包拒绝、API 测试
```
