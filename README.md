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
| `policies[].conditions` | 否 | 键值对，请求 `context` 中对应键存在且相等才命中 |

评估请求形如 `{subject, action, resource, context}`。规则的 selector（`resource`/`action`/`subject`）相等或为 `"*"` 即适用；适用规则的 `conditions` 按三态评估：

- **条件全部满足**：`context` 中每个条件键都存在且值相等（无条件规则直接满足）→ 规则确定命中；
- **条件明确不成立**：已给出的某个键值与要求不符 → 规则确定**不**命中（AND 已为假，其余键缺不缺都不影响结论）；
- **条件无法评估**：已给出的键都相符，但仍有条件键在 `context` 中缺失 → 规则处于**信息不足**状态，补齐属性后可能命中也可能不命中。

## 冲突与不确定性处理规则

对同一请求的**全部适用规则**做合并（按优先级）：

1. **缺属性不放行（最高优先级的「判不了」）**：只要存在一条适用规则因缺少属性而无法评估，最终结论即 `indeterminate` 且 `allowed=false`（默认拒绝）。**即使已有 `allow`（乃至 `deny`）确定命中也绝不放行**——资料不全时不允许得到允许结论；
2. **显式拒绝优先**：无信息不足规则时，任一确定命中规则为 `deny`，最终结论即 `deny`，即使同时命中 `allow`（冲突按拒绝处理）；
3. **允许**：无信息不足、无 `deny`，且至少一条 `allow` 确定命中，结论为 `allow`；
4. **信息不足（indeterminate）**：上述均不满足时，结论为 `indeterminate`——**不等同于允许**，服务按默认拒绝处理（`allowed=false`），但与显式拒绝可区分。

### 两种「判不了」如何区分

`indeterminate` 通过响应中的 `reason_code` 细分为两类，调用方可据此决定是否补属性重试：

| `reason_code` | 含义 | 补属性有用吗 |
| --- | --- | --- |
| `no_applicable_policy` | 真的没有任何适用策略：没有 selector 匹配的规则，或其条件都因**值不符**而明确不成立 | 无用，重试也不会变 |
| `missing_attributes` | 有适用策略，但判断所需属性缺失，当前无法评估 | **有用**：按 `required_attributes` 补齐后重试 |

属性给全的常规结论对应 `matched_allow` / `matched_deny`。

### 缺失属性如何呈现（结构化、可程序化解析）

当 `reason_code=missing_attributes` 时，响应额外携带：

- `required_attributes`：去重后的缺失属性名并集，如 `["region", "tier"]`，可直接据此回填；
- `missing_attributes`：逐条证据 `[{"rule_id": "deny-cn", "attribute": "region"}, ...]`，
  能看出结论是被**哪些规则、缺了哪些属性**卡住的（多条规则缺同一属性时只在并集中出现一次，证据中按规则分别列出）；
- `reasons`：人类可读的判定依据，包含被卡住的规则 ID、缺失属性名，以及「虽有规则命中但仍默认拒绝」的说明。

示例（`allow-all` 无条件放行 + `deny-cn` 要求 `region=cn`）：

```jsonc
// 请求 context 不含 region
{"decision": "indeterminate", "allowed": false,
 "reason_code": "missing_attributes",
 "required_attributes": ["region"],
 "missing_attributes": [{"rule_id": "deny-cn", "attribute": "region"}]}

// 请求 context={"region": "eu"}：值不符 = 明确不成立，正常放行
{"decision": "allow", "allowed": true, "reason_code": "matched_allow",
 "required_attributes": [], "missing_attributes": []}
```

> 注意区分：`region` 给了但值是 `eu` 属于「条件明确不成立」，`deny-cn` 不命中，请求按 `allow-all` 放行；只有 `region` **根本没给**才落到信息不足。

每次响应都包含可读的判定依据（`reasons`）与确定命中的规则明细（`matched`）。

## 版本更新语义

- 策略包必须携带 `version`；更新通过 `POST /policies` 提交完整新包。
- **原子更新**：已校验通过的新包整体替换旧包引用；更新期间旧版本继续对外服务，不会中断。
- **单次评估版本一致**：每次评估先取得当前快照，整个评估只基于该快照，不会出现新旧版本规则混合的结果。新引入的 `reason_code` 与缺失属性清单同样取自该单一快照，策略更新与并发请求同时发生时不会混版本。
- **向后兼容**：
  - 顶层结论取值不变，仍是 `allow` / `deny` / `indeterminate`；属性给全的正常请求，允许 / 显式拒绝 / 无适用策略三种行为与响应字段保持原样；
  - 本次为**纯增量**改动：响应新增 `reason_code`、`missing_attributes`、`required_attributes` 三个字段，旧字段含义不变，旧调用方无需改动；
  - 语义上唯一需要注意的变化：以前「条件所需属性缺失」与「条件值不符」都算规则不命中；现在前者会让结论落到 `indeterminate + missing_attributes`（缺资料不放行），后者才是明确不命中。
- **非法包拒绝**且原因可区分：
  - `BundleParseError`（HTTP 400，`parse_error`）：JSON 语法错误、顶层非对象等无法解析的情形；
  - `BundleValidationError`（HTTP 422，`validation_error`）：缺必填字段、`effect` 取值非法、规则 ID 重复等语义非法情形。
  - 被拒绝的包不会影响当前生效版本。

## 判定记录

每次评估都会追加一条判定记录，包含请求输入、所用策略版本与最终结论
（`GET /audit` 查询）。评估与记录在同一调用内完成，并发请求与策略更新
同时发生时，记录与结论保持一一对应，不丢失、不错配。

## HTTP 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `POST` | `/decide` | 评估请求，返回结论、版本、判定依据（含 `reason_code` 与缺失属性清单） |
| `POST` | `/policies` | 原子更新策略包（`{"bundle": {...}}`） |
| `GET` | `/policies/version` | 查询当前生效版本 |
| `GET` | `/audit` | 查询判定记录（同样包含 `reason_code`、`missing_attributes`、`required_attributes`） |

## 本地验证

```bash
# 安装依赖（uv）
uv sync

# 运行测试（覆盖冲突合并、缺属性不放行、两种信息不足区分、版本稳定性、
# 非法包拒绝；-s 打印请求输入、命中策略版本与判定依据，含缺失了哪些属性）
uv run pytest tests -q -s

# 启动服务
uv run python main.py

# 手工验证
curl -X POST localhost:8000/policies -H 'content-type: application/json' -d '{
  "bundle": {"version": "v1", "policies": [
    {"id": "allow-read", "effect": "allow", "resource": "doc", "action": "read"}
  ]}}'
curl -X POST localhost:8000/decide -H 'content-type: application/json' -d '{
  "subject": "alice", "action": "read", "resource": "doc"}'
curl localhost:8000/audit

# 缺属性语义验证：无条件 allow + region=cn 的 deny
curl -X POST localhost:8000/policies -H 'content-type: application/json' -d '{
  "bundle": {"version": "v-region", "policies": [
    {"id": "allow-all", "effect": "allow", "resource": "doc", "action": "read"},
    {"id": "deny-cn", "effect": "deny", "resource": "doc", "action": "read",
     "conditions": {"region": "cn"}}
  ]}}'
# 1) 不给 region -> indeterminate + missing_attributes，allowed=false
curl -X POST localhost:8000/decide -H 'content-type: application/json' -d '{
  "subject": "alice", "action": "read", "resource": "doc"}'
# 2) region=eu 值不符 -> 条件明确不成立 -> allow 正常放行
curl -X POST localhost:8000/decide -H 'content-type: application/json' -d '{
  "subject": "alice", "action": "read", "resource": "doc",
  "context": {"region": "eu"}}'
```

## 代码结构

```
policy_service/
  models.py         # 数据类型：规则、策略包、请求、结论、判定记录
  bundle_loader.py  # 策略包解析与校验（区分解析错误 / 语义错误）
  store.py          # 原子版本切换的不可变快照存储
  evaluator.py      # 命中合并与可解释结论生成
  audit.py          # 线程安全的判定日志
  service.py        # 快照 -> 评估 -> 记录 的完整决策流程
  app.py            # FastAPI HTTP 接口层
tests/              # 评估语义（含缺属性三态、两种信息不足区分）、版本稳定性、非法包拒绝、API 测试
```
