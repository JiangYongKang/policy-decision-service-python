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

评估请求形如 `{subject, action, resource, context}`。规则命中条件：
`resource`/`action`/`subject` 相等或为 `"*"`，且全部 `conditions` 满足
（`context` 缺失对应键即视为不满足）。

## 冲突与不确定性处理规则

对命中同一请求的**全部**规则做合并：

1. **显式拒绝优先**：任一命中规则为 `deny`，最终结论即 `deny`，即使同时命中 `allow`（冲突按拒绝处理）；
2. **允许**：无 `deny` 且至少一条 `allow` 命中，结论为 `allow`；
3. **信息不足（indeterminate）**：无任何规则命中（含条件所需上下文缺失）时，结论为 `indeterminate`——**不等同于允许**，服务按默认拒绝处理（`allowed=false`），但与显式拒绝可区分。

每次响应都包含可读的判定依据（`reasons`）与命中的规则明细（`matched`）。

## 版本更新语义

- 策略包必须携带 `version`；更新通过 `POST /policies` 提交完整新包。
- **原子更新**：已校验通过的新包整体替换旧包引用；更新期间旧版本继续对外服务，不会中断。
- **单次评估版本一致**：每次评估先取得当前快照，整个评估只基于该快照，不会出现新旧版本规则混合的结果。
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
| `POST` | `/decide` | 评估请求，返回结论、版本、判定依据 |
| `POST` | `/policies` | 原子更新策略包（`{"bundle": {...}}`） |
| `GET` | `/policies/version` | 查询当前生效版本 |
| `GET` | `/audit` | 查询判定记录 |

## 本地验证

```bash
# 安装依赖（uv）
uv sync

# 运行测试（覆盖冲突合并、版本稳定性、非法包拒绝；日志打印请求输入、策略版本与判定依据）
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
tests/              # 评估语义、版本稳定性、非法包拒绝、API 测试
```
