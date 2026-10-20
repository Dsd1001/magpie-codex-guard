# Magpie Codex Guard：设计说明（alpha）

## 组件边界

- **Node 插件入口**：负责启动和关闭 Go 服务，提供本机和临时远程两种管理入口。远程模式复用原插件的 Go Console，按需下载 SHA-256 固定校验的 cloudflared，直接将临时隧道连接到 Go 的本机环回监听地址；没有新增 Node HTTP 代理。
- **Cloudflare 临时控制台**：远程连接使用一次性 10 分钟管理票据、30 分钟会话和最多 30 分钟的 Quick Tunnel；首次连接必须通过远端 `/health` 就绪检查。Go 控制台校验随机临时域名、Host 和 Origin，直接签发 SameSite=Lax、HttpOnly、Secure（远程 HTTPS）会话 Cookie；管理令牌仅通过插件启动时的私有进程管道传递。隧道不接触 Gateway Key 原始值。
- **Go 服务**：负责 Codex 账号读取、独立探针、自动题库、指纹采样、持久化调度、路由控制和只读快照。模型下拉框优先调用 Magpie 自带 `magpie models codex` 的只读目录并严格筛选 `codex/` ID；若 CLI 不可用且已配置检测连接，可回退到 `/v1/models`。实际请求直接使用原生 `codex/` 模型标识及 `X-Magpie-Account` 固定账号，无需、也不会改写网关的中间件文件或附加 `quality-probe/` 临时模型前缀。不使用生产 Key 查询模型，也不改变自动隔离开关。
- **指纹评分器**：Go 纯本地实现 lm-detector shared-detector-v2。嵌入官方固定版本 binary 与 60 个模型的精简元数据；不加载完整 12 MB JSON bank，也不运行额外的 Node/Bun 评分进程。
- **SQLite**：单写连接持久化状态、隔离 Hold、下次复测时间、日请求预算和写前路由日志。
- **路由控制器**：持有 Magpie `caller-keys.json.lock` 后操作 `caller-keys.json`；输入来自当前 Magpie 的稳定账号 ID 和 Gateway Key 清单。控制器绝不修改 `logins.json`。

## 状态与时间

```
healthy/unverified
      |
      | one objective failure
      v
 suspect (retry same question after 2 minutes)
      |
      | three valid failures total
      v
fingerprint_pending (create Hold, REMOVE FROM PRODUCTION FIRST)
      |
      | 3 pinned number-generation requests
      +--> explicit mismatch (high risk): 48h -> 96h -> 144h ...
      |
      +--> match/indeterminate/unavailable (low risk): 6h -> 30h -> 54h ...
                                               |
                                               | objective answer correct
                                               v
                                      recovery_confirm (+2m)
                                               |
                                               | second valid correct answer
                                               v
                              delete Hold -> restore production account
```

普通 HTTP 故障不增加错误次数，不完成恢复；再次尝试不会损失已保存的隔离起始时间。两个互相独立的上游请求产生的两次正确回答才可以解除隔离。

注意：实际调度为单探针、分钟级排队，所以绝对执行时间会略晚于名义时间；已持久化到期时间不会因进程重启重新计时。

## 风险判分

Go 实现保留频率、近邻、统计 baseline、位置与序列特征和温度校准。使用与官方仓库的 `shared_detector.bin` 完全对应的 `model_metadata.json`。比较预期模型类别时，`codex/gpt-6.1-sol` 与官方合并类 `gpt-6-astra` 关联。

只有三条足够完整、符合语言模型数字序列统计形状的回答才会进入排名；不充分的批次按 indeterminate 处理。在候选库内首位概率 ≥ 0.90 且预期模型概率 < 0.03 时判为高风险，其余视为匹配或无法判定，走低风险。**这个业务阈值是初始保守策略，并非官方提供的自动隔离阈值。**

原始公开 reference 样本及原版 JS 分数已固化为 `internal/fingerprint/testdata/official_*.json`，Go 回归测试约束结果差异。更新评分文件时必须重新生成 golden 并重新审核类别合并及风险阈值。

## 防误放行保证与边界

1. 隔离依据来自持久化的 `Holds`，不是通过一次错误或默认计数判断。
2. 第三次客观题失败在数据库落盘后立即同步路由，路由同步失败禁止继续以“已排除生产路由”的名义进行指纹复核。
3. 常规情况下生产 Key 白名单明确包含健康 Codex ID，原有非 Codex 条目不被删除。
4. **当单个生产 Key 对 Codex 的可用账号为零时，禁用该 Key；绝不使用空名单或不存在的占位账号。** 因此这条路径还会中断该 Key 上的非 Codex 流量。
5. 专用检测 Key 必须可访问全部 Codex 账号，并且当前提供的明文密钥必须与该 Key 匹配。
6. 原子替换、写前日志、原白名单及 `off` 开关的持久化基线允许状态恢复；文件被管理员改动时拒绝盲目覆盖。
7. 当前插件只治理通过受管理 Gateway Key 发起的调用；绕过这个机制的直接调用、未来 Magpie 核心版本改变匹配语义均需单独验证。
8. 若 Magpie 账号完全消失、Key 异常或全部禁用，不能默默删去隔离 Holds 来恢复路由。

## 待验证的上线门槛

- 在真实 Magpie 版本上进行正式插件加载、鉴权、账号路由及独立 Key 检测。
- 在资源限制相当于 sub2 的 Linux 容器环境评估完整评分器的 RSS 和 CPU。
- 使用**真实账号新采样**检验指纹误判率，并明确观测期后是否批准将身份异常升级为 48 小时隔离。
- 核实正在运行的旧插件路由状态与历史 Holds 的安全迁移方法；不得同时启用两个写控制器。
- 实际浏览器桌面和移动端页面验收（当前仅完成 JavaScript 语法检查与 jsdom 冒烟测试）。

当前不是可直接替换生产的稳定版本。
