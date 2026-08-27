# M10：Gateway 代理服务

> - 状态：未开始
> - 所属计划：[Heyaki MVP 至 v1 实施TODO 计划](heyaki-implementation-plan.md)
> - 前置：M5 | 建议发布点：v1.1 Gateway beta（不进入 v1.0 发布门禁）
> - 设计依据：[Gateway 代理服务设计](../design/gateway-service.md)、
>   [Heyaki 设备通信基础设施设计](../design/heyaki-architecture.md) §8.6

本里程碑交付受限 L4 Gateway 代理：已授权设备 A 经与 B 的认证会话，访问 B gateway
profile 允许的 TCP 目标（B 网络节点或经 B 出公网）。L3/TUN 与 UDP 形态是计划
`POST-11`/`POST-12`，不属于本里程碑；Heyaki 会话多跳转发不属于本计划。

## 协议 1.3 change control

- [ ] `M10-01` 冻结 protocol 1.3 变更单并更新 wire protocol 文档与 golden vectors：capability bit 13 `gateway_v1`（要求 negotiated minor ≥ 3）、`StreamOpen` 可选 `gateway` 字段、`heyaki.protocol.gateway.v1.GatewayConnect` schema、2 字节 prelude 编码与 dial 错误到 `StableStatusCode` 的映射表；不新增帧类型。
- [ ] `M10-02` 版本互通回归：未协商出 bit 13 的会话收到携带 `gateway` 字段的 `STREAM_OPEN` 时按 `protocol` 拒绝并仅关闭该通道；1.2 及更旧对端将字段视为未知可选字段跳过，行为不受影响。

## 授权与 profile

- [ ] `M10-03` 定义并实现 `gateway.use` / `gateway.provide:<profile>` scope：默认关闭、不进任何标准 pairing 模板；请求 scope、TrustGrant、profile 与本地策略按交集裁决（沿用 M5-12 机制）。
- [ ] `M10-04` 实现 gateway profile 配置：CIDR 允许列表、端口 allowlist、`allow_internet`（默认 false）、并发流/字节/速率配额、每流空闲与总时长上限、dial deadline、人工确认模式；配置非法时启动失败。
- [ ] `M10-05` 实现 B 侧准入：scope/profile/CIDR/端口裁决；环回、链路本地、B 自身管理网段与隧道端点的默认 deny 列表；域名在 B 侧解析后逐地址校验；配额满载 fail-closed 拒绝并计数。
- [ ] `M10-06` 实现 TUI 同意流与 Gateway 视图：B 侧按 profile 确认模式显示对端与目标范围并允许/拒绝（`first_use` 决定可持久化）；A 侧发起 gateway、查看目标/路径/配额/prelude 延迟与 SOCKS 前端状态。

## 服务实现

- [ ] `M10-07` 实现 B 侧 `GatewayService`：`STREAM_OPEN(gateway)` 准入后在 executor 托管 Asio runtime 上本地 dial；拨号成功发送 prelude（status=0），失败/拒绝发送携带映射 status 的 `STREAM_RESET`；此后双向字节搬运复用 M5 stream 状态机。
- [ ] `M10-08` 实现 A 侧 `open_gateway_stream(peer, host, port, deadline)`：prelude 到达前处于 connecting，成功返回普通 `ByteStream`，失败/超时返回稳定错误码并 reset；遵守公共 Result/cancellation 语义。
- [ ] `M10-09` 实现可选 SOCKS5 前端：用户态、默认仅绑定 loopback、仅 `CONNECT`；域名目标（ATYP=0x03）原样透传由 B 侧解析；不进核心库依赖闭包，通过公共 API 工作。
- [ ] `M10-10` 背压与调度：gateway 通道权重不高于 event/file；隧道↔本地 socket 搬运有界缓冲，满载 reset 该流并计数，drop 语义显式配置且可观测。
- [ ] `M10-11` 路径策略与计量：`PeerPathPolicy` 增加 `gateway_paths` 约束（TURN 路径允许/限速/禁止）；gateway 活跃流数、准入结果分布、按 profile 字节/速率、TURN 路径占比、dial P95 接入指标。
- [ ] `M10-12` 审计与 threat model：五元组、时长、双向字节与结束原因入审计；目标 host 未通过校验以稳定 token 替换（safe_detail 纪律）；threat model 增补 gateway 条目（防火墙内侧、SSRF、探测 oracle、公网滥用、环回、资源耗尽）并完成评审。

## 测试与退出条件

- [ ] 准入矩阵：无 `gateway.provide` scope、CIDR 外目标、deny 列表网段、环回/隧道端点、超配额、非法 host 全部默认拒绝，且拒绝原因可由指标与审计观察。
- [ ] 协议：1.3 golden vectors 通过；未协商 bit 13 的互通回归通过；旧 epoch 迟到 gateway 流被隔离；session restart 后旧流对调用方呈现断流而非静默重连。
- [ ] 集成（netns）：A（网段 1）—B（网段 1+2）—目标（网段 2）拓扑、B 出公网路径、强制 TURN 数据路径下行为与计量正确；SOCKS5 前端经 curl/浏览器端到端，且 B 网络 split-DNS 域名由 B 侧解析验证。
- [ ] 资源与公平性：gateway 满载时 control/Shell 延迟达标（复用 M5 加权调度 benchmark）；持续过载下队列与 RSS 保持上限，reset/reject 计数与统计一致；关闭测试证明活跃流被 reset、本地 socket 回收、无 detached 工作。
- [ ] 安全：经 gateway 的连接探测受速率限制与配额约束；错误映射粗粒度（不区分 refused/unreachable/filtered）；审计与日志不含未校验目标 host 自由文本与 B 网络拓扑。
