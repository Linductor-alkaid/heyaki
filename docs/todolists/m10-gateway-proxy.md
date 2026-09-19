# M10：Gateway 代理服务

> - 状态：进行中（Round 1 协议 1.3 变更单已冻结，2026-09-19）
> - 所属计划：[Heyaki MVP 至 v1 实施TODO 计划](heyaki-implementation-plan.md)
> - 前置：M5 | 建议发布点：v1.1 Gateway beta（不进入 v1.0 发布门禁）
> - 设计依据：[Gateway 代理服务设计](../design/gateway-service.md)、
>   [Heyaki 设备通信基础设施设计](../design/heyaki-architecture.md) §8.6

本里程碑交付受限 L4 Gateway 代理：已授权设备 A 经与 B 的认证会话，访问 B gateway
profile 允许的 TCP 目标（B 网络节点或经 B 出公网）。L3/TUN 与 UDP 形态是计划
`POST-11`/`POST-12`，不属于本里程碑；Heyaki 会话多跳转发不属于本计划。

## 协议 1.3 change control

- [x] `M10-01` 冻结 protocol 1.3 变更单并更新 wire protocol 文档与 golden vectors：capability bit 13 `gateway_v1`（要求 negotiated minor ≥ 3）、`StreamOpen` 可选 `gateway` 字段、`heyaki.protocol.gateway.v1.GatewayConnect` schema、2 字节 prelude 编码与 dial 错误到 `StableStatusCode` 的映射表；不新增帧类型。
- [x] `M10-02` 版本互通回归：未协商出 bit 13 的会话收到携带 `gateway` 字段的 `STREAM_OPEN` 时按 `protocol` 拒绝并仅关闭该通道；1.2 及更旧对端将字段视为未知可选字段跳过，行为不受影响。

## 授权与 profile

- [x] `M10-03` 定义并实现 `gateway.use` / `gateway.provide:<profile>` scope：默认关闭、不进任何标准 pairing 模板；请求 scope、TrustGrant、profile 与本地策略按交集裁决（沿用 M5-12 机制）。（B 侧每流 live 执行点随 M10-07 服务交付；scope 定义、默认关闭、模板排除回归与交集机制已冻结并测试）
- [x] `M10-04` 实现 gateway profile 配置：CIDR 允许列表、端口 allowlist、`allow_internet`（默认 false）、并发流/字节/速率配额、每流空闲与总时长上限、dial deadline、人工确认模式；配置非法时启动失败。
- [ ] `M10-05` 实现 B 侧准入：scope/profile/CIDR/端口裁决；环回、链路本地、B 自身管理网段与隧道端点的默认 deny 列表；域名在 B 侧解析后逐地址校验；配额满载 fail-closed 拒绝并计数。（Round 2 交付纯准入引擎：profile 选择/端口/内置+配置 deny 列表逐地址过滤/并发与字节配额 fail-closed，全部有测试；隧道端点运行时 deny 与拒绝计数随 M10-07/M10-11 落地）
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

## 实施记录

### Round 1（2026-09-19）：M10-01/M10-02 protocol 1.3 变更单冻结

生产代码（主循环实现）：

- 协议升 1.3：`include/heyaki/protocol.hpp` 新增 `Capability::gateway_v1`（bit 13）、
  `protocol_1_3_capability_bits`、`known_capability_bits`、`current_protocol_version{1,3}`；
  `src/core/protocol.cpp` `capabilities_for_version` minor≥3 分支；根 CMake 协议版本 3。
- 新 schema `proto/heyaki/gateway/v1/gateway.proto`（`GatewayConnect{host,port,profile}`）与
  `stream.proto` 的 `StreamOpen.gateway = 4` 可选字段；`tests/protocol/CheckProtocolSources.cmake`
  登记 gateway 契约与 domain。
- 新公共面 `include/heyaki/gateway.hpp` + `src/core/gateway_protocol.cpp`：scope helper
  （`gateway.use` / `gateway.provide:<profile>`）、`GatewayConnect` 镜像与严格 codec（未知字段/
  重复/缺字段拒绝）、host 文法（LDH/IPv4/IPv6 字面量、253 字节、禁 NUL/控制/空格/下划线/首尾
  连字符或点）、profile 文法（`[a-z0-9_.-]` 64 字节）、2 字节 prelude 编解码（仅 0 合法）、
  `GatewayRefusal` 九类 → `StableStatusCode` 冻结映射与稳定 token 名、设计 §8 冻结限额常量。
- `src/client/byte_stream.{hpp,cpp}`：A 侧 `open_gateway_stream`（每连接专用 stream 域逻辑
  通道；未协商 bit 13 本地拒绝、不发帧——M10-02 发射门控；`is_gateway()` 标记）；B 侧
  `handle_open` 解析 field 4：未协商 bit 13 或 body wire 级畸形 → `fail_business_channel`
  仅关该通道（会话存活）；文法非法 → 流级 RESET(permission_denied)；无消费者 →
  RESET(unimplemented)（默认关闭）；新增 `set_gateway_inbound_handler` 供 Round 3 网关服务
  接管准入；`grant_initial_credit` 提取共用。普通流路径零变化（未知可选字段仍跳过）。

文档：wire protocol 文档升 1.3 基线（§4 bit 13、新 §6.3.1 gateway 流语义：发射/接收门控、
prelude、冻结 dial/refusal 映射表、探测 oracle 粗粒度合并；§7 增 m10 vectors）；`proto/README.md`
登记 gateway schema 与生产 codec 归属。

测试（IVA 独立验证 PASS，2026-09-19）：`tests/unit/m10_protocol_test.cpp` 27 例（host/profile
文法全表、严格 codec、prelude、映射表快照、版本钳制/required 位回归、环回双会话 8 场景：
1.3 端到端、对 1.2 对端本地门控零发帧、无 handler unimplemented、min=2 会话注入 field-4 OPEN
仅关通道且 ping 存活、畸形 body 同前、文法非法流级 permission_denied、普通流回归、1.2 未知
可选字段跳过）；golden vectors `tests/vectors/m10-golden-vectors.json`（GatewayConnect 两种、
plain/gateway STREAM_OPEN、prelude，经生产 codec 生成、configure 期逐字节比对）；fuzz 注册
`parse_protobuf<GatewayConnect>` + 回归种子；`version_test` 钉死断言 2→3。证据：新测试 27/27、
`unit|protocol` 标签 34/34、network 标签 15/15（coturn 外部矩阵按既有门控自跳过）、
fuzz smoke 81 corpus 单元回放，全绿；无生产缺陷。CI run 35452360300 十一 job 终态绿
（asan 首跑 `SimultaneousSameKindOpensResolveToRegisteredChannel` 为既有 attach-race 抖动，
重跑绿；本轮改动不触及 transport 层）。

### Round 2（2026-09-19）：M10-04/05 profile 配置与准入引擎（+M10-03 scope 冻结）

生产代码（主循环实现）：

- `include/heyaki/gateway.hpp` / `src/core/gateway_protocol.cpp` 扩展：`GatewayIp`/`GatewayCidr`
  原语（parse/format/CIDR 逐前缀位 contains/家族隔离/catch-all 判定；format 遵循 RFC 5952 含
  IPv4-mapped 点分特例）；`GatewayProfileConfig`（CIDR 允许列表、denied_cidrs 叠加段、端口
  allowlist 空表=全拒、allow_internet 默认 false、每 session/每 profile 双并发帽、聚合字节/速率
  配额、每流 idle/总时长帽、dial deadline、never/first_use/always 确认模式）；硬上限常量
  （64/64、1TiB、256MiB/s、1h、24h、30s）；`validate_gateway_profile(s)`（名法/空列表/
  catch-all 未开 internet/端口/配额/超时全轴拒绝式校验，重名与 64 顶帽）；纯准入引擎
  `admit_gateway_connection`（profile 选择：空名唯一 profile 或 not_enabled；端口裁决；解析后
  逐地址：内置 deny 表 → denied_cidrs → allowed_cidrs，存活子集即 dial_addresses；会话/Profile
  并发与字节配额满载 fail-closed quota_exhausted）。
- `NodeConfig::gateway_profiles`（空=关闭）+ `Node::create` 校验（非法集合启动失败，错误透传）。
- 内置 deny 表（不可配置移除）：0.0.0.0/8、127/8、169.254/16、224/4、255.255.255.255/32、
  100.64/10、::/128、::1/128、fe80::/10、ff00::/8、**::ffff:0:0/96**（IPv4-mapped 段整体 deny，
  防 mapped 环回绕过——IVA 对抗复验发现，冻结语义：mapped 段全拒、公网目标须原生 v4/v6 形式）。
- IPv6 文法修复（IVA 抓出三缺陷后主循环修复并经对抗复验）：尾/中 `::` 压缩文法、
  `ipv6_groups` 尾组末位装配（`::1` 字节错位曾使内置环回 deny 全部失配，安全级）、
  `format_gateway_ip` 非头部压缩双冒号、`ipv4_octets` 尾点拒绝；quota 拒绝清空 dial_addresses。
- `docs/operations/parameter-freeze.md` 新增 §6a Gateway profile 冻结表（默认/硬上限/依据，
  deny 常量成文）；TUI NodeConfig 构造点同步 `.gateway_profiles = {}`。

测试（IVA 三轮：首轮 FAIL 抓出 D1/D2/D3 三生产缺陷 → 主循环修复 → 对抗复验 PASS → mapped-deny
补测 PASS）：`tests/unit/m10_gateway_policy_test.cpp` 55 例（IP/CIDR 文法与字节布局、
inet_pton/inet_ntop oracle 交叉 39 万格式扫描、profile 校验全轴 detail token、准入矩阵 18 项
含内置 deny 11 段与 mapped 段、Node::create 非法拒绝、TUI 模板 gateway 排除、参数冻结钉死）；
`m9_parameter_freeze_test` 扩 gateway 段；8 个 NodeConfig 穷举初始化测试补新字段。证据：
55/55 + 27/27（m10_protocol）+ `unit|protocol` 35/35 + asan 预设两 m10 目标无告警。
残留（随 M10-07/11 闭环）：隧道端点运行时 deny、拒绝原因计数器、B 侧真实 resolver
（引擎已按"解析后逐地址"契约设计）。
