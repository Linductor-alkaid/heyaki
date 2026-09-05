# M9：生产加固与 v1 发布

> - 状态：进行中（2026-09-05 立项；前置 M8 遗留三件套 P2-F1/P3-F3/P4-F7（+P4-F9）已修复放行，见 [m8-remote-shell.md](m8-remote-shell.md) 遗留节；M9-01 Round 1 已交付，见文末实施记录）
> - 所属计划：[Heyaki MVP 至 v1 实施 TODO 计划](heyaki-implementation-plan.md)
> - 前置：M8 | 建议发布点：v1.0

## 可观测性与运维

- [ ] `M9-01` 设备端导出架构第 13.2 节全部 LAN/relay/协议指标，并与 executor failure/status、comm stats 建立明确关联字段。（Round 1 已交付 2026-09-05：`NodeMetrics` 统一聚合 + `Node::metrics()` 周期发布 + Prometheus 文本导出 `format_node_metrics_prometheus`；新增 pairing 审计计数器与连通性结果/时长计数器；executor 关联字段经内嵌 `RuntimeSnapshot`。缺口见实施记录"剩余范围"。）
- [ ] `M9-02` relay 导出 Prometheus 指标、结构化日志、有限审计和可选 trace correlation；高频成功事件采样。
- [ ] `M9-03` 为 registration、pairing、connection、session、operation 和 transfer 建立不含机密的 correlation ID。
- [ ] `M9-04` 定义 SLO dashboard 与告警：multicast/listener readiness、presence/handshake reject、登录失败、租约续期、直连率、TURN allocation、pairing 猜测、队列拒绝、RPC overload、文件 hash 和 worker failure。
- [ ] `M9-05` 编写运维 runbook：证书/credential 轮换、设备吊销、relay/coturn 重启、数据库备份恢复、磁盘满、过载和版本回滚。

## 可靠性、兼容性与性能

- [ ] `M9-06` 完成 LAN/NAT 矩阵：same-bridge multicast、multicast blocked、multi-NIC/interface change、full-cone、restricted、port-restricted、symmetric、hairpin、CGNAT、IPv6-only 和 UDP blocked。
- [ ] `M9-07` 在 Linux/Windows 双向组合验证 LAN-only、relay-signaled direct、TURN/UDP、TURN/TCP/TLS、Windows firewall/network profile、文件权限/命名和 PTY/ConPTY。
- [ ] `M9-08` 完成 relay 重启、coturn 重启、网络切换、credential 过期、磁盘满、慢消费者和任意关闭点故障注入。
- [ ] `M9-09` 执行 24/72 小时长稳、反复发现/过期/建连/断连和容量过载测试，证明内存、fd/handle、worker、session、endpoint directory 和 TTL/replay cache 有界。
- [ ] `M9-10` 基准消息 latency、并发 RPC、事件 fan-out、单/多文件吞吐、Shell 竞争延迟、relay 内存和带宽。
- [ ] `M9-11` 基于结果重新冻结默认容量、水位、timeout 和重试参数；默认值必须有测量依据和硬上限。
- [ ] `M9-12` 完成 schema N-1/N 兼容、rolling relay upgrade 和新旧设备互通；不兼容行为必须在握手期拒绝。

## 安全与发布工程

- [ ] `M9-13` 扩展 fuzz 持续时间，覆盖所有 parser、状态机、ProfileStore migration 和 VT；保存最小化 regression corpus。
- [ ] `M9-14` 完成 secret scan、dependency vulnerability scan、SBOM、许可证、编译 hardening 和发布制品签名。
- [ ] `M9-15` 执行安全回归：multicast 洪泛/伪造/重放、LAN TLS MITM/slowloris、密码猜测/泄漏、grant/fingerprint/endpoint 伪造、降级、越权 method/topic、路径穿越、relay/TURN 放大。
- [ ] `M9-16` 编写安装、配置、部署、升级、备份、故障排查和 API 文档；示例必须从已编译源码嵌入或同步测试。
- [ ] `M9-17` 打包 client libraries、relay、TUI、coturn 示例配置与符号/许可证，验证干净机器安装和卸载。
- [ ] `M9-18` 形成 v1 release checklist，记录测试 commit、依赖 commit、协议版本、已知限制和回滚方案。

## M9/v1 最终验收

- [ ] 同区域正常网络登记 P95 < 2 秒，可打洞直连 P95 < 3 秒，TURN fallback P95 < 5 秒。
- [ ] 无 relay/STUN/TURN 的三设备测试 LAN 能自主发现、认证和建立 host-candidate DataChannel；未知/已信任 peer 分别进入 PairingRestricted/Authorized。
- [ ] TUI 本地初始化后，同 OS 用户的库应用可复用 profile 运行 LAN-only；存在 enrollment 时可无人工登录 relay，多 endpoint 同时在线且路由准确。
- [ ] 未信任设备只能进入 pairing-only，错误密码不触达业务 handler，正确密码只授予策略交集内 scope。
- [ ] LAN-only、relay-signaled direct 和 TURN 三条路径均通过消息、RPC、事件、ByteStream、文件和启用后的 Shell 端到端测试。
- [ ] 所有发送/接收/任务/诊断队列在压力下保持配置上限，无持续内存增长或静默消息损失。
- [ ] 文件可从任意已确认块恢复并通过最终 BLAKE3；非幂等 RPC 断线返回 `outcome_unknown`。
- [ ] Shell 未授权、文件越界、超额资源、协议降级、伪造签名和重放全部默认拒绝。
- [ ] relay 数据库、日志、WSS 终止点和 TURN 抓包均不能恢复授权密码、verifier、私钥或业务明文。
- [ ] TUI 仅通过 Heyaki 公共 API 覆盖全部正式能力；高频事件与窄终端下仍保持有界刷新和可用布局。
- [ ] Linux/Windows 发布矩阵、sanitizer、fuzz、长稳、故障注入、兼容性和安全评审全部通过或有明确阻断结论。

## 实施记录

### Round 1（2026-09-05）：M9-01 设备端指标聚合与导出

交付物：

- `include/heyaki/node.hpp`：`NodeMetrics` 聚合模型（node/pairing/connectivity/
  transport/channels/services/runtime 七段）+ `NodePairingMetrics`、
  `NodeConnectivityMetrics`（含 `record_authenticated` 结果/路径/时长记账）、
  `NodeTransportGauges`、`NodeChannelMetrics`；`Node::metrics()`。
- `include/heyaki/metrics.hpp` + `src/core/metrics.cpp`：
  `format_node_metrics_prometheus`（文本格式 0.0.4 子集，HELP/TYPE 齐备、counter
  带 `_total`、可选 instance 标签并做转义；~200 个指标族）。
- `src/client/pairing_service.{hpp,cpp}`：`PairingServiceStats` 在 `audit()` 汇聚点
  无条件递增（与 audit_sink 配置解耦）。
- `src/client/node.cpp`：`PeerAttempt::begun_at`；入站/出站 attempt 创建计
  `connections_initiated`；`peer_session_changed` 在 authenticated（经
  `peer_session_snapshot` 取实时 data_path/rtt）、pairing_restricted、closed（失败/
  superseded 分流）转移点记账；prune tick 在 service diagnostics 之外同拍发布
  `NodeMetrics`（`executor::comm::DoubleBuffer`，与既有模式一致）。
- `tests/unit/m9_metrics_test.cpp`：格式良构性校验（每行可解析、HELP==TYPE、
  计数≥阈值）、配对块 golden 钉死、instance 转义、`record_authenticated` 单元、
  双节点 LAN 真会话端到端（idle 快照 → connect → authenticated 计数/时长/传输
  gauge/executor 关联字段全链路断言）。

数据来源映射（架构 §13.2 → 现有面）：注册/租约/WSS 重连 → `NodeSnapshot.relay`；
multicast/presence/TLS 分类 → `NodeSnapshot.{directory,tls,announcements_*}` 与接口
快照；配对/TrustGrant → 新增 pairing 计数器；route/直连率/失败原因 → 新增
connectivity 计数器（coordinator 拒绝原因计数既有）；RTT/buffered → 传输 gauge；
channel 队列 → `SessionChannelManager::channel_snapshots()` 聚合；RPC/事件/文件/
Shell → 五个服务 Stats（既有）；executor failure/status 与 metrics mailbox comm
stats → 内嵌 `RuntimeSnapshot`（提交拒绝、任务异常、wait 超时、mailbox
overwrite/stale/lag）。

### 剩余范围（M9-01 完成前）

- §13.2 "注册成功率/租约续期失败"缺独立计数器（relay 客户端现有
  heartbeats/reconnect 是替代面）：需在 relay enrollment/WSS 客户端补
  registration_attempts/success/lease_refresh_failure 计数。
- "信令 fallback/winner"聚合（现有 per-attempt 快照无 winner 计数）、"丢包估计"
  （libdatachannel stats 已启用但未聚合）、TUI 队列深度/渲染延迟（TUI 侧导出）。
- Prometheus 指标族语义评审 + M9-03 correlation ID 与 instance 标签打通
  （本轮已支持 instance 标签注入，operation/transfer 级关联待 M9-03）。
- M9-02 relay 侧导出（`RelayServerSnapshot` 数据面已齐，缺 Prometheus 端点与
  结构化日志）；M9-04/05 dashboard 与 runbook 以本轮指标族为输入。
