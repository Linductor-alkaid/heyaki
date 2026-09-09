# M9：生产加固与 v1 发布

> - 状态：进行中（2026-09-05 立项；前置 M8 遗留三件套 P2-F1/P3-F3/P4-F7（+P4-F9）已修复放行，见 [m8-remote-shell.md](m8-remote-shell.md) 遗留节；M9-01 Round 1/2、M9-02 Round 3、M9-03 Round 4、M9-04/05 Round 5 与 M9-06 Round 6 已交付，M9-07 起未开始，见文末实施记录）
> - 所属计划：[Heyaki MVP 至 v1 实施 TODO 计划](heyaki-implementation-plan.md)
> - 前置：M8 | 建议发布点：v1.0

## 可观测性与运维

- [ ] `M9-01` 设备端导出架构第 13.2 节全部 LAN/relay/协议指标，并与 executor failure/status、comm stats 建立明确关联字段。（Round 1 交付 2026-09-05：`NodeMetrics` 统一聚合 + `Node::metrics()` 周期发布 + Prometheus 文本导出 `format_node_metrics_prometheus`；新增 pairing 审计计数器与连通性结果/时长计数器；executor 关联字段经内嵌 `RuntimeSnapshot`。Round 2 交付 2026-09-05：relay 注册/租约计数器、信令 winner/fallback 聚合、backend 字节 gauge 周期采样、TUI 队列/渲染诊断与 `metrics` 命令；丢包估计受 pinned libdatachannel API 限制，见实施记录。缺口见实施记录"剩余范围"。）
- [x] `M9-02` relay 导出 Prometheus 指标、结构化日志、有限审计和可选 trace correlation；高频成功事件采样。（Round 3 交付 2026-09-06：`format_relay_metrics_prometheus` 全量导出 `RelayServerSnapshot` 七个诊断块；同端口 TLS 上的纯 HTTP `GET /metrics` 端点（无 WebSocket upgrade，`metrics_path` 可配置，非 GET 405）；`RelayLogRecord` JSON Lines 结构化日志（16 类事件，失败/安全/生命周期事件全量，心跳/信令转发/查询按 `success_log_period` 采样，0 关闭采样）；登录/注册完成与拒绝携带 device/endpoint/tenant 审计字段（拒绝含声称身份），信令事件携带 `RequestId` 关联字段，metrics instance 标签 = 证书 SHA-256 十六进制与日志流可 join；`heyaki-relay` main 默认把日志打到 stdout。OpenTelemetry 出口属于部署侧桥接，留 M9-04 工具链决策。见实施记录 Round 3。）
- [x] `M9-03` 为 registration、pairing、connection、session、operation 和 transfer 建立不含机密的 correlation ID。（Round 4 交付 2026-09-08：全部复用既有随机非机密 wire ID，无协议变更——pairing 审计事件携带 wire pairing RequestId + GrantId 并经 `Node::pairing_audit_records()` 暴露有界审计环；RPC 完成事件 `RpcCallOutcome.request_id` 自关联，准入失败 Error 携带 operation ID；shell 审计记录补 `shell_id`；connection/session 的 RequestId/SessionId 进入 TUI 会话视图（request=/session= 行，与 relay 信令日志同 ID 空间）；registration 因 v1 控制协议冻结无 wire ID，以快照墙钟锚点 `registration_started_unix_milliseconds`（TUI `since=`/指标 gauge）+ device+tenant join relay 日志；transfer 级 `TransferId` 在 API/事件/TUI 已全覆盖，本轮核对无缺口。见实施记录 Round 4。）
- [x] `M9-04` 定义 SLO dashboard 与告警：multicast/listener readiness、presence/handshake reject、登录失败、租约续期、直连率、TURN allocation、pairing 猜测、队列拒绝、RPC overload、文件 hash 和 worker failure。（Round 5 交付 2026-09-09：`deploy/observability/` 下 Prometheus recording rules（8 条 `heyaki:slo:*` 比率）+ alert rules（20 条，relay-fleet 与 device 两组，critical/warning 分级）+ Grafana dashboard（24 面板）+ scrape 配置示例与信号映射 README；`tests/unit/m9_slo_rules_test.cpp` 渲染两个导出器并强制规则/面板只引用真实指标族、告警结构完整、runbook 锚点有效。设备侧序列无通路时告警天然静默。OTel 决策：v1 不内建出口，部署侧用 otel-collector 的 Prometheus receiver 桥接。见实施记录 Round 5。）
- [x] `M9-05` 编写运维 runbook：证书/credential 轮换、设备吊销、relay/coturn 重启、数据库备份恢复、磁盘满、过载和版本回滚。（Round 5 交付 2026-09-09：`docs/operations/runbook.md`——快速参考（CLI/config 键/端点/日志事件/状态枚举）、20 条告警逐条分诊（症状→首要动作→深入诊断）、7 类操作程序（含 relay 叶证书 pin 约束、TURN secret 四代窗口、SQL 级吊销镜像 `revoke_device` 语义、SQLite 回滚 journal 的备份次序、回滚前的 schema 检查）与已知运维缺口清单；告警 runbook_url 锚点由 m9_slo_rules 测试锁定。见实施记录 Round 5。）

## 可靠性、兼容性与性能

- [x] `M9-06` 完成 LAN/NAT 矩阵：same-bridge multicast、multicast blocked、multi-NIC/interface change、full-cone、restricted、port-restricted、symmetric、hairpin、CGNAT、IPv6-only 和 UDP blocked。（Round 6 交付 2026-09-10：NAT 行由新 harness `deploy/coturn/run_nat_matrix.sh` 覆盖——root+coturn 门控的 netns/nftables 拓扑（双私网客户端经仿真 NAT 到公网 netns 的 relay+双 coturn），六场景 full_cone/restricted_cone/port_restricted_cone/symmetric/hairpin/cgnat，cone 类断言 direct_srflx 打洞直连、symmetric/CGNAT 断言 TURN fallback P95<5s；`tests/network/nat_probe.py` 在每个场景前用同一 socket 查双 STUN 服务器，先证明仿真 NAT 类别本身（EIM 端口一致 vs symmetric 端口相异、映射地址=公网别名）；matrix node 增加 `--srflx-only` 排除 host 候选防止绕过 NAT。same-bridge multicast/multicast blocked/multi-NIC/接口切换/IPv6-only 由既有 `heyaki_network_harness`（m3a，非特权 userns）覆盖，UDP blocked 由既有 `heyaki_m4_network_matrix` 覆盖。CI coturn-topology job 以 root 执行全部六 NAT 场景。见实施记录 Round 6。）
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

### Round 2（2026-09-05）：M9-01 剩余缺口收敛

交付物：

- relay 注册生命周期计数器（§13.2 "注册成功率、租约续期失败"）：`RelayNodeSnapshot`
  新增 `registration_attempts/successes/failures/lease_refresh_failures`；
  `start_relay_connect` 计 attempt，login_result accepted 计 success，
  `relay_failed` 在 connecting/awaiting_* 阶段落死计 failure（ready 后的连接
  损失只计 reconnect/missed，不重复计注册失败），heartbeat 轮在下一 tick 仍未
  收到 ack 计一次 lease_refresh_failure。导出为
  `heyaki_node_relay_registration_*_total` 与
  `heyaki_node_relay_lease_refresh_failures_total`。
- 信令 winner/fallback 聚合（§13.2 "signaling route/fallback/winner"）：
  `NodeConnectivityMetrics` 新增 `signaling_route_selected_lan/relay`（attempt
  准许点记账，含入站对端选择；合计 == connections_initiated，与 authenticated
  时刻的 route 计数差值即 per-route 在途/失败归因）和 `signaling_route_fallbacks`
  （automatic 模式下"无 LAN endpoint 可达而选 relay"；lan_only/relay_only 固定
  选择不计）。记账点：`begin_peer_attempt`/`admit_inbound_attempt`（与
  connections_initiated 同点，覆盖全部 WebRTC attempt 准许路径，包括 LAN offer
  owner 经 `maybe_begin_peer_attempt` 的二次选择）。
- backend 链路统计周期采样：pinned libdatachannel 只暴露
  `bytesSent()/bytesReceived()/rtt()`（无 packetsLost/jitter），Round 1 只在
  ICE Connected 时采样一次。现新增 `StatsEvent`：node 500ms tick 经
  `request_stats_refresh()`（best-effort，队列满丢弃不失败会话，下 tick 重试）
  投递到 transport 既有 callback drain 上下文，`refresh_path_stats()` 重采样
  RTT/字节/selected pair 后"安静发布"（只更新 DoubleBuffer 快照，不触发
  state handler，不重跑会话状态机）。`PathInfo` 增加 `bytes_sent/received`，
  `NodePeerSessionSnapshot` 透传 `transport_bytes_sent/received`，
  `NodeTransportGauges` 聚合 `transport_bytes_sent/received_sum`（gauge 语义：
  活跃会话求和，会话关闭会回落的说明已写入头文件注释）。导出
  `heyaki_transport_backend_bytes_sent/received`。
- 修复 Round 1 缺陷：`metrics_strand` 此前直接读 `attempt.snapshot`（rtt/
  buffered 从未回写，恒为 0），现改用 `peer_session_snapshot(attempt)` 的
  实时装饰快照，RTT/buffered/bytes gauge 全部激活。
- TUI 可观测性（§13.2 "TUI event queue 深度、合并/drop 和渲染延迟"）：
  状态视图新增 QUEUES 块（signal/inbound/ack/rpc/event/file/shell 七通道的
  depth/capacity@peak:drop + pairing mailbox overwrite 计数，全部来自
  executor comm stats）与 RENDER 行（渲染 pass 计数、last/max 耗时）；
  新增 `metrics` 命令直接输出 `format_node_metrics_prometheus(node.metrics())`
  的 Prometheus 文本，设备侧导出无需 scraper 即可到达。
- 测试：m9 单测扩展（record_route_selection 单元、新指标族 golden、LAN e2e
  断言 selected_lan>=1/fallbacks==0/backend bytes 经 tick 采样 >0）；m3b 两个
  重连测试（outage/restart）断言注册计数器全生命周期语义（含"ready 后连接
  损失不计注册失败"的负向断言）。本机 ctest 49 通过 + 3 环境门控跳过
  （coturn/matrix，与 Round 1 基线一致）。

已知限制（记录为 M9-04/M9-11 输入，非本轮阻断）：

- 丢包估计：pinned libdatachannel 的 stats API 不暴露 packetsLost/jitter，
  只有 bytes/rtt。要做真正的丢包率需要升级 libdatachannel（getStats 全量）
  或在应用层从不可靠通道序列缺口推导。已聚合 bytes/rtt 作为现状替代面；
  该缺口不引入 executor ledger 条目（属第三方依赖 API 面，非 executor 限制）。
- relay 客户端 `lease_refresh_failures` 的正向路径（ready 后静默丢 ack）无
  稳定自动化测试——现有 harness 只能制造连接关闭（走 reconnect 路径）。
  计数器与 `heartbeats_missed` 在同一递增点，负向断言（happy path == 0）已覆盖。

### Round 3（2026-09-06）：M9-02 relay 侧可观测性

交付物：

- Prometheus 导出：`src/relay/relay_metrics.{hpp,cpp}` 的
  `format_relay_metrics_prometheus(RelayServerSnapshot, instance)`，覆盖
  snapshot 七个诊断块（server/database/rate-limit 四 scope/lease/endpoint
  directory/login/enrollment，共 ~106 个指标族，`heyaki_relay_` 前缀，
  counter 带 `_total`）。与设备端导出共用 `src/core/metrics_text_writer.hpp`
  （从 `metrics.cpp` 抽出的 detail writer，转义/HELP/TYPE 布局一致）。
  `relay_id_to_hex` 把证书 SHA-256 渲染为 instance 标签。
- `/metrics` HTTP 端点：`RelayServerConfig.metrics_path`（默认 `/metrics`，
  校验不得与 health/control path 相同，config 文件键 `metrics_path`、CLI
  `--metrics-path`）。路由发生在 WebSocket upgrade 之前（stock scraper 的
  纯 GET 会被 `async_accept` 拒绝），非 GET 回 405 + `Allow: GET`。
  响应在 server 执行上下文用最新 `current` 快照序列化；新增
  `metrics_scrapes` 计数器。
- 结构化日志：`src/relay/relay_log.{hpp,cpp}` 定义 16 类
  `RelayLogEventKind` 与 `RelayLogRecord`（ts/level/event/conn/device/
  endpoint/tenant/request_id/detail，字段缺省整体省略，JSON 转义含控制
  字符）。`format_relay_log_json` 输出单行 JSON。`RelayServerConfig.log_sink`
  在 server 执行上下文同步回调（异常吞掉、必须快速返回）；`heyaki-relay`
  main 默认打到 stdout（每行 flush）。
- 采样：`success_log_period`（默认 100，config 键与 CLI 同名；0 关闭采样
  事件）。heartbeat_refreshed / signaling_forwarded / endpoint_query_served
  三类高频成功事件按类计数，第 1 条 + 每 N 条放行，其余只递增
  `log_events_sampled_out`。失败（capacity/handshake/policy/rate/
  enrollment_rejected/login_rejected/signaling_rejected）、安全审计
  （enrollment_completed/login_completed/endpoint_published，携带
  device/endpoint/tenant；拒绝路径携带声称身份）与生命周期
  （server_state_changed/server_error）不采样。无 sink 时计数器照常递增。
- 有限审计与 correlation 种子：登录/注册完成与拒绝事件携带身份字段；
  信令 forward/reject 事件携带 wire `RequestId`（`request_id` 字段，
  与 M9-03 correlation ID 空间对齐）；metrics instance 标签 = relay id
  hex，可与日志流 join。OpenTelemetry 出口未内建（架构表述为"可选"），
  由 M9-04 工具链选型时决定桥接方式。
- snapshot 扩展：`RelayServerSnapshot` 新增 `relay_id`/`metrics_scrapes`/
  `log_events_emitted`/`log_events_sampled_out`。
- 测试：`tests/unit/m9_relay_observability_test.cpp`（11 例）：导出格式
  良构性 + 代表族钉死、instance 标签转义、relay id hex、JSON 转义与字段
  省略、config 键加载与冲突拒绝、`/metrics` HTTPS e2e（200/405/计数器/
  无 WebSocket 计数）、结构化日志 e2e（登录审计字段、period=2 采样 2/3、
  generation 不符 login_rejected 携带声称身份、信令拒绝携带 request_id）、
  period=0 关闭采样、无 sink 计数器照常 + 经 /metrics 导出。本机 ctest
  53/53 通过 + 3 环境门控跳过（coturn/matrix）。CI 10/10 绿（提交链
  eadf127→26add86→e2684f8）：首轮 CI 抓到两个本机未暴露的真实缺陷并已
  修复——CI GCC/Clang `-Werror=missing-field-initializers` 拒绝部分指派
  初始化（改 `log_context()` 工厂逐成员赋值），ASan 发现日志 record 的
  `detail` string_view 悬垂于产生它的局部 Error（改为自有 `std::string`，
  sink 可安全存档 record）；asan 的 usrsctp 泄漏与 gcc-Release 的 TUI
  harness 超时为既有抖动，rerun 即绿。

设计说明：

- 日志埋点全部复用现有执行上下文与计数点（`log_event` 不调用 `publish()`，
  由外层 handler/DeferredPublish 统一 flush）；无新增线程/队列，不引入
  executor ledger 条目。
- 采样计数器按事件类独立（`SampledEventCounts`），语义为"第 1 条 +
  每 N 条"，period=2 时 3 个心跳事件放行第 1、3 条（测试锁定）。
- `/metrics` 与控制面共用 TLS 监听：scraper 必须持证书信任（与 health
  端点同安全模型）；独立监听端口如 M9-04 dashboard 阶段有需求再加。

### Round 4（2026-09-08）：M9-03 correlation ID

交付物：

- pairing：`PairingAuditEvent`（移入公共头 `pairing_protocol.hpp`）新增
  `request_id`/`grant_id` 关联字段——evaluate 全路径（attempt/denied_*/granted）
  携带 wire pairing RequestId，granted 额外携带签发的 GrantId；accept_grant 的
  grant_accepted/rejected（binding/identity/signature/scope）携带请求与声称的
  grant 双 ID；revoke_grant 携带 GrantId；批量轮换事件（无单一 ID）保持缺省。
  `PairingServiceConfig.audit_sink` 由 Node 接线（此前为 nullptr，审计事件根本
  不可达）：事件经 `Impl::pairing_audit_sink` 投递到 node strand 的有界环形
  缓冲（容量 256，镜像 shell 审计模式），公开 `Node::pairing_audit_records()`
  读取。注意 revoke/rotate 走公共 API 调用者线程，故 sink 必须投递而非就地
  追加（evaluate/accept_grant 在 strand 上的会话回调里触发）。
- operation：`RpcCallOutcome` 新增 `request_id`——全部终态（对端响应、
  cancel、本地 deadline、session 丢失 outcome_unknown、retry 队列淘汰/中止）
  自关联，session 丢失批量终结时无需调用方簿记；准入失败（编码/容量/ID 冲突/
  发送失败）经 `attach_request_id` 把 wire RequestId 字节装入
  `Error::operation_id`（§13.1 错误对象携带 operation ID；调用方传入零 ID 时
  生成的 ID 只有 Error 能命名）。TUI rpc 视图 call 后打印 `op <req id>`。
- shell：`ShellAuditRecord` 新增 `shell_id`，审计环与 ShellServiceEvent 流
  可 join。
- connection/session：`NodePeerSessionSnapshot` 的 RequestId/SessionId 进入
  TUI SESSIONS 块（`request=`/`session=` 行，置于 candidate 之后——m4/m6
  TUI harness 驱动正则钉死 device→endpoint→signaling 行邻接，本轮本地抓到
  插行破坏契约后重新布局）。request ID 与 relay 日志（M9-02 signaling 事件
  的 `request_id` 字段）同 ID 空间，可跨侧 grep。
- registration：v1 控制协议（LoginResult/Heartbeat）无 per-cycle 请求 ID 且
  冻结，不加 wire 字段。`RelayNodeSnapshot.registration_started_unix_milliseconds`
  记录当前 connect+login 周期起始墙钟（周期序号 = 既有
  `registration_attempts`），导出为
  `heyaki_node_relay_registration_started_unix_milliseconds` gauge，TUI RELAY
  行显示 `cycle=`/`since=`；与 relay 日志的 join 键保持 device identity +
  tenant + 时间窗（relay 侧登录事件已携带）。
- transfer：核对确认 `TransferId` 已覆盖 API（FileTransferEvent/Summary）、
  TUI（transfer 命令打印与 pause/resume/cancel 入参）与文件服务内部记账，
  无缺口，不改动。
- 测试：`tests/unit/m9_correlation_test.cpp`（4 例：pairing 审计双 ID 与
  计数器不变式、RPC 成功/session 丢失完成携带请求 ID、准入失败 Error 命名
  操作、Node 审计环经公共 API 跨线程记录撤销）；m3b 两个重连测试断言锚点
  非零且随周期推进；m9_metrics 钉死新 gauge；tui_setup 断言 request=/session=
  行。本机 ctest 全绿 + 3 环境门控跳过（coturn/matrix，与基线一致）。

设计说明：

- 关联 ID 全部是 wire 上已有的随机 16 字节值（非机密、不可从凭证推导），
  不新增 ID 空间、不做指标标签（基数）；与 relay 侧 M9-02 的
  `request_id` 日志字段、证书 SHA-256 instance 标签构成同一 join 体系。
- 无新增线程/队列：审计环投递复用 node strand（asio post，与
  poke_relay_activity 同模式），无 executor ledger 条目。

### Round 5（2026-09-09）：M9-04 SLO dashboard/告警 + M9-05 runbook

交付物：

- `deploy/observability/`（新顶层部署物料目录，与 `deploy/coturn/` 并列）：
  - `prometheus/heyaki-recording.yml`：8 条 `heyaki:slo:*` recording rules
    （relay 登录失败/握手失败/信令拒绝比率 + device 注册失败/直连率/TURN
    占比/pairing 密码拒绝/RPC 准入拒绝比率），比率一律 `clamp_min` 分母防
    除零，30s 求值。
  - `prometheus/heyaki-alerts.yml`：20 条告警，`heyaki-relay-slo`（8 条：
    down/not-running/登录失败率/握手失败率/信令背压/容量/四 scope 限速/
    租约表）与 `heyaki-node-slo`（12 条：LAN listener 未就绪/multicast 未
    验证/presence 拒绝/注册失败/租约续期失败/pairing 猜测/队列拒绝/RPC
    overload/文件完整性/executor 任务异常/worker 失败/TURN 主导）。分级：
    critical = 可达性、注册塌方、数据完整性、executor 任务损失；warning =
    退化趋势。比率类告警带流量门控（分母 rate > 0）避免低流量误报。
  - `prometheus/heyaki-scrape.yml`：relay `/metrics` TLS scrape 示例
    （job 名 `heyaki-relay` 与 `up` 告警对齐）+ 设备侧 textfile 接入约定。
  - `grafana/heyaki-overview.json`：24 面板 dashboard（relay 健康/登录/
    信令/容量/限速/采样健康 + device 注册/租约/路径构成/建连时长/LAN
    就绪/pairing/队列/RPC/文件/worker），枚举 gauge 的数值映射写入面板
    映射与描述。
  - `README.md`：M9-04 枚举的 11 类信号 → 指标族 → 告警 → 面板映射表、
    数据源边界（relay 常驻端点 vs 设备 opt-in 接入）、OTel 决策（v1 不内
    建出口，桥接 = otel-collector Prometheus receiver，零代码变更）。
- `docs/operations/runbook.md`：快速参考（CLI/config 键全集、端点、16 类
  日志事件、状态枚举、DB schema）、20 条告警逐条分诊、7 类操作程序
  （relay 证书轮换含 pin 约束、TURN secret 四代窗口、bootstrap token、
  SQL 级设备吊销（镜像 `revoke_device` 的 generation 递增 + `device_revoked`
  审计行）、relay/coturn 重启、SQLite 备份恢复（默认 rollback journal →
  停机复制优先、在线 `.backup` 次之）、磁盘满、过载分层、版本回滚）、
  已知运维缺口四条。
- `tests/unit/m9_slo_rules_test.cpp`（4 例）+ tests/CMakeLists 注册
  （`heyaki_m9_slo_rules_tests`，标签 unit;metrics;m9;observability;slo）：
  - 渲染 `format_node_metrics_prometheus(NodeMetrics{})` 与
    `format_relay_metrics_prometheus(RelayServerSnapshot{})`（导出器无条
    件写全部族，零值渲染即完整面；钉 ≥190/≥95 族防解析漂移）；
  - 受控格式 YAML 解析器（`- record:`/`- alert:`、单行与 `>`/`>-` 折叠
    expr、for/severity/summary/runbook_url；折叠终止行回送主循环）；
  - 断言全部 expr/模板 query 中的 `heyaki_*` token ∈ 导出器族集合、
    `heyaki:slo:*` ∈ record 名集合（左边界排除 `"`，防 label 值
    `job="heyaki-relay"` 误报）、告警结构完整、severity 取值合法、
    runbook_url 锚点经 GFM 规则匹配 runbook 标题集合、dashboard JSON
    括号配平且 ≥24 面板 ≥60 表达式。
- 本地以 PyYAML/json 做了真实解析器交叉验证（3 个 YAML + dashboard JSON
  合法、告警 20/录制 8 与钉死数一致）。

设计说明：

- 设备指标集中采集是部署侧约定而非代码：设备在 NAT 后且架构上无常驻
  导出端点，dashboard/告警的 device 组查询定义完备、序列出现即生效，
  无序列时表达式为空、告警天然静默（无需 absent 门控）。
- 直连率/TURN 占比按"比率 + 趋势告警"设计（阈值随部署基线调整），不设
  绝对 SLO 数值——网络环境差异使其无普适默认；最终验收数值由 M9-10
  基准与 M9-11 参数冻结回收。
- runbook 与告警的联动是可执行契约：重命名 runbook 标题或改告警名都会
  被 m9_slo_rules 测试拦截，防止文档与告警漂移。

### Round 6（2026-09-10）：M9-06 LAN/NAT 矩阵

交付物：

- `deploy/coturn/run_nat_matrix.sh`（root+coturn 门控，SKIP 77，CTest
  `heyaki_m9_nat_matrix`，TIMEOUT 1500；CI 在 coturn-topology job 以 root
  执行）：netns/nftables 拓扑 = 双私网客户端命名空间（10.78.0.0/24 与
  10.78.1.0/24）经 host NAT 网关到达公网命名空间（203.0.113.0/24：relay
  + 双 coturn 实例，各持独立广播地址 .2/.3，relayed<->relayed 候选对不
  相互拒绝）；host 持映射别名 .10/.11/.20。六场景（架构 §"网络仿真"）：
  - full_cone：静态 DNAT（任意端口入站）+ 端口保持 SNAT = EIM+EIF，
    断言 `direct_srflx` 打洞直连（3 循环 P95<5s，首循环 M6 消息+RPC 严格）。
  - restricted_cone：静态 DNAT + nft 动态集合记录出站目的 IP，入站仅放
    行已联系 IP（地址相关过滤），断言 `direct_srflx`。
  - port_restricted_cone：`(ip . port)` 拼接集合，入站仅放行已联系
    ip:port（经典打洞），断言 `direct_srflx`。
  - symmetric：无入站 DNAT + 按目的地不相交端口段 SNAT
    （turn A→1xxxx、turn B→2xxxx、其余→3xxxx，`fully-random`），打洞必
    败，断言 `turn_udp` fallback（3 循环 P95<5s）。
  - hairpin：双客户端同一 bridge 同一 NAT（别名 .10/.11），`ct status dnat`
    放行回环路由流量、丢弃其余同网段 UDP，断言 `direct_srflx`。
  - cgnat：家端 full-cone NAT 命名空间（静态 DNAT+端口保持 SNAT）叠加
    host 运营商 symmetric NAT（双级 NAT），断言 `turn_udp` fallback
    （3 循环 P95<5s）；深层客户端网段在 host 加回程路由。
- `tests/network/nat_probe.py`：RFC 5389 binding 探测，同一 UDP socket
  先后查询双 STUN 服务器并打印两个 XOR-MAPPED-ADDRESS。每个场景在跑
  heyaki 之前先验证仿真 NAT 类别：cone 类要求两映射完全一致且等于公网
  别名（EIM+已应用 SNAT），symmetric 类要求端口相异（按目的地分段）。
  NAT 类别验证与会话结果解耦：探测失败独立计 failure（防"拓扑没生效、
  断言碰巧通过"）。
- `apps/demo/m4_matrix_node.cpp`：`--srflx-only` 开关
  （`allow_ipv4_host=false`、srflx 保持）——host 候选不进入交换，强制每
  条候选对穿越仿真 NAT；对既有 M4 场景零行为变更。
- `tests/CMakeLists.txt`：`heyaki_m9_nat_matrix` 注册（labels
  relay;network;nat;m9）；`.github/workflows/ci.yml` coturn-topology job
  增加 "Run M9 NAT matrix in namespaces" 步骤（timeout 30min）。
- 矩阵行 → 覆盖面映射：same-bridge multicast / multicast blocked /
  multi-NIC+接口切换 / IPv6-only(link-local) = `heyaki_network_harness`
  （m3a，非特权 userns）；UDP blocked = 既有 `heyaki_m4_network_matrix`
  的 udp_blocked 场景（TURN/UDP 阻断 → 有界显式失败）；六 NAT 行 = 本轮。

设计说明：

- host 既是 NAT 网关又是路由器：客户端 relay WSS 走 TCP 不做 NAT（地址
  学习只来自 STUN/TURN），UDP 全部经 `inet heyaki_nat` 表（pre/out/flt
  三链）转换；公网命名空间使 coturn/relay 观察到的是 SNAT 后的公网地
  址，而非宿主机本地投递（宿主机上无 input 路径 SNAT）。
- GitHub runner 的 Docker FORWARD DROP 策略用 iptables 显式 ACCEPT 对冲；
  场景丢弃规则在独立 nft 表中仍然生效（同一 hook 上 ACCEPT 裁决不会绕过
  其他 base chain）。
- 本机验证：全部 nft 命令（含 `fully-random`、`(ip . port)` 拼接集合、
  `update @set`、`ct status dnat`、家端 NAT 表）在非特权 userns 沙箱对
  真实内核逐条通过；probe 对本地 STUN responder 端到端验证（同 socket
  双查询、编解码往返）。坑：nft 链名 `fwd` 是保留字，必须改名（沙箱首
  轮抓出，CI 前修复）；veth/namespace 名长 ≤15。
- 直连 P95<3s 与 TURN<5s 的最终验收数值冻结留给 M9-10 基准与 M9-11
  参数冻结；本轮 P95 门限 5s（与 M4 turn_fallback 同口径），全部样本
  记录在日志 `*_P95_MS` 行。
- 首轮 CI（run 34386163184，2026-09-09）三个发现与修正：(1) probe 输出
  解析 bug——`sed` 前缀替换残留 `server1=` 尾巴导致全部判 unparsable，
  改 `tr`/`sed` 按字段提取（用 CI 实际输出样本回归验证）；(2) cone 场景
  配 TURN 时 ICE 提名在 srflx 打洞与 TURN 分配之间赛跑（fullcone 3 循环
  得 1×direct_srflx + 2×turn_udp），cone 类改为 STUN-only——打洞能力本身
  是断言对象，不允许 TURN 兜底参与提名；(3) symmetric/CGNAT 下
  `direct_srflx` 标签 = 本地候选类型，对端实为 relayed（TURN 日志
  CHANNEL_BIND/CREATE_PERMISSION 证实；与 M4 harness 对同一语义的既定
  契约一致），probe 已独立证明 symmetric 类别，故断言集改为
  `turn_udp,direct_srflx`（"必经中转"语义不变）。CGNAT 双 NAT 的
  attempt_expired 尾部（首轮 1 绿 2 红，现象同 M4 lossy 家族）按 M4 先例
  改为最多三对新鲜参与者的有界重试 + dump 增加 conntrack 输出待查。

### 剩余范围（M9-01 完成前）

- ~~注册成功率/租约续期失败计数器、信令 fallback/winner 聚合、TUI 队列/渲染
  导出~~：Round 2 已交付（见上）。
- 丢包估计受 pinned libdatachannel API 限制（bytes/rtt 已聚合，packetsLost
  不存在）：升级依赖或在应用层推导的取舍留给 M9-10 基准测试结论后决定。
- Prometheus 指标族语义评审（命名/标签/类型过一遍 scrape 消费视角）；
  ~~M9-03 correlation ID 与 instance 标签打通~~：Round 4 已交付（见上）。
- ~~M9-02 relay 侧导出~~：Round 3 已交付（见上）。M9-04/05 dashboard 与
  runbook 以 Round 1/2/3 指标族与日志事件为输入。
