# M9：生产加固与 v1 发布

> - 状态：已完成（2026-09-05 立项，2026-09-17 收官；前置 M8 遗留三件套 P2-F1/P3-F3/P4-F7（+P4-F9）已修复放行，见 [m8-remote-shell.md](m8-remote-shell.md) 遗留节；M9-01 Round 1/2、M9-02 Round 3、M9-03 Round 4、M9-04/05 Round 5、M9-06 Round 6、M9-07 Round 7、M9-08 Round 8、M9-09 Round 9、M9-10 Round 10（基准 harness + 同 kind 双流 UAF 修复）、M9-11 Round 11（参数冻结 + 孤儿 staging 清理）与 M9-12 Round 12（schema N-1/N 兼容 + rolling relay upgrade + 新旧设备互通）、M9-13 Round 13（fuzz 扩展 + regression corpus）、M9-14 Round 14（secret/vuln 扫描 + SBOM/许可证门禁 + 编译加固 + 发布签名）、M9-15 Round 15（安全回归八面：wire 伪造/重放/slowloris/退避指数/泄漏猎杀/伪造 grant·candidate·endpoint/文法表/服务端 oversized·1:1）、M9-19 Round 16（TURN/TCP 解封：libnice 双后端 + TURN/TLS 全后端硬拒绝）与 M9-16 Round 17（安装/配置/部署/API/故障排查五篇文档 + `heyaki_m9_docs_examples` 示例同步测试）、M9-17 Round 18（打包：版本 1.0.0、coturn 示例配置与 40+2 许可文本入安装树、package_release.sh 发布流（符号拆分/双 tar/卸载仿真）、uninstall target、heyaki_m9_package CTest）与 M9-18/M9-01 Round 19（v1 release checklist + 指标族语义评审收尾：两处 TYPE 矛盾修复 + 命名约定机械化强制 + 验收对账）已交付——**M9 全部条目完成**，最终 CI 状态见 Round 19 记录，见文末实施记录）
> - 所属计划：[Heyaki MVP 至 v1 实施 TODO 计划](heyaki-implementation-plan.md)
> - 前置：M8 | 建议发布点：v1.0

## 可观测性与运维

- [x] `M9-01` 设备端导出架构第 13.2 节全部 LAN/relay/协议指标，并与 executor failure/status、comm stats 建立明确关联字段。（Round 1/2 交付指标面；Round 11 决策丢包替代面；Round 19 收尾 = 指标族语义评审：全 376 族从 scrape 消费视角过命名/类型/单位/标签基数——修两处 TYPE 语义矛盾（enrollment/lease generation counter→gauge，HELP 原文自述 gauge semantics）、一处 counter 命名（event_lag_total_sequences→event_lag_sequences_total）；毫秒单位、手写直方图三元组、标签基数策略成文为约定（deploy/observability/README.md 新节）并由 heyaki_m9_slo_rules 新测试 `MetricFamiliesFollowNamingConventions` 机械化强制（counter 必 _total 除直方图三元组、gauge 禁 _total、HELP 必在 TYPE 前、新毫秒族须进冻结允许表）。无引用面破坏（dashboard/rules/golden 均未引用被改族）。）（Round 1 交付 2026-09-05：`NodeMetrics` 统一聚合 + `Node::metrics()` 周期发布 + Prometheus 文本导出 `format_node_metrics_prometheus`；新增 pairing 审计计数器与连通性结果/时长计数器；executor 关联字段经内嵌 `RuntimeSnapshot`。Round 2 交付 2026-09-05：relay 注册/租约计数器、信令 winner/fallback 聚合、backend 字节 gauge 周期采样、TUI 队列/渲染诊断与 `metrics` 命令；丢包估计受 pinned libdatachannel API 限制，见实施记录。缺口见实施记录"剩余范围"。）
- [x] `M9-02` relay 导出 Prometheus 指标、结构化日志、有限审计和可选 trace correlation；高频成功事件采样。（Round 3 交付 2026-09-06：`format_relay_metrics_prometheus` 全量导出 `RelayServerSnapshot` 七个诊断块；同端口 TLS 上的纯 HTTP `GET /metrics` 端点（无 WebSocket upgrade，`metrics_path` 可配置，非 GET 405）；`RelayLogRecord` JSON Lines 结构化日志（16 类事件，失败/安全/生命周期事件全量，心跳/信令转发/查询按 `success_log_period` 采样，0 关闭采样）；登录/注册完成与拒绝携带 device/endpoint/tenant 审计字段（拒绝含声称身份），信令事件携带 `RequestId` 关联字段，metrics instance 标签 = 证书 SHA-256 十六进制与日志流可 join；`heyaki-relay` main 默认把日志打到 stdout。OpenTelemetry 出口属于部署侧桥接，留 M9-04 工具链决策。见实施记录 Round 3。）
- [x] `M9-03` 为 registration、pairing、connection、session、operation 和 transfer 建立不含机密的 correlation ID。（Round 4 交付 2026-09-08：全部复用既有随机非机密 wire ID，无协议变更——pairing 审计事件携带 wire pairing RequestId + GrantId 并经 `Node::pairing_audit_records()` 暴露有界审计环；RPC 完成事件 `RpcCallOutcome.request_id` 自关联，准入失败 Error 携带 operation ID；shell 审计记录补 `shell_id`；connection/session 的 RequestId/SessionId 进入 TUI 会话视图（request=/session= 行，与 relay 信令日志同 ID 空间）；registration 因 v1 控制协议冻结无 wire ID，以快照墙钟锚点 `registration_started_unix_milliseconds`（TUI `since=`/指标 gauge）+ device+tenant join relay 日志；transfer 级 `TransferId` 在 API/事件/TUI 已全覆盖，本轮核对无缺口。见实施记录 Round 4。）
- [x] `M9-04` 定义 SLO dashboard 与告警：multicast/listener readiness、presence/handshake reject、登录失败、租约续期、直连率、TURN allocation、pairing 猜测、队列拒绝、RPC overload、文件 hash 和 worker failure。（Round 5 交付 2026-09-09：`deploy/observability/` 下 Prometheus recording rules（8 条 `heyaki:slo:*` 比率）+ alert rules（20 条，relay-fleet 与 device 两组，critical/warning 分级）+ Grafana dashboard（24 面板）+ scrape 配置示例与信号映射 README；`tests/unit/m9_slo_rules_test.cpp` 渲染两个导出器并强制规则/面板只引用真实指标族、告警结构完整、runbook 锚点有效。设备侧序列无通路时告警天然静默。OTel 决策：v1 不内建出口，部署侧用 otel-collector 的 Prometheus receiver 桥接。见实施记录 Round 5。）
- [x] `M9-05` 编写运维 runbook：证书/credential 轮换、设备吊销、relay/coturn 重启、数据库备份恢复、磁盘满、过载和版本回滚。（Round 5 交付 2026-09-09：`docs/operations/runbook.md`——快速参考（CLI/config 键/端点/日志事件/状态枚举）、20 条告警逐条分诊（症状→首要动作→深入诊断）、7 类操作程序（含 relay 叶证书 pin 约束、TURN secret 四代窗口、SQL 级吊销镜像 `revoke_device` 语义、SQLite 回滚 journal 的备份次序、回滚前的 schema 检查）与已知运维缺口清单；告警 runbook_url 锚点由 m9_slo_rules 测试锁定。见实施记录 Round 5。）

## 可靠性、兼容性与性能

- [x] `M9-06` 完成 LAN/NAT 矩阵：same-bridge multicast、multicast blocked、multi-NIC/interface change、full-cone、restricted、port-restricted、symmetric、hairpin、CGNAT、IPv6-only 和 UDP blocked。（Round 6 交付 2026-09-10：NAT 行由新 harness `deploy/coturn/run_nat_matrix.sh` 覆盖——root+coturn 门控的 netns/nftables 拓扑（双私网客户端经仿真 NAT 到公网 netns 的 relay+双 coturn），六场景 full_cone/restricted_cone/port_restricted_cone/symmetric/hairpin/cgnat，cone 类断言 direct_srflx 打洞直连、symmetric/CGNAT 断言 TURN fallback P95<5s；`tests/network/nat_probe.py` 在每个场景前用同一 socket 查双 STUN 服务器，先证明仿真 NAT 类别本身（EIM 端口一致 vs symmetric 端口相异、映射地址=公网别名）；matrix node 增加 `--srflx-only` 排除 host 候选防止绕过 NAT。same-bridge multicast/multicast blocked/multi-NIC/接口切换/IPv6-only 由既有 `heyaki_network_harness`（m3a，非特权 userns）覆盖，UDP blocked 由既有 `heyaki_m4_network_matrix` 覆盖。CI coturn-topology job 以 root 执行全部六 NAT 场景。见实施记录 Round 6。）
- [x] `M9-07` 在 Linux/Windows 双向组合验证 LAN-only、relay-signaled direct、TURN/UDP、TURN/TCP/TLS、Windows firewall/network profile、文件权限/命名和 PTY/ConPTY。（Round 7 交付 2026-09-11：Linux↔Windows 真跨机组合在 GitHub 托管 runner 上被平台能力阻断（runner 互不可达、WSL2 长期损坏），按"每 OS 全组合 + 双向发起 + 平台特有行为"解构——Windows CI 新增 `heyaki_windows_network_matrix`（`tests/network/run_windows_network_matrix.ps1`：lan_only/relay_direct/turn_udp 三场景发起方互换；TURN 由新 `heyaki-test-turn-server`（libjuice 内嵌 TURN/UDP，静态凭据经 matrix node 新 `--turn-username/--turn-credential` 覆写）提供，Windows 无 coturn。udp_blocked 在 Windows 单机不可仿真——WFP 豁免 loopback，程序级阻断规则碰不到同机 TURN server（CI 首跑实证），故由 Linux CI 的 m4 矩阵 iptables 场景覆盖、跨 OS 模式下 harness 显式支持），防火墙 harness 增加程序级放行规则的正向场景，矩阵节点新增 `--lan-only` 模式；跨 OS 阻断结论、TURN/TCP/TLS 依赖限制（pinned libjuice 客户端 UDP-only）与自托管混合机队程序记录于 `docs/operations/cross-os-matrix.md`。文件命名/权限与 PTY/ConPTY 经 Windows CI 既有套件覆盖（映射表见跨 OS 文档）。本机发现并修复 PeerSession 同域二次 open 竞争杀会话的真实缺陷（LAN offer-owner 侧服务挂载竞争 `subscribe_events`）。见实施记录 Round 7。）
- [x] `M9-08` 完成 relay 重启、coturn 重启、网络切换、credential 过期、磁盘满、慢消费者和任意关闭点故障注入。（Round 8 交付 2026-09-12：三面合成——进程级故障矩阵 `deploy/coturn/run_fault_matrix.sh`（CTest `heyaki_m9_fault_matrix`，root+coturn 门控 SKIP 77，CI coturn-topology job 执行）六场景：relay_restart_transfer（m7 传输在首个 transferring 相位确定性暂停→杀 relay→重启→恢复提交，直连数据面不依赖信令 relay）、turn_restart（双 coturn 杀死→已认证 TURN 会话经 ICE consent（RFC 7675，pinned libjuice 30s）显式关闭→coturn 重启后新参与者经 TURN 重建）、path_switch（同一对设备在 direct→blocked(TURN)→direct 三段网络条件下重建正确路径）、lease_expiry（SIGSTOP 冻结 responder 越过 3s 租约→endpoint 被逐出→解冻后 heartbeat 重插租约、新发起方可达）、slow_receiver（2 MiB 推入 4mbit/50ms 整形链路，限内有界完成）、stale_turn_credential（过期 REST 凭据→coturn 拒绝分配→有界显式失败）；matrix node 新增 `--m7-bytes/--m7-pause-hold-ms/--m7-wait-ms/--turn-credential-expiry-offset-ms`。磁盘满：`RLIMIT_FSIZE` 模式（EFBIG 为 ENOSPC 的可移植替身）两例单测——m7 接收方中途写失败→命名错误+无最终文件+staging 清理+sender 收到终态+限额恢复后重推字节一致；relay SQLite 写满→显式 storage 错误+已提交行保留+失败事务回滚+重开完好。任意关闭点：ProfileStore 崩溃矩阵模式克隆到文件服务——test-only 编译 `heyaki_file_fault_injection`（`HEYAKI_FILE_FAULT_POINT` 命中即 `_Exit(86)`）在 file_store 六个盘上边界（staging.after_create/chunk.after_write/state.after_write/commit.before_rename/commit.after_rename/commit.after_cleanup；state 写入经 thread_local 深度标记与 chunk 写区分）注入进程死亡，`tests/file/file_crash_probe.cpp` + `RunFileCrashTest.cmake` 驱动（CTest `heyaki_m9_file_crash_recovery`）：rename 前任意崩溃点最终文件不可见（原子性）、崩溃后同内容新传输提交且字节一致、残留 staging 不阻塞不毒化。既有覆盖映射：relay outage/backoff/进程级 relay_restart（m3b + M4 矩阵）、TURN 凭据/租约/token/grant 过期单测（fake clock 全绿）、同 transfer id 会话丢失恢复（m7 SessionLossPauses）、接口切换发现层（m3a HEYAKI_SWITCH_INTERFACE）、慢订阅者背压（m5/m6/m7 队列上限族）。见实施记录 Round 8。）
- [x] `M9-09` 执行 24/72 小时长稳、反复发现/过期/建连/断连和容量过载测试，证明内存、fd/handle、worker、session、endpoint directory 和 TTL/replay cache 有界。（Round 9 交付 2026-09-12：`tests/network/run_m9_soak_harness.sh`（CTest `heyaki_m9_soak`，`HEYAKI_REQUIRE_M9_SOAK=1` 门控 SKIP 77，CI coturn-topology job 以 Release 构建直跑）三相位——Phase A 会话 churn：matrix node 新 `--soak-cycles N` 让长存 initiator 在单进程内循环 dial/authenticate/m6+m7 演练/SIGKILL 断连（harness 每循环杀并重生 responder，同 profile 重登录重发布），每循环采样 RSS/fd/会话表/replay 深度/executor 任务 gauge（`SOAK_CYCLE` 行），`SOAK_SUMMARY` 携带门（work_done/closed_ok 全循环达成、live 会话排空、fds_first→last ≤ +24、RSS 增长 ≤ 32MiB、replay_peak ≤ per-peer 256）；Phase B 设备 churn：K 个短生命周期全新设备对同一长存 relay 顺序 enroll/login/publish/exit，每迭代 scrape `/metrics` 采样五个 gauge 族 + relay RSS/fd 门；Phase C 容量过载：第二个 tight relay（max_connections=3、endpoint_directory_capacity=2）承受 5 并发参与者，断言连接容量与目录容量拒绝计数器点燃、幸存者仍可登录、优雅退出后 lease/endpoint 表排空、RSS/fd 有界。CI 片段经 runbook 的"长稳（soak）测试"程序放大为 24/72h 运行（含验收门与斜率分析）。既有确定性单测映射：TTL 表容量/过期（m3b_relay_ttl）、endpoint directory 容量/代际/租户冲突（m3b_relay_endpoint）、replay cache 全局/per-peer/TTL（m4_signaling M4ReplayCache）、连接容量拒绝（m3b_relay ConnectionCapacityRejectsAboveBound）、限速四 scope（m3b_relay_wss_client/rate_limiter）、队列上限与慢消费者（m5/m6/m7 overflow 族）。关键发现：closed 会话进入 `finished_peer_sessions` 有界诊断史环（容量 1024）是设计行为——soak 门是"无 live 会话 + 总数随循环数有界"，不是"列表归零"。见实施记录 Round 9。）
- [x] `M9-10` 基准消息 latency、并发 RPC、事件 fan-out、单/多文件吞吐、Shell 竞争延迟、relay 内存和带宽。（Round 10 交付 2026-09-13：`tests/network/run_m9_bench_harness.sh`（CTest `heyaki_m9_bench`，`HEYAKI_REQUIRE_M9_BENCH=1` 门控 SKIP 77，CI coturn-topology job Release 直跑）三相位——Phase R 注册+直连 P95（fresh 进程对 ×N 循环，endpoint 表排空后下一轮），Phase T TURN fallback P95（双 `heyaki-test-turn-server` 静态凭据 + `--force-turn`，标签契约与 Windows 矩阵一致接受 `turn_udp|direct_srflx` 半中转对），Phase L 长存套件（matrix node 新 `--bench-initiator/--bench-responder/--bench-shell/--bench-connect-only` 模式：消息 RTT（顺序单在途 1KiB、终态事件采样、发送前 drain）、顺序/并发 RPC（16 窗口 × N 完成、按 wire RequestId 匹配、MpscChannel 交付）、事件 fan-out（N 订阅者 × 可靠 QoS × 时间戳载荷、逐订阅者 delivered/P95 门）、单文件/双并发文件吞吐、shell 敲键→回显延迟空闲 vs 2MiB 推送竞争下）；门 = v1 验收数值（登录 P95<2s/直连 P95<3s/TURN P95<5s）+ 零失败 + fan-out 全量送达 + 文件全部提交；`BENCH_METRIC`/`BENCH_THROUGHPUT`/`M9_BENCH_OK` 行即测量交付物（M9-11 输入）。runbook 新程序"Run a performance benchmark"。基准首跑与收敛过程抓出并修复 **三个真缺陷**（M4 同 kind 双流 UAF、m7 零字节伪 complete、m7 提前 complete，见 Round 10 记录）：双方同时为同一 ChannelKind 建流时，入站重复流的包装对象不在 transport `channels_` map 里，其 OpenEvent 把悬垂指针交给 pending open 完成——堆 UAF（ASan 钉死）；修复 = transport 级确定性收敛（offerer 的流胜出：offerer 拒绝重复流，answerer 在重复流 OpenEvent 时 promote 并退役自己的流；重复包装对象由 `duplicates_` map 持有；关闭/错误事件对重复流不传导为会话失败）+ 会话级 `adopt_physical_channel` 对非 initiator-owned 域（shell/stream）允许替换 + `TransportSession::async_open_channel` 契约文档化（answerer 竞争时 completion 指针需经 channel handler 修正）；回归测试 `M4WebRtcTransport.SimultaneousSameKindOpensResolveToRegisteredChannel`（真双侧 SCTP，offerer 拒绝 + answerer promote + 双向 roundtrip）。本机实测（debug/loopback）：登录 P95 22ms、直连 P95 1021ms、TURN P95 1077ms、消息 P95 2.7ms、RPC P95 2.3ms、并发 RPC P95 8.5ms、单文件 8MiB/s、双并发 9MiB/s、shell ping p50≈300ms（PTY 输出 500ms 维护 tick 的设计行为，M9-11 输入）、fan-out 三订阅者 10/10 送达。见实施记录 Round 10。）
- [x] `M9-11` 基于结果重新冻结默认容量、水位、timeout 和重试参数；默认值必须有测量依据和硬上限。（Round 11 交付 2026-09-13：[docs/operations/parameter-freeze.md](../operations/parameter-freeze.md) 冻结表（默认值 + 硬上限 + 测量依据三栏，M9-10 基准/ M9-09 soak / M9-06-08 矩阵数据为据，实测全部低于验收门、结论为默认值零调整）+ 九处校验补硬上限（RuntimeConfig 全部容量/线程/11 个生命周期超时、RelayNodeConfig 超时/心跳≤租约帽/退避/队列、RelayWssClientConfig、ChannelBudgetConfig、ByteStreamLimits、SignalingCoordinatorConfig、五个服务 attach、ShellProfileConfig 24h/7d/1GiB、RelayServerConfig 写队列帧/lease 子容量/限流策略前移）+ 新导出 `validate_config`/`validate_relay_node_config` 公共声明 + 孤儿 staging 清理（`file_store::sweep_stale_staging`：24h 年龄门（最慢实测传输三个数量级之外）、严格 `.heyaki-<32hex>.part/.state` 匹配不碰用户文件与目录、FileService attach 向阻塞 worker 投递 fire-and-forget 清理）+ Round 10 移交决策处置：shell 500ms tick 冻结（实测 p50≈300ms，事件驱动 drain 记 v1.x 候选）、packetsLost 维持 bytes/rtt 随 M9-19 后端切换重估、per-IP 32/s 保留 + NAT 共享出口部署观察项；`tests/unit/m9_parameter_freeze_test.cpp` 18 例钉死全部默认值与上限拒绝（漂移即红）。本机 ctest 61/61 全绿。见实施记录 Round 11。）
- [x] `M9-12` 完成 schema N-1/N 兼容、rolling relay upgrade 和新旧设备互通；不兼容行为必须在握手期拒绝。（Round 12 交付 2026-09-14：三处真缺陷修复——(1) LAN presence/hello 版本门由"严格同 minor"放宽为 `lan_supported_minor_floor = 1`（新公共常量 `include/heyaki/protocol.hpp`）：M3a 期遗留的 `minor < current.minor` 会把 1.1 设备从 1.2 设备的发现域整体挡掉，现同 major、minor ≥ LAN 位引入版的 presence/hello 全部准入，真实版本协商仍在 SESSION_HELLO；(2) PeerSession 重启帧收发两侧按协商能力位强制（wire §4 "协商不出的行为不得启用"此前只有发起侧 Node 检查）：协商 < 1.2 的会话 `send_restart_frame` 显式拒绝（`restart_capability_not_negotiated`）、入站 offer/answer/candidate 计数后忽略不转发，对端无法再驱动未协商能力的会话重启；(3) relay login 完成能力集按协商版本钳制（`capabilities_for_version` 新导出 `include/heyaki/protocol.hpp`）：自报 1.1 却声称 bit 12 的设备不再拿到越版能力授予。`tests/unit/m9_compat_test.cpp`（11 例，CTest `heyaki_m9_compat`，labels unit;protocol;relay;m9;compatibility）：协商下调与交集、`capabilities_for_version` 全映射、major 失配/越版 required 位在 `negotiate_protocol` 显式拒绝、1.2↔1.1 loopback 会话认证后协商 {1,1} 且重启帧被忽略/拒绝（含 1.2↔1.2 正常转发对照）、relay login 1.1 设备准入 + 能力钳制 + `incompatible_major_version`/`required_capability_unavailable` 握手期显式拒绝（未知 required 位在 encode 层即不可编码）、enrollment 1.1 准入、LAN 1.1 presence/hello 准入 + 1.0/异 major/缺位拒绝、rolling upgrade（v1 schema + 既有 device 行 → 原库迁移至 v2 → 免重登记 login 成功 → 重启再登录 + audit 保留）。文档：wire 协议 §4 unknown-field 语义修正（解析器显式拒绝未知字段——canonical 签名对象跳过字段会改变签名输入，v1.x 加可选字段必须由发送方按协商 minor 门控发射）+ LAN presence/hello 准入规则成文；runbook 新程序"Roll a relay upgrade"（备份→user_version 对账→换二进制重启→免重登记验证→延迟备份；`schema_too_new` 拒绝打开 = 回滚边界）并更新"Roll back a version"（回滚验证锚定 compat 套件）。既有覆盖对账：relay DB v1→v2 迁移（m3b_relay_database）、ProfileStore v1 迁移（m2_profile）此前已有测试，本轮补齐登录连续性。本机 ctest 62/62 全绿。CI 终态 run 34849636945 十 job 全绿（2026-09-14；
首轮 -Werror=missing-field-initializers 修复 0f824b7；windows matrix 已知
抖动家族轮转三轮后第 4 次绿）。见实施记录 Round 12。）
- [x] `M9-19` 解除 TURN/TCP 的 pinned 依赖阻断，交付 v1 的 TURN/TCP 连通能力；TURN/TLS 证实无任何 pinned 后端可用，改为全后端硬拒绝。（Round 16 交付 2026-09-16，方案 A 落地为双构建 + 关键调研修正，见文末 Round 16。交付语义达成：M9-07 遗留的 udp_blocked-with-TURN-unreachable 场景可经 TURN/TCP 建立 DataChannel 并通过 m6/m7 端到端演练（CI `coturn-topology` job 以 libnice 后端跑 NAT 矩阵新 `turn_tcp` 场景断言）。）
  - **原缺口**：pinned libdatachannel v0.23.2 默认 ICE 后端 libjuice 的 TURN 客户端仅 UDP（`juice_create` 只绑 UDP socket，上游 README 明示 RFC 6544/TCP 不支持，issue #104 无实现计划），`allow_turn_tcp/allow_turn_tls` 因此被 `WebRtcTransportConfig::tcp_turn_backend_verified=false` 门控拒绝。协议面（wire 标签、candidate policy、`IceServerKind::turn_tcp/turn_tls`）已就绪。
  - **方案 A 落地（Round 16）**：不升级 pin、双构建——新 CMake 选项 `HEYAKI_ICE_BACKEND`（默认 `juice` = vendored libjuice；`nice` = 系统 libnice/GLib，Linux only，版本地板 0.1.21 = ubuntu-24.04 发行线，与 OpenSSL 同类的平台依赖非 lock-file 原子）。nice 构建置 `USE_NICE=ON` + 编译宏 `HEYAKI_WEBRTC_TCP_TURN=1`，新公共谓词 `heyaki::tcp_turn_backend_supported()` 驱动 Node/transport 双层门控（libjuice 构建继续拒绝 `allow_turn_tcp`，错误不变）；`heyaki-test-turn-server` 在 nice 构建下单独补建 vendored libjuice（EXCLUDE_FROM_ALL）。CI `coturn-topology` job 切 nice 后端（+apt libnice-dev），NAT/故障/soak/bench 全部矩阵在 libnice 上回归（即立项时的"ICE 行为回归全量重跑"）；其余 job 与 Windows 维持 libjuice。
  - **关键调研修正（TURN/TLS）**：libnice 的 `NICE_RELAY_TYPE_TURN_TLS` 是遗留兼容占位符——`agent_create_tcp_turn_socket` 只对 GOOGLE/OC2007 兼容模式套伪 SSL（`socket/pseudossl.c`，非真 TLS），标准 ICE（RFC 5245，libdatachannel 所用）下 TURN_TLS 与 TURN_TCP 同一明文路径（libnice 0.1.22 源码判读 + 上游生态旁证：kinesis-webrtc-sdk-c issue #1585 指 libnice 连 RFC 6062 全 TCP 分配都是 TODO）。libdatachannel 把 `turns:` 原样映射 `NICE_RELAY_TYPE_TURN_TLS` 交给 libnice。结论：接受 `turns:` 配置 = "TLS"静默退化为明文 TURN/TCP 的配置谎言，且对 coturn `tls-listening-port` 会因无 TLS 握手直接失败。因此 `allow_turn_tls` 候选类与 `NodeIceServerKind::turn_tls` 服务器在 `validate_peer_path_policy` 与 transport `valid_config` 双层硬拒绝（新错误 detail `turn_tls_backend_not_verified`，全部后端），矩阵节点 `--turn-transport tls` 在 flag 解析期拒绝；`DataPathKind::turn_tls` 枚举/metrics/signaling 序列化面保留（v1 内不可达）。解除路径：上游 libnice 落地真 TURN/TLS、libjuice 实现 issue #104、或评估自研（原方案 B/C 不变）。
  - **安装包缺口修复**：nice 构建导出的 LibDataChannel target 携带 `$<LINK_ONLY:LibNice::LibNice>` 而上游 config 不替消费者 find libnice——heyaki 安装包内置 libdatachannel 的 FindLibNice/FindGLIB 模块并在 heyakiConfig 先建导入 target（`heyaki_installed_consumer` 在 nice 构建下回归验证）。
  - **主要风险与联动（结转）**：libnice/GLib 依赖影响 Windows 交付与 M11 Android 移植（Android 无官方 GLib 支持）——按立项建议已先在 Linux CI 打通并冻结验收，Windows/Android 后端选择保持独立决策点。M9-10 基准随 CI 后端切换自动转为 libnice 口径（coturn-topology 每次 push 重跑 bench；packetsLost 重估输入随之更新，冻结表 §9.3 已同步）。不进 executor feedback ledger（第三方依赖 API 面，与 M9-01 同类，见 `docs/operations/cross-os-matrix.md` 的 TURN/TCP 与 TURN/TLS 依赖限制节——已按 Round 16 结论重写）。

## 安全与发布工程

- [x] `M9-13` 扩展 fuzz 持续时间，覆盖所有 parser、状态机、ProfileStore migration 和 VT；保存最小化 regression corpus。（Round 13 交付 2026-09-15：**覆盖审计与补缺**——既有 20 个 harness 目标（fuzz_targets.hpp）经 5 个 libFuzzer entry 分发：frame-parser entry 覆盖全部 parser 面（frame/stream 解码、LAN datagram/hello/signaling、signed offer/answer/candidate/session-hello、pairing、trust grant、m8 shell、**m8 VT**——VT 此前已覆盖）；本轮发现 m6/m7 service payload parser 不在任何 libFuzzer entry（仅 smoke 直调），补入 frame-parser entry；connection_attempt_state_machine fuzzer 此前已编译但 CI 从未运行，本轮纳入；**新增 ProfileStore migration fuzz 目标**（`tests/fuzz/profile_store_fuzz.cpp` + `heyaki_profile_store_fuzzer`）：四种模式（合法 v1 fixture / 攻击者字节写入 identity 公钥列 / 截断 DB / 整文件随机字节），oracle = M2 迁移契约钉死的不变量（成功 → backup 存在 + 幂等重开；失败 → 文件仍在 + 尝试过迁移必留 backup；任意输入只允许显式错误）。**持续时间**：CI 从 `-runs=100`（<1s/目标）改为逐目标墙钟预算 `-max_total_time=60`（profile 90s），clang Debug job 每轮 ~5.5min 专项 fuzz；corpus README 记录本地 1800s 长跑命令。**regression corpus**：新仓库内 `tests/fuzz/corpus/`（6 个 entry 目录 + README 溯源/最小化纪律/提交新 crash 单元的流程），smoke 测试（`heyaki_fuzz_smoke`）每轮回放全部 corpus 单元（本轮 80 个）并生成种子到 build 目录；CI libFuzzer 以 `tests/fuzz/corpus/<entry>` + `build/fuzz-corpus/<entry>` 双目录为种子。坑：ProfileStore::open 对 DB 文件本身拒绝 group/other 位（外部构造的 v1 fixture 须 chmod 0600，同 M2 fixture 先例）、加密文件后端拒绝权限过宽的目录链（fuzz 根与 case 目录都要 0700）、migrate 尚未开始时（纯损坏字节）不欠 backup——失败不变量必须以"迁移确已尝试"为前提。CI 终态 run 34880683984 十 job 全绿（2026-09-15；首轮 cstdint 补头 e06b8eb、
次轮 Windows 后端不一致修复 5322a5a、tsan 抖动 rerun 绿）。见实施记录 Round 13。）
- [x] `M9-14` 完成 secret scan、dependency vulnerability scan、SBOM、许可证、编译 hardening 和发布制品签名。（Round 14 交付 2026-09-15：六面控制全部 CTest 强制并进新 CI `supply-chain` job——①**secret scan**：`scripts/run_secret_scan.sh` + digest-pin 的 gitleaks 8.24.3（`deploy/security/secret-scan.lock`，官方 checksum `9991e0b2…`）全 git 历史扫描 + 阳性对照（先证明规则集能命中再报全清）；基线 31 命中全部处置：30 个在 `.mimosa/hook-state/`（**会话工具快照被 48d7f4/386f82a 意外提交，本轮 `git rm -r --cached` 移出 5003 个文件并 gitignore**，内容为工具自身哈希/代码标识非凭据，历史路径 allowlist 留档）、1 个为 `Error{…,"password",detail}` 误报（allowlist 枚举封闭错误串集，真密码仍会命中）；测试 fixture 密钥材料零命中、未发放任何 tests/ 整体豁免。②**漏洞扫描**：`scripts/osv_vulnerability_scan.py` 单批 querybatch 查全部 40 个 pin commit + 已知漏洞 OpenSSL 对照 commit 自检（检不出即 fail-closed）+ `deploy/security/osv-triage.tsv` 三态 triage（未 triage 即红、陈旧条目告警）；结果 0 命中；OSV 对 native C/C++ 覆盖稀疏的限制与补偿控制成文；**coturn 部署制品单审**：4.10.0 镜像含 CVE-2025-69217/2026-27624/40613/43994 修复（fix commit 经 GitHub compare 判定为 tag 祖先），CVE-2026-43915/53448（admin 面板 XSS/SQLi）不在 4.10.0 但部署 `no-cli` 且无 web-admin → not-affected，发布时复检；Ubuntu 回退包 4.6.1-1build4 在多个影响域内 → 生产必须走 digest-pin 镜像。③**SBOM/许可证**：heyaki 自身入册（version+build commit）+ 版本化 namespace（Created 保持固定换字节级可复现）；生成期**copyleft 门禁**（runtime/test 组与递归子模块禁 AGPL/GPL/LGPL/SSPL 原子，optional 组仅允许"permissive OR"形态——zstd `BSD-3-Clause OR GPL-2.0-only` 不进 v1 构建）；现状全部 permissive。④**编译加固**：`HEYAKI_HARDENING`（默认 ON）——全局 `-fstack-protector-strong`/PIC/探针 CET/探针 FORTIFY（3→2 阶梯，仅优化配置，避开 distro 预定义重定义警告）+ 可执行文件 `-pie -Wl,-z,relro,-z,now,-z,noexecstack` + MSVC `/GS /guard:cf /GUARD:CF /CETCOMPAT`（x64）；`heyaki_m9_hardening_check` 用 readelf 断言 PIE/NX/full-RELRO/canary（Release 加 FORTIFY `__*_chk`）；`readelf` 本地化坑以 `LC_ALL=C` 钉死。⑤**发布签名**：`heyaki-release-sign`（pinned libsodium Ed25519；keygen/manifest/sign/verify/check；manifest 字节序确定性、严格解析、symlink 排除）+ 规程 `docs/operations/release-signing.md`（离线 keygen、key id=SHA-256(pub) 前 16 hex、轮换程序）+ `heyaki_m9_release_signing` 往返（真制品 + 全篡改方向必拒）。审计总录 `docs/supply-chain/m9-release-audit.md`。本机 werror 构建 66/66 绿 + Release FORTIFY 断言过 + IVA 独立验证（含 manifest 确定性/坏签名/路径逃逸/漏洞负路径）全 PASS。见实施记录 Round 14。）
- [x] `M9-15` 执行安全回归：multicast 洪泛/伪造/重放、LAN TLS MITM/slowloris、密码猜测/泄漏、grant/fingerprint/endpoint 伪造、降级、越权 method/topic、路径穿越、relay/TURN 放大。（Round 15 交付 2026-09-16：八攻击面覆盖矩阵审计 + 真缺口补齐，全部测试轮、零生产缺陷——唯一生产面发现是 `encode_lan_presence` 拒绝序列化签名不符对象（纵深防御，迫使伪造走字节手术=真实攻击者路径）。新增：`tests/unit/m9_security_regression_test.cpp`（CTest `heyaki_m9_security_regression`：`trust_scope_covers` 精确/前缀通配文法表测 + `safe_logical_file_name` 攻击形态全表）；m3a 三例（真组播 socket 上签名伪造/身份冒名/低序列重放拒收、slowloris 滴注部分 ClientHello 被握手死线回收且真实 peer 照常认证、跨源全局 provisional 容量帽）；m5 四例（退避指数翻倍/封顶全表 fake clock、跨源隔离无全局锁死、伪造 TrustGrant 签名接受侧拒绝零持久化、密码字面量泄漏猎杀——审计 detail + profile 根全文件字节扫描）；m4_signaling 第三方密钥 candidate 拒绝；m4_relay_signaling 三例（endpoint 发布会话绑定 E2E `endpoint_record_session_mismatch` + 正控、服务端 oversized WSS 帧丢弃存活、信令 1:1 无扇出/无反射恰 +8）；m7 终段 symlink 被 rename 替换不跟随。降级面经核对由 M9-12 compat 套件完备覆盖。审计总录 `docs/security/m9-security-regression.md`（含残余接受项：/metrics 无客户端认证、coturn 配置级反射控制）；threat-model §7 记 M9-15 回归门。本机 debug 全量 6 目标绿 + werror 构建零警告 + IVA 独立验证 12/12 二连跑零抖动 PASS。见实施记录 Round 15。）
- [x] `M9-16` 编写安装、配置、部署、升级、备份、故障排查和 API 文档；示例必须从已编译源码嵌入或同步测试。（Round 17 交付 2026-09-17：新五篇用户文档 + 文档索引——`docs/README.md`（索引 + 示例同步纪律）、`docs/getting-started.md`（前置依赖/预设构建/安装前缀/已安装包消费/首次 relay+TUI/demos 表）、`docs/configuration.md`（relay 配置文件全 24 键三列表 + 相对路径语义 + CLI 覆写 + 设备侧 struct 配置模型与校验器映射）、`docs/deployment.md`（拓扑、relay 主机要求 + systemd 单元、bootstrap token 创建面、coturn/observability、设备机队、升级/备份/回滚 → runbook 锚点表、安装树布局）、`docs/api.md`（六 target 模块表、executor 并发契约、错误模型、profile/node 生命周期、发现/会话/配对/五服务/指标/relay 注册、协议兼容规则）、`docs/troubleshooting.md`（六域症状优先分诊表 + 诊断采集法 + 平台注记）。示例同步测试 `heyaki_m9_docs_examples`（tests/docs/）：`extract_doc_examples.cmake` 在 configure 期从五篇文档提取 `heyaki-cpp <slug>`（编译为独立可执行并逐个运行）与 `heyaki-relay-config <slug>`（经真 `load_relay_config_file` 解析+校验，含缺证书负路径断言）围栏块；文档列为 CMAKE_CONFIGURE_DEPENDS（编辑即重提取）；重复 slug/空块/未配对围栏 configure 期 FATAL。README Documentation 节前置文档索引。本机 debug+werror 双构建零警告、docs 测试绿、全量 werror ctest 绿（m3a/m3b 并行抖动单跑绿，已知家族）。见实施记录 Round 17。）
- [x] `M9-17` 打包 client libraries、relay、TUI、coturn 示例配置与符号/许可证，验证干净机器安装和卸载。（Round 18 交付 2026-09-17：项目版本 0.0.0→1.0.0；安装树补齐 coturn 示例配置四件套（turnserver.conf/docker-compose.yml/env 模板/README → share/heyaki/coturn/）与 licenses.lock 全部 40 个第三方许可文本（逐条 RENAME `<name>-<basename>` → share/heyaki/licenses/，缺文件即 configure FATAL 与 SBOM 生成同语义）；nice 构建额外装 LGPL-2.1 全文 + NOTICE-libnice（动态链接满足重链接义务、源码指路，M9-19 遗留项闭环）；新 `scripts/package_release.sh` 单命令发布流——干净前缀安装 → M9-17 清单断言（8 二进制/5 公共头/cmake 包/proto/coturn 四件套/SBOM/许可清单/≥30 许可文本）→ readelf 探测 + objcopy 拆分调试符号（<stage>/… 与 <dbg>/….debug 镜像）→ strip 后二进制复跑 --version → 主/-dbg 双 tar.gz + SHA256SUMS → 解包冒烟 → **manifest 驱动卸载仿真**（新 `cmake/cmake_uninstall.cmake` + `uninstall` target，逐文件删除后断言前缀零常规文件）；构建无调试信息退出 77（CTest skip 语义——普通 Release CI job 跳过，supply-chain job 配 `-DCMAKE_*_FLAGS=-g` 后全流程真跑）。CTest `heyaki_m9_package`（Linux 非 sanitizer、objcopy/readelf/tar/bash 齐备才注册，SKIP_RETURN_CODE 77，TIMEOUT 900）。deployment.md 打包产物节更新为终态。本机验证：debug 全流程 PACKAGE_OK（11 个调试文件、版本 heyaki-1.0.0-linux-x86_64、卸载零残留）、plain Release skip 路径、nice 构建安装 42 许可文件含 LGPL/NOTICE、juice 40 且无 LGPL、installed_consumer/supply_chain/release_signing/docs 四测试随版本升全绿。见实施记录 Round 18。）
- [x] `M9-18` 形成 v1 release checklist，记录测试 commit、依赖 commit、协议版本、已知限制和回滚方案。（Round 19 交付 2026-09-17：`docs/operations/release-checklist-v1.md`——发布身份（1.0.0/wire {1,2}/heyaki 自身许可 NOASSERTION 为产品决策点）；依赖 commit 记录（dependencies.lock 35 直依赖 + transitive 5 + licenses.lock 全文随包，系统面 OpenSSL 3.x 地板/libnice 0.1.21 地板/coturn 4.10.0 digest + 回退包 CVE 结论）+ 发布前三复检（OSV/coturn 镜像/secret scan）；验证证据矩阵（十一 CI job 覆盖面 + 验收实测数字 + 打包流落 supply-chain job）与 tag 时盖章步骤；已知限制 13 条成文（TURN/TLS、libnice consent 80s、packetsLost、控制面字节计数、/metrics 认证、无 admin CLI、跨 OS 阻断、Windows 磁盘满、共享出口限速、shell tick、SCTP 帧帽、未知字段拒绝、打包 Linux-only）；回滚方案四层（relay schema 边界/设备 N-1/TURN 四代凭据/库 SameMajorVersion）；发布七步程序（打包→签名→复检→盖章→tag 为产品所有者动作）。文档索引挂链。）

## M9/v1 最终验收

- [x] 同区域正常网络登记 P95 < 2 秒，可打洞直连 P95 < 3 秒，TURN fallback P95 < 5 秒。（M9-10 基准 harness 三相位 CI 常跑（coturn-topology Release，libnice 后端）；冻结表实测：登记 P95 22-32ms（余量 60-90×）、直连 300-1021ms（3-10×）、TURN 663-1077ms（5-7×）；门 = bench Phase R/T 断言。NAT 矩阵拓扑真实 P95：cone 打洞 ≤2059ms、symmetric/CGNAT TURN ≤1356ms。）
- [x] 无 relay/STUN/TURN 的三设备测试 LAN 能自主发现、认证和建立 host-candidate DataChannel；未知/已信任 peer 分别进入 PairingRestricted/Authorized。（m3a `heyaki_network_harness` 全套 + Windows/CI lan_only 矩阵场景（direct_host 认证、m6/m7 严格）；默认拒绝→PairingRestricted→配对→Authorized 由 m5 全套与 M9-15 伪造/重放面钉死；TUI 同 OS 用户复用 profile 由 m2/TUI harness 覆盖。）
- [x] TUI 本地初始化后，同 OS 用户的库应用可复用 profile 运行 LAN-only；存在 enrollment 时可无人工登录 relay，多 endpoint 同时在线且路由准确。（ProfileStore 共享 profile/endpoint_for 合一（m2+架构 §5.4，TUI org.heyaki.tui 与库应用各持 endpoint）；免登录 relay 重连经 enrollment generation（m3b 重连/重启测试）；多 endpoint 路由=endpoint 目录 + tenant 隔离（m3b_relay_endpoint/m4_signaling）；文档化于 getting-started/api.md。）
- [x] 未信任设备只能进入 pairing-only，错误密码不触达业务 handler，正确密码只授予策略交集内 scope。（m5 default-deny 全套 + M9-15 补齐：退避指数全表、跨源隔离、伪造 TrustGrant 拒绝、scope 文法表 heyaki_m9_security_regression；交集语义在 m5 与 api.md 成文。）
- [x] LAN-only、relay-signaled direct 和 TURN 三条路径均通过消息、RPC、事件、ByteStream、文件和启用后的 Shell 端到端测试。（M9-07 Windows lan_only/relay_direct/turn_udp 矩阵首轮严格断言 m6+m7；M9-06 NAT 矩阵六场景 m6 严格 + m7 文件；M9-19 turn_tcp 场景 strict-m7（UDP 全灭下 TURN/TCP）；shell 端到端 = m8 全套 + bench shell 段（空闲/竞争）；ByteStream = m5/m6 通道族。三条路径 × 能力对账见 cross-os-matrix.md。）
- [x] 所有发送/接收/任务/诊断队列在压力下保持配置上限，无持续内存增长或静默消息损失。（M9-09 soak 三相位：RSS/fd/replay/会话史环/任务 gauge 全循环门 + Phase B/C 设备与容量过载；慢消费者/队列上限/反饥饿 = m5/m6/m7 overflow 族 + M9-08 slow_receiver 整形链路；有界性另由 M9-11 冻结上限钉死。）
- [x] 文件可从任意已确认块恢复并通过最终 BLAKE3；非幂等 RPC 断线返回 `outcome_unknown`。（m7 bitmap 续传/SessionLossPauses/崩溃矩阵六盘上边界（heyaki_m9_file_crash_recovery）+ Round 10 两处 complete 缺陷回归；outcome_unknown = m6 语义族 + at-most-once result cache。）
- [x] Shell 未授权、文件越界、超额资源、协议降级、伪造签名和重放全部默认拒绝。（shell live scope + 默认关（m8）；文件 roots/配额/文法（m7 + M9-15 文法全表）；降级 = M9-12 compat 套件（版本/能力/重启帧三层）；伪造签名/重放 = M9-15 八面（presence 字节手术/低序列重放/伪造 grant·candidate·endpoint）；审计总录 m9-security-regression.md。）
- [x] relay 数据库、日志、WSS 终止点和 TURN 抓包均不能恢复授权密码、verifier、私钥或业务明文。（密码面按协议不接触 relay；M9-15 密码字面量泄漏猎杀（审计 detail + profile 根全文件扫描）；relay 只持哈希 token/generation（m3b schema）；数据面 P2P + TURN 中继不含信令明文；TUI/relay 日志审计字段不含机密（M9-02/03 设计约束 + 测试）。）
- [x] TUI 仅通过 Heyaki 公共 API 覆盖全部正式能力；高频事件与窄终端下仍保持有界刷新和可用布局。（heyaki_tui_setup 只链 heyaki::client/profile 公共面；m3b/m4/m6/m7/m8 TUI harness 驱动全部视图；QUEUES/RENDER 有界性 = M9-01 Round 2 + 高频 fan-out bench 段。）
- [x] Linux/Windows 发布矩阵、sanitizer、fuzz、长稳、故障注入、兼容性和安全评审全部通过或有明确阻断结论。（CI 十一 job 全绿基线（M9-19 终态 35178705793 + M9-16/17/18 增量轮见记录）；阻断结论成文：跨 OS 真机组合 runner 不可达、Windows udp_blocked 不可仿真、TURN/TLS 无后端（cross-os-matrix.md / release-checklist 已知限制）；M9-15 IVA 独立验证 + 审计总录。）

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
- 第二轮 CI（run 34388185805）probe 六场景全绿（EIM/symmetric 类别与
  公网别名全部验证）、symmetric 3/3、cgnat try1 过；但 cone 类 STUN-only
  全部 attempt_expired、hairpin 以 direct_host 认证。根因：**DNAT 在
  prerouting 已把目的改写成对端私网地址，forward hook 上穿越 NAT 的打洞
  包与 host 直连包地址不可区分**——防绕过网段互 drop 把打洞包一并杀掉
  （hairpin 因已加 `ct status dnat accept` 而幸存）。修正：基础链只留
  established accept，`client_bypass_drops`（10.78/10.79 两对网段）按场
  景叠加且必须在 `cone_accept`（`ct status dnat accept`）与
  restricted/port-restricted 的集合过滤之后。另一确认：`--srflx-only`
  过滤的是候选通告面（对端只知 srflx 地址 → 任何成功对必穿 NAT），本地
  agent 仍可提名 host 类型本地候选，故 data_path 标签集为
  `direct_host,direct_srflx`（cone 类）/ 三标签（symmetric/cgnat）。
  规则次序在本机 userns 沙箱按 restricted 场景逐条复现验证。
- 第三轮 CI（run 34390321528，2026-09-09）全绿（10/10，asan 首跑
  m3b_relay_wss 计时断言抖动 rerun 即绿，与本轮改动无关）。NAT 矩阵
  实测：full_cone 3/3 打洞直连（1070/2059/1060ms，P95 2059ms）、
  restricted_cone 1078ms、port_restricted_cone 119ms、symmetric 3/3 经
  TURN 中转（P95 1356ms）、hairpin 1060ms（direct_host 标签 = 打洞穿
  NAT 后本地 host 候选被提名）、cgnat try1 255ms（双 NAT TURN 中转）；
  全部场景 m6 消息+RPC 严格通过、m7 文件提交成功。

### Round 7（2026-09-11）：M9-07 Linux/Windows 组合验证

交付物：

- `apps/demo/m4_matrix_node.cpp`：`--lan-only` 运行模式（lan.enabled +
  lan_only 连通模式、200ms 通告节奏、无 relay_override、跳过 relay ready
  等待与恢复宽限、发起方经组播目录 `entry.lan` 找对端并 `connect_lan`）；
  `--turn-username/--turn-credential` 显式凭据覆写（绕过 REST 推导，供
  libjuice 静态凭据测试 TURN server）；`--lan-only` 与
  `--stun/--turn/--force-turn/--srflx-only` 互斥校验（lan_only 策略本就
  禁 srflx/TURN/ICE server，矛盾 flag 提前报 usage）。
- `apps/demo/test_turn_server.cpp` → `heyaki-test-turn-server`（链接
  `LibJuice::LibJuiceStatic`，进入安装目标清单）：pinned libjuice 内嵌
  TURN/UDP server 的最小封装，静态长期凭据 + relay 端口区间，stdout 打印
  `TURN_SERVER_READY`。Windows 无 coturn，TURN/UDP 场景由它与客户端同一
  ICE 栈对拍；本机实测单实例即可中转同机双端（relayed<->relayed），矩阵
  仍按 Linux 先例双实例（A/B 各持不相交 relay 端口段）。
- `tests/network/run_windows_network_matrix.ps1`（CTest
  `heyaki_windows_network_matrix`，`HEYAKI_REQUIRE_WINDOWS_NETWORK_MATRIX=1`
  门控，SKIP 77，TIMEOUT 900；CI windows job 常开）：四场景——
  `lan_only`（无 relay，组播发现 + LAN TLS 信令 + 认证会话，双向发起，
  首轮 m6 消息/RPC + m7 文件严格断言，`data_path=direct_host`）、
  `relay_direct`（本机 `heyaki-relay.exe` + openssl 生成 CA/叶子证书
  （SAN 127.0.0.1）+ seed-token + enroll，双向发起，`direct_host`）、
  `turn_udp`（双 test-turn-server + force-turn，`turn_udp`）、
  `udp_blocked`（`New-NetFirewallRule` 程序级出站 UDP 阻断 TURN 端口 →
  断言 `authenticated=0` 有界显式失败，finally 删规则）。支持
  `-RelayUrl/-RelayCaFile/-EnrollToken` 跨 OS 模式指向远端 Linux relay。
- `tests/network/run_windows_firewall_harness.ps1`：增加放行正向场景——
  Public profile 下按 runbook 加程序级 UDP 49189 入/出放行规则后，
  `TwoLanNodesDiscoverEachOtherWithoutRelay` 必须通过（证明阻断场景失败
  得其所，且文档化最小规则对）；TIMEOUT 90→180。
- `docs/operations/cross-os-matrix.md`：组合→覆盖位置映射表（LAN-only/
  relay direct/TURN UDP/udp blocked/防火墙/文件命名权限/PTY-ConPTY 各自
  的 Windows CI 落点）、Linux↔Windows 真跨机在 GitHub 托管 runner 上的
  阻断依据（runner 互不可达；windows-2025 WSL2 损坏 actions/runner-images
  #11784/#11869；无嵌套虚拟化）、TURN/TCP/TLS 的 pinned 依赖限制
  （libjuice TURN 客户端 UDP-only，`tcp_turn_backend_verified` 门控，
  重估时点 M9-10 后）、自托管混合机队操作程序（Linux 侧 relay+TURN、
  Windows 侧裸命令或 harness 跨 OS 模式、双向断言与留档要求）。
- 缺陷修复（本机 lan-only 矩阵首跑即暴露）：`PeerSession` 新增
  `opening_physical_channels_` 在途集合——`ensure_physical_channel` 此前
  只以 `physical_channels_`（open 完成时才插入）防重，同域第二次请求
  （服务挂载 vs `subscribe_events` 的 send_frame）会在首次 open pending
  期重复 `async_open_channel`，transport 层把任何 pending 期二次 open 拒
  为 `prepared_channel_options_mismatch`（选项相同也拒），`self->fail`
  杀死已认证会话。relay 模式从未触发只因 subscribe 侧恰为非 offer
  owner；LAN 模式 offer owner 由 ID 决胜决定，可与逻辑发起方相反。
  回归测试 `M4PeerSession.SameDomainRequestsCoalesceWhilePhysicalOpenInFlight`
  （m4_support 的 LoopbackTransportPair 增加 defer_opens/flush 与
  open_request 计数，临时还原缺陷验证过测试确实变红）。

本机验证（Linux）：lan_only（direct_host 1076ms，m6/m7 全过，修复前
100% 复现会话被杀）、relay_direct（direct_host 2047ms）、turn_udp
（turn_udp 1085ms，test-turn-server）三场景端到端绿；全量 ctest 串行
两轮仅 m3a_lan 负载抖动（单跑绿，与基线一致；基线 stash 对照确认）；
m4/m6 TUI harness 带改动 3/2 次全绿（一次并行负载失败为既有抖动家族）。
CI 迭代三轮收敛（提交链 7d40f9e→4ca91fa→31ac97e→8d2525e，终态 run
34562937220 10/10 绿，asan m3b endpoint_queries 计时抖动 rerun 即绿）：
首轮实证矩阵真实可跑（lan_only 首轮/relay_direct 双向/turn_udp 首轮绿）
并暴露三个问题——New-NetFirewallRule -Program 拒正斜杠路径（前置
Resolve-Path 规范化）、场景第二轮可输给反向发现滞后首轮拒绝（responder
先启 1s + 发起方 --connect-retries 3，与 M4 lossy 家族同因）、单机 TURN
配额下提名可为本地 srflx×对端 relayed 半中转对（接受 turn_udp|
direct_srflx 标签集，"双中转"严格断言是 Linux netns 拓扑属性）；次轮
脚本编辑引入 PS 解析错误（缺 `]`）被 CI 0.48s 抓出；第三轮发现 WFP
豁免 loopback——本地 udp_blocked 场景移除（Linux CI iptables 场景继续
承担该契约），跨 OS 模式保留并参数化远端 TURN（-TurnEndpoint 等）。
Windows 双构建最终实测：lan_only 581/1083ms、relay_direct 84/67ms、
turn_udp 110/121ms（Debug，双向）。

设计说明：

- "双向组合"在 CI 内的可达语义 = 每 OS 全部传输路径 × 发起方互换 ×
  平台特有行为（防火墙 profile、NTFS 命名/权限、ConPTY）；真·跨机
  Linux↔Windows 留自托管程序 + 明确阻断结论（最终验收"或有明确阻断
  结论"分支）。
- TURN/TCP/TLS 不引入 executor ledger 条目（第三方依赖 API 面，与 M9-01
  丢包估计缺口同类先例）；配置/wire/candidate 面已就绪，升级
  libdatachannel 后只需后端验证 + 置 `tcp_turn_backend_verified`。

### Round 8（2026-09-12）：M9-08 故障注入

交付物：

- `deploy/coturn/run_fault_matrix.sh`（root+coturn 门控，SKIP 77，CTest
  `heyaki_m9_fault_matrix`，TIMEOUT 1500，labels relay;network;fault;m9；
  CI coturn-topology job 增加 "Run M9 fault matrix in namespaces" 步骤）：
  复用 M4 矩阵拓扑（双客户端 netns + host relay + 双 coturn），六场景：
  - `relay_restart_transfer`：发起方经 `--m7-pause-hold-ms` 在首个
    transferring 相位暂停文件传输（stdout 无缓冲，脚本轮询
    `MATRIX_PHASE m7-paused` 得到确定性故障窗口），窗口内杀 relay
    （TERM→KILL）并重启；断言恢复后传输经 resume 提交（m7_file=1，
    commit 自带 BLAKE3 门）、relay_state=ready、data_path 直连。直连数据
    面不依赖信令 relay 存活由本场景证明；一次有界重试容忍 runner 计时。
  - `turn_restart`：TURN 中转会话认证并持握后杀双 coturn；断言参与者有界存活
    （预算内退出、结果行产出、无挂起）且 relay 控制面不受影响；重启 coturn 后
    新参与者必须再经 TURN 认证成功（coturn 真正回到服务）。**已证伪的假设**：
    pinned libjuice 虽实现 RFC 7675 consent freshness（CONSENT_TIMEOUT 30s），
    但 TURN 服务器死亡并不经 consent 在 40-70s 窗口内传导为会话关闭——CI
    run 34684217306 与本机嵌入式 TURN server 复现均持握 state=authenticated
    到退出；会话级关联丢失终止契约由 m4 shutdown 矩阵承担，该缺口记录为
    已知限制（升级 libdatachannel 后重估，同 TURN/TCP 先例类别）。
  - `path_switch`：同一对已注册设备连续三段网络条件——直连（direct）→
    封锁 inter-client 转发（mediated/TURN）→ 恢复直连——每段重建会话并
    断言数据面选择正确；证明设备在网络切换后无陈旧状态毒化。
  - `lease_expiry`：responder 以 1s 心跳/3s 租约运行，SIGSTOP 冻结 9s
    越过租约 TTL（relay 按 heartbeat 请求值裁定租约），endpoint 被逐出；
    解冻后 heartbeat 重新插入租约（round2 发起方认证成功）且 responder
    relay_state=ready。本机实测走"TCP 存活+租约重插"分支（reconnect
    分支由 relay_restart 覆盖）。
  - `slow_receiver`：2 MiB 文件推入 `netem rate 4mbit delay 50ms` 整形
    的接收方链路（实测有效 SCTP 吞吐约 1 mbit，4 MiB 会越过 25s 等待，
    载荷定为 2 MiB）；断言会话不死、m6 正常、传输在等待预算内有界完成。
  - `stale_turn_credential`：发起方以 `--turn-credential-expiry-offset-ms
    -3600000` 推导过期 REST 凭据并以 `--force-turn` 强制其唯一候选 ride 该
    分配（否则 host×对端 relayed 半中继对会绕开过期凭据照常认证——CI 第二
    轮实证）；coturn 以 401 拒绝分配，断言与 udp_blocked 同形的有界显式
    失败（authenticated=0 + closed + 命名错误）且 turn 日志含 401（把失败
    钉死在凭据而非 forced-turn 提名 stall）。
- `apps/demo/m4_matrix_node.cpp` 四个 fault-matrix flag：
  `--m7-bytes N`（尺寸化载荷）、`--m7-pause-hold-ms N`（transferring
  相位暂停→hold→resume，公共 pause/resume API）、`--m7-wait-ms N`（m7
  完成等待覆写，默认 15000）、`--turn-credential-expiry-offset-ms N`
  （带符号，REST username 时间戳偏移）。
- 磁盘满（POSIX `RLIMIT_FSIZE`+忽略 SIGXFSZ，EFBIG 为 ENOSPC 可移植替身，
  克隆 m2 DiskFull 模式）：
  - `tests/unit/m7_file_test.cpp`
    `DiskFullFailsReceiveExplicitlyAndRecoversAfterSpace`：接收方首个
    256KiB 块中途写失败→failed 事件携带 "write_failed"、最终文件不存在、
    staging sidecar 经 blocking 清理（无 .heyaki- 残留）、sender 收到
    abort 终态（sender_failed≥1）；限额恢复后同内容新传输提交且字节
    一致。
  - `tests/unit/m3b_relay_database_test.cpp`
    `DiskFullFailsWritesExplicitlyAndPreservesEarlierData`：token
    create/consume 建立基线后，cap 在当前 db+journal 足迹+24KiB，循环
    audit 行直至越限；断言显式 `ErrorCode::storage`、重开后 audit 计数
    == 基线+成功行数（失败事务回滚）、token 剩余使用次数保留。
- 文件服务任意关闭点崩溃矩阵（ProfileStore 崩溃矩阵模式的第二实例）：
  - `src/client/file_store.cpp`：`HEYAKI_FILE_FAULT_INJECTION` test-only
    编译注入 `file_fault_injection_point`（env `HEYAKI_FILE_FAULT_POINT`
    命中即 `std::_Exit(86)`，生产编译为无条件调用的 no-op，同 profile
    模式）；六个点：`staging.after_create`、`chunk.after_write`、
    `state.after_write`、`commit.before_rename`、`commit.after_rename`、
    `commit.after_cleanup`。`write_resume_state` 经 `write_small_file`
    复用 `write_staging_at`——thread_local 深度标记让 chunk 点只对传输
    载荷写触发，state sidecar 拥有独立窗口。Windows/POSIX 两分支均置点。
  - `tests/file/file_crash_probe.cpp`（`heyaki_m9_file_crash_probe`）：
    push 模式跑真实 M7 loopback 对直至死于指定点（NO_CRASH=失败）；
    verify 模式新进程断言：rename 前崩溃点最终文件不可见（原子性——
    最终路径只能由 rename 创建）、rename 后崩溃点最终文件字节一致、
    崩溃后同内容新传输提交字节一致且残留 staging 计数不变（不阻塞、
    不毒化）。probe 直接调用 `file_store::blake3_file` 以在归档解析中
    先于 `heyaki::client` 拉入 fault 注入对象（否则生产 file_store.o
    补位、故障点永不触发——首跑 NO_CRASH 即此坑）。
  - `tests/file/RunFileCrashTest.cmake` + CTest
    `heyaki_m9_file_crash_recovery`（labels integration;file;m9;
    reliability，sanitizer ptrace 跳过规则与 profile 崩溃矩阵同）。
- 既有覆盖映射（本轮核对，不重复建设）：relay outage/backoff/重启重登
  （m3b 单测 + M4 矩阵 relay_restart）、TURN/租约/bootstrap token/grant/
  pairing 时限的过期单测（fake clock 全绿）、同 transfer id 的会话丢失
  恢复（m7 SessionLossPausesAndNextSessionResumes——sender book 存活路径，
  与本轮进程死亡路径互补）、接口切换发现层（m3a
  RefreshesSocketsAfterInterfaceSwitch + run_harness.sh
  HEYAKI_SWITCH_INTERFACE）、慢订阅者/队列上限/公平性（m5 channels、
  m6/m7 pending/overflow/anti-starvation 族）。

本机验证（Linux 非特权 userns 沙箱，coturn 以只绑端口的桩替身——不答
STUN/TURN，直连主机候选仍可认证）：relay_restart_transfer
（direct_host 2020ms，m7_file=1，relay_reconnects=2）、lease_expiry 三段、
slow_receiver（2MiB 整形链路提交）全绿；turn_restart/path_switch/
stale_turn_credential 依赖真 coturn，CI 验证。全量 ctest（58/58 + 5 环境
门控跳过）+ 崩溃矩阵六点本机绿。CI 三轮收敛（提交链 d400ff4→aa31f90→
6180209→b55b905，终态 run 34686617215 十 job 全绿，windows Release 首跑
m3b ConnectsWithTlsPin 抖动 rerun 即绿——既有家族，与本轮无关）：首轮
编译错（生产编译里空 RAII 守卫结构被 GCC -Werror=unused-variable 拒绝，
本机构建未开 warnings-as-errors 故未现，加 [[maybe_unused]]）；次轮两个
场景级发现——turn_restart 的 consent 假设证伪（见上）与 stale 场景裸
--stun ":PORT" 空 hostname；第三轮 stale 场景再修（host×对端 relayed 半
中继对绕开过期凭据照常认证，发起方加 --force-turn 强制唯一候选 ride
过期分配 + turn 日志 401 断言钉死凭据拒绝）。坑：netem `rate 4mbit delay 50ms` 下有效 SCTP 吞吐约 1 mbit
（非 4mbit），4MiB 载荷 25s 内只到 77.6%——载荷与等待预算必须按有效吞吐
定；场景体内参与者调用必须 `|| true` 守卫（函数内 set -e 失败不触发 ERR
trap，静默退出无现场）；裸 `--stun ":PORT"` 不经 run_pair 地址展开会得到
空 hostname（ice_server_fields_invalid）。

设计说明：

- 进程级文件崩溃矩阵的恢复语义是"新传输提交字节一致"，不是"同 transfer
  id 续传"——进程死亡同时消灭 sender book，同 id 重.offer 无从发生；同 id
  恢复的契约由 m7 SessionLossPauses（会话丢失、sender 存活）承担，两路径
  互补。孤儿 staging（进程死亡残留）今日无自动清理，靠 root 配额兜底——
  已知缺口记录于此，清理器留 M9-11 参数冻结时评估。
- turn_restart 的会话终止：首版假设 libjuice consent（RFC 7675，30s）会在
  持握期内关闭会话——CI 与本机复现双双证伪（TURN 死后会话以
  state=authenticated 存活至 70s 持握期末）。断言已收敛到系统的真实保证：
  有界存活 + relay 不受影响 + coturn 恢复服务；缺口为 pinned 依赖行为
  （非 executor 限制，不入 executor ledger），升级 libdatachannel 后重估。
  本机复现方法：heyaki-test-turn-server 单 netns 同机中继 + kill -9，73s
  观察窗。
- 磁盘满单测 POSIX-only（RLIMIT_FSIZE）；Windows 无对应机制，ENOSPC 面
  由 CI Windows 既有套件的路径/权限拒绝场景部分覆盖，完整 Windows 磁盘
  满仿真留自托管程序（cross-os-matrix.md 先例）。

### Round 9（2026-09-12）：M9-09 长稳与容量过载

交付物：

- `apps/demo/m4_matrix_node.cpp` soak 模式：`--soak-cycles N`（仅 initiator，
  与 responder 角色组合直接 usage 拒绝）。单进程循环：对端目录条目就绪
  （20s 上限；stale 记录由有界重拨吸收，`options.retries + 2` 次）→ dial →
  认证 → m6 消息+RPC 与 m7 事件+文件演练（从一次性流程逐字抽出的
  `exercise_initiator_services` lambda，每循环独立目标文件名
  `matrix/soak-<i>.bin`，LatestMailbox 每循环重置）→ 打印
  `SOAK_CYCLE idx=i state=work-done`（含 rss_kb/fds/sessions/replay/
  tasks_active/tasks_queued/data_path）→ 等 harness 杀掉 responder 后会话
  进入终态（45s，覆盖 pinned libjuice RFC 7675 consent 30s）→ 打印
  `state=closed` 采样。终态 `SOAK_SUMMARY`：cycles=N/N、work_done、
  closed_ok、rss first/last/max、fds first/last/max、replay_peak、
  sessions_final（含诊断史）与 sessions_live_final、tasks_active_final、
  duration。进程采样走 /proc/self（`VmRSS` + /proc/self/fd 计数，fd 数含
  opendir 句柄近似——跨循环 delta 才是信号）；非 Linux 平台报 0 仅为编
  译兼容。一次性流程的行为与输出 marker 保持逐字不变（fault/nat matrix
  轮询的 `MATRIX_PHASE m7-paused` 等不受影响）。
- `tests/network/run_m9_soak_harness.sh`（CTest `heyaki_m9_soak`，labels
  network;relay;soak;m9，TIMEOUT 1500；`HEYAKI_REQUIRE_M9_SOAK=1` 门控
  SKIP 77，与 Windows 矩阵同模式，避免拖慢默认套件与 sanitizer 预设；
  CI coturn-topology job 在 fault matrix 之后以非 root 直跑）：
  - Phase A 会话 churn：长存 initiator `--soak-cycles` + responder 每循环
    SIGKILL + 同 profile 重生（harness 轮询 work-done 行得到确定性故障
    窗口，与 fault matrix 的 MATRIX_PHASE 编排同法）。门：SOAK_SUMMARY
    全循环 work_done/closed_ok、sessions_live_final==0、sessions_total ≤
    4×cycles+16（有界史环核算）、tasks_active_final==0、fds_last ≤
    fds_first+HEYAKI_SOAK_FD_SLACK(24)、rss_last ≤ rss_first+
    HEYAKI_SOAK_RSS_GROWTH_KB(32768) 且 rss_max ≤ 4×增长门、
    replay_peak ≤ 256（ReplayCachePolicy per-peer 默认容量）、
    MATRIX_RESULT authenticated=1 m7_file=1。
  - Phase B 设备 churn：K 个全新 profile（全新 DeviceId）顺序
    init/enroll/login/publish/exit，每迭代 scrape 长存 relay 的
    `/metrics`（`heyaki_relay_active_sessions`、
    `heyaki_relay_endpoint_table_entries`、`heyaki_relay_lease_entries`、
    login/enrollment challenge 表 entries）+ `/proc` RSS/fd；终态门：五个
    gauge 族 ≤ 有界值（4/8/4/8/8）、relay RSS 增长 ≤ 2×增长门、fd ≤
    baseline+32。
  - Phase C 容量过载：第二 relay 实例 max_connections=3 +
    endpoint_directory_capacity=2，5 并发参与者。门：连接容量拒绝
    （`heyaki_relay_capacity_rejected_total`）≥1、目录容量拒绝
    （endpoints/endpoint_table 两族）≥1、全部参与者有界退出、≥3 个
    relay_state=ready（过载拒绝不杀伤登录能力）、优雅退出 4s 后
    lease/endpoint 表归零且 active_sessions 回到 scrape-only 基线
    （=1，metrics 抓取自身持有唯一存活 TLS 连接——baseline 同值）、
    tight relay 自身 RSS/fd 有界。
  - scrape 实现：python3 + `ssl.create_default_context(cafile)` 以
    HTTP/1.0 GET `/metrics`（无 chunked，read-to-EOF），归一化去 label。
    生成的 CA 必须带 basicConstraints/keyUsage 扩展（python TLS 栈比
    C++ 客户端默认严格，裸自签 CA 报 "CA cert does not include key
    usage extension"）。
  - env 旋钮：`HEYAKI_SOAK_SESSION_CYCLES`(6)/`HEYAKI_SOAK_CHURN_PARTICIPANTS`(8)/
    `HEYAKI_SOAK_OVERLOAD_PARTICIPANTS`(5)/`HEYAKI_SOAK_RSS_GROWTH_KB`(32768)/
    `HEYAKI_SOAK_FD_SLACK`(24)/`HEYAKI_SOAK_WORK_DIR`；失败时保留 work dir
    并 dump relay/participant/日志尾部与最后一次 metrics scrape。
- `docs/operations/runbook.md` 新程序"Run a soak (long-stability) test"：
  命令模板、24/72h 放大方法（按 CI 片段的 per-cycle duration_ms 折算
  cycles，磁盘预算提醒）、三段工件保留要求（work dir、SOAK_CYCLE/
  SOAK_SUMMARY、SOAK_RELAY_SAMPLE 序列）、通过标准（CI 片段强制门 +
  24/72h 的一/后半中位斜率分析）与按失败门的分诊路径。
- `.github/workflows/ci.yml`：coturn-topology job 新步骤
  "Run M9 soak harness (loopback churn + overload)"（timeout 30min，
  非 root，复用该 job 已构建的 relay/matrix/demo 三个二进制）。

既有覆盖映射（本轮核对，不重复建设）：TTL 表容量拒绝/过期/重插
（m3b_relay_ttl_test）、endpoint directory 容量/代际回退/租户冲突
（m3b_relay_endpoint_test）、replay cache 全局+per-peer 容量拒绝与 TTL
保留（m4_signaling_test M4ReplayCache 三例）、连接容量满拒绝与握手超时
释放槽位（m3b_relay_test）、限速四 scope（m3b_relay_wss_client +
rate_limiter）、控制面写队列水位（config `control_write_queue_*`）、
设备侧队列上限/慢消费者/反饥饿（m5 channels、m6/m7 pending/overflow 族）。

本机验证（Linux debug 构建）：三相位端到端绿（4 cycles/4 churn/5
overload：initiator RSS 25.2→26.6MiB、fds 23→23、replay_peak 8、
sessions_live_final 0；relay#1 RSS 17.7→19.0MiB、gauge 全程有界；tight
relay 容量拒绝 3 连接 + 23 目录、排空归零）；CI 规模默认旋钮（6/8/5）
全绿 3m52s；一次性路径（无 soak flag 的 initiator+responder 对）重构后
回归验证 authenticated=1/m6/m7 全过；全量 ctest（含新 heyaki_m9_soak
注册，未设 env 时 SKIP 77）。CI 终态 run 34698025758 十 job 全绿：
soak 步骤在 coturn-topology job（Release）首跑即绿（initiator RSS
21.4→22.5MiB、fds 18→15、replay_peak 12，全程 ~4min）；首跑 Windows
Debug 的 windows_network_matrix lan_only/first-initiates 出现 file=0
首轮抖动（message=1 rpc=1，其余五场景全绿；与上一 docs-only run 的
turn_udp/first-initiates 首轮抖动同属 Windows runner 负载下的首轮家族，
与本轮改动无关），rerun 即绿。

关键设计事实（后续长稳运行与 M9-11 的输入）：

- closed 会话按设计进入 `finished_peer_sessions` 有界诊断史环
  （容量 = `lan.diagnostic_capacity`，默认 1024），`peer_sessions()`
  在流量后不归零——"排空"的正确断言是 live 会话为零 + 总数随循环数
  有界增长。24/72h 运行超过 1024 循环后该环封顶（pop_front），
  sessions_final 门在放大运行时按 1024 封顶值解读。
- SIGKILL 的 responder 由重生登录的 lease/endpoint 替换语义清理
  （`lease_removed_total`/`endpoints_removed_total` 计数，60s TTL 兜底
  不必等）；relay `active_sessions` gauge 含 scrape 自身的 TLS 连接，
  排空断言口径为"回到 scrape-only 基线"。
- 一次重拨可落在 stale 目录记录上（endpoint 60s TTL 内），表现为
  有界 attempt_expired/handshake_failed 噪声，重拨预算内收敛——
  soak 门不把这些计为失败（work_done/closed_ok 才是循环成败）。
- 24/72h 验收语义：CI 片段证明门机制与短时有界性；小时级运行由
  runbook 程序执行（按片段 per-cycle 时长折算 cycles），一/后半
  RSS 中位斜率是判据，慢于此的泄漏记 M9-11 输入。

### Round 10（2026-09-13）：M9-10 基准测试 + 同 kind 双流 UAF 修复

交付物：

- `apps/demo/m4_matrix_node.cpp` bench 模式：
  - `--bench-initiator`（替代一次性 m6/m7 演练）：拨号全部已发现 peer
    （fan-out 订阅者即 peer，拨号间隔 300ms——loopback 上所有身份共享
    relay 的 per-IP 限速 scope（32/s），同时多拨的信令突发会触发
    `rate_limited` 并把两个参与方的控制连接打掉重连）；`BENCH_CONNECT`
    （dial→authenticated + data_path + peers 计数）。
  - 套件段（各段独立计数、`--bench-connect-only` 全跳过）：消息 RTT
    （顺序单在途 1KiB peer_acked；ack 观察者只发布终态事件——`queued`
    是中间态，初版把它当失败发布导致样本全废；每次发送前 drain 通道防
    上一轮超时残值串账；等待窗 > TTL 20s）；顺序 RPC（echo 1KiB、drain
    前置）；并发 RPC（窗口 16——服务端 max_concurrent_calls=16 / 客户端
    pending 上限 64 之下，窗口超限直接 usage 拒绝；完成回调经
    `MpscChannel<BenchRpcDone>` 按 wire RequestId 匹配发送时间戳；准入
    拒绝计数不混入延迟总体）；事件 fan-out（发布侧逐 peer
    `publish_event`，载荷 8B steady 微秒 + 4B 序号，订阅者打印
    `BENCH_FANOUT_RX seq= rtt_us=` 由 harness 聚合；reliable_live QoS
    使"全量送达"门有意义）；文件段（单路 / 双并发（默认每会话发送上限
    2）/ shell 竞争下一路；文件事件经容量 1024 的通道 + 终态登记表，
    等待他路传输时先落谁的终态都不会丢）；shell 竞争（open_shell →
    active；空闲 ping 基线；2MiB 推送期间 ping；token 匹配在累计输出
    流上做——PTY 回显使 token 出现即输入帧→PTY→输出帧往返）。
  - `--bench-responder`：认证后附加订阅 `bench.fanout`（reliable_live）
    + 逐事件 RTT 打印。`--bench-shell`：服务侧暴露固定 "bench" profile
    （POSIX `/bin/sh`，TERM=dumb，无 wire 可执行覆写面）。`seed-trust`
    新增可选 seed 基数参数（见下坑 2）。relay-ready 处打印
    `MATRIX_PHASE relay-ready login_ms=`（进程启动→登录接受的注册时长，
    Phase R/T 的样本源）。
  - 生命周期纪律：全部 bench 通信端点（ack/rpc/rpc 并发/文件通道、shell
    mailbox）声明在 run_node 作用域——`shutdown()` 排水期的迟到回调仍可
    能发布，per-section 局部通道首版即因此 UAF（见缺陷 1 的发现过程）。
- `tests/network/run_m9_bench_harness.sh`（CTest `heyaki_m9_bench`，
  labels network;relay;bench;m9，TIMEOUT 1500，SKIP 77 门控；CI
  coturn-topology job 在 soak 步骤后非 root 直跑，构建目标补
  `heyaki-test-turn-server`）：
  - Phase R：共享已注册 profile 对、每轮 fresh 进程对（干净节点状态），
    轮间等 relay endpoint 表排空（租约自然过期），采集双方 login_ms 与
    initiator connect_ms；门：登录 P95≤2000ms、直连 P95≤3000ms、全部
    `direct_host`。
  - Phase T：同循环 + 双 test-turn-server（不相交 relay 端口段，静态凭
    据 `--turn-username/--turn-credential` 覆写）+ `--force-turn`；门：
    P95≤5000ms、标签 ∈ {turn_udp, direct_srflx}（单机 TURN 提名可为
    本地 srflx×对端 relayed 半中转对，与 M9-07 Windows 矩阵契约一致）。
  - Phase L：3 个 bench responder（shell+fanout）+ 1 个 bench
    initiator 全套件；门：`BENCH_CONNECT peers==订阅者数`、各延迟总体
    failures==0 且 P95≤500ms 保守界、顺序 RPC n==N、fan-out 每订阅者
    delivered==published 且 P95≤1s、三个文件段全部提交、shell ping 无
    失败；末尾 relay 足迹门（endpoint/lease 表归零、RSS ≤ baseline+
    64MiB、fd ≤ baseline+64，信令转发计数差为带宽代行指标——relay 无
    控制面字节计数器导出，记录为已知导出缺口，与 M9-01 丢包估计同类）。
  - env 旋钮：`HEYAKI_BENCH_CYCLES/SUBSCRIBERS/MSG_N/RPC_N/RPC_CONC_N/
    FANOUT_N/FILE_BYTES/FILE_MULTI_BYTES` + 各 P95 门限 + WORK_DIR。
- `docs/operations/runbook.md` 新程序 "Run a performance benchmark
  (M9-10)"：命令模板、门语义（loopback 数字 = 跨提交趋势基线与验收下
    界，拓扑真实 P95 仍在 NAT 矩阵）、读数指引（shell ping 含 ~500ms
  PTY drain tick 设计行为）、工件归档要求（BENCH_METRIC/THROUGHPUT/
  M9_BENCH_OK 行 = M9-11 参数冻结输入）。

**缺陷 1（真缺陷，M4 期潜伏，基准首跑抓出，ASan 钉死）**：双方同时为
同一 `ChannelKind` 建流（shell/stream 域按设计双侧按需创建；
`initiator_owned_domains` 只含 event/file/message/rpc）时，transport 的
`attach_channel` 对已注册 kind 的 `channels_.emplace` **静默失败**——
入站重复流的包装对象不在 map 中，但其 rtc 回调照常入队事件；其
OpenEvent 到达时把**未持有所有权的指针**交给该 kind 的 pending open 完
成回调，事件 variant 在 drain 循环下一次赋值时析构 shared_ptr → 通道对
象释放 → `PeerSession::physical_channels_` 悬垂 → 下一次 `send_frame →
pump → physical->send` 堆 UAF（表现为 `pure virtual method called` 或
SIGSEGV，1-in-N 时序依赖，故 M4-M9 九轮 CI 未暴露；基准的 shell 段 +
多订阅者压力把窗口踩热）。修复（`src/transport/webrtc/
webrtc_transport_session.cpp` + `src/client/peer_session.cpp`）：
  - transport 级确定性收敛——**offerer 的流胜出**：offerer 对重复入站流
    直接关闭拒绝；answerer 把重复包装对象存入 `duplicates_` map 保活，
    其 OpenEvent 到达时 promote（退役自己的流、`channels_[kind]` 换成
    offerer 的流、退役对象活到 handler 末尾让 channel handler 同步改
    指针）；重复流的 Closed/Error 事件不再传导为 pending open 失败或
    整会话 fail。
  - 会话级 `adopt_physical_channel` 对非 initiator-owned 域允许替换
    （初版错用 `config_.initiator` 判替换——offer owner 由 ID 决胜可与
    逻辑发起方相反，ASan 二轮复现钉死该角色错配；正确判据是域是否
    initiator-owned）。
  - `handle(OpenEvent)` 只允许**已注册**通道解决 pending/进入 adoption
    （纵深防御）。
  - `TransportSession::async_open_channel` 契约文档化：双侧可开的 kind
    上 answerer 的 completion 指针不稳定，须装 channel handler 重定向。
  - 回归测试 `M4WebRtcTransport.SimultaneousSameKindOpensResolveTo
    RegisteredChannel`：真双侧 SCTP 同时开 file kind；断言 offerer 拒
    绝计数、双方 open 成功、双向 roundtrip 经 completion/handler 指针
    存活（旧代码 ASan 下必红）；裸跑 8/8 稳定。

**缺陷 2（真缺陷，m7，基准稳定性排查钉死）**：`FileService::prune()` 对
仍在 probing 的 sender（manifest 为空、chunk_count=0）调 `drain_window`，
完成条件 `next_read_chunk(0) >= chunk_count(0)` 空真——探测未在首个
500ms 维护 tick 内完成就发出零字节 FILE_COMPLETE（`complete_sent` 锁
死），接收方按未知 transfer id 静默忽略，真发完后不再补发裁决请求 →
双方永等（接收方全量字节在手）。负载下 probe 慢于一个 tick 即触发
（3 订阅者/ASan 必现，单对空闲不复现——九轮 CI 未暴露的原因）。修
复 = complete 条件加 `manifest.size != 0` 守卫；回归测试
`M7FileService.PruneWhileProbingFiresNoZeroByteComplete`（临时还原缺
陷验证过变红）。

**缺陷 3（真缺陷，m7，缺陷 2 修复后余留快失败暴露）**：
`next_read_chunk` 在读取**派发**时自增——最后一个读的哈希未落
staging 时 `next_read >= chunk_count` 已真、window 恰空，FILE_COMPLETE
抢跑（实测缺 61380 字节 ≈1 个 negotiated chunk）→ 接收方
`complete_early` 协议拒绝 → 发送方 peer_rejected 终止。修复 =
`SenderState.chunks_hashed`（finish_send_hash 递增）替代派发计数作
complete 条件；回归测试 `M7FileService.ConcurrentSendsOfSameSourceBothCommit`
（同源双并发 + prune 穿插，即 CI 暴露的交错）。

CI 收敛（提交链 d411155→a2a0e3d→dc9bcfd→f981167→257cb95→7ce4c83→
4a71ad6，终态 run 34755338925 十 job 全绿——asan m3a_lan 计时与
Windows matrix relay_direct/first-initiates file=0 两处已知抖动家族
rerun 即绿）轮内又暴露并修复缺陷 1 修复自身的三个次生问题（全部
heuristic 由新回归测试在不同 sanitizer/负载下的交错撑出）：
(a) offerer 到达即关闭入站重复流会杀掉 answerer 自己的注册流（其
pending open 以 channel_closed_before_open 误终）——收敛改为单向、
由流主人执行：offerer 只登记忽略，answerer promote 时退役自己的流；
(b) 已注册通道关闭后滞留 channels_ 使该 kind 的后续 open 永久挂在
pending_opens（kind 级死锁）——关闭即释放 kind 映射；
(c) 释放映射时 shared_ptr 引用归零提前析构，PeerSession 裸指针撞已
毁 vtable（shutdown 矩阵 pure-virtual SIGABRT/SEGV 钉死）——关闭/
退役包装对象移入会话生命周期的 closed_channels_ 退役列表。回归测试
最终形态：offerer open 确定（无人可退役 offerer 的流），answerer 结
局按交错容忍（promote 成功 | adopt/mismatch 有界错误，送达门只绑定
成功交错），内存安全由 sanitizer 预设把守；本机 debug 20/20、asan
30/30 稳定。

本机验证：m4 受影响族（webrtc/peer_session/topology/shutdown/session）
全绿；崩溃独立复现场景（bench initiator+responder + shell 段）ASan 构
建 3/3 零报告（修复前 1-in-2 崩）；debug 全量 ctest 60/60；基准
harness 三相位端到端绿（3 订阅者、双循环，终态连续 4/4 全绿）。

坑（后续轮避免）：

1. `steady_clock` 时戳锚点用函数内 static 首调求值会撞表达式求值顺序
   （操作数求值未指定 → 下溢 18446744073709551）；进程锚点必须用命名空
   间级常量。
2. `seed-trust` 的 GrantId 由固定 id_seed 派生：同一 profile 顺序对多个
   peer 播种信任时，同 ID grant 后写覆盖前写（put_trust_grant 按
   GrantId upsert）→ 只有最后一对保持信任；新可选 seed 基数参数，每对
   用互异基数。
3. awk 数组 1 基索引 vs 0 基最近秩下标：单样本文件 percentile 返回空串
   且 `(( <= gate ))` 算术上下文把空串当 0 静默通过——百分位辅助必须
   自测单样本。
4. bash `set -e` 下 `grep -qv ... && fail` 模式在 grep 无匹配（退出 1）
   时整语句失败直接杀脚本——否定断言必须写 `if grep ...; then fail; fi`。
5. relay 四 scope 限速中 per-IP（32/s）在 loopback 上由全部身份共享：
   多节点+多拨号突发会 `rate_limited` 且被拒心跳引发连接重建（基准观测
   到 conn 14/17 → 18/20 重连链）。基准以 300ms 拨号间隔规避；生产部署
   每设备独立 IP 不受影响，但"拒绝后客户端重连"行为记为 M9-11 观察项。
6. relay 控制面无字节计数器导出（`RelayServerSnapshot` 不含 WSS 字节），
   "relay 带宽"以 `signaling_forwarded_total` 差值为代行指标；字节级导
   出缺口与 M9-01 packetsLost 同类记录。
7. `set -o pipefail` 下 `grep`（零匹配退出 1）在管道里会杀整条赋值
   语句——`unique=$(grep|sed|wc)` 类"零命中=合法缺失"的收集必须
   `{ grep ... || true; } | ...` 守卫，否则失败被静默吞掉且现场不保
   留（本轮 harness 三次静默退出均此因）。
8. 基准套件的多 peer 采样必须等满期望数量（首个会话认证即采样会漏
   掉 staggered dial 的后来者——fan-out 订阅者静默缺席）；harness 侧
   `peers==订阅者数` 门与套件侧 20s 等满双向锁死。
9. 无断言的 python 文本补丁会静默不匹配（本轮 peers 门首次"添加成
   功"实未落盘）——脚本类补丁必须 assert 锚点或事后 grep 验证。
10. relay.conf 内的路径按 config 文件位置解析：`--work-dir` 必须传绝
    对路径（CTest 注册传的是绝对路径，手动调用传相对路径会让 relay
    报 certificate_missing）。
11. shell 交互延迟实测 p50≈300ms：PTY 输出在 500ms 维护 tick
   （`prune_peer_services` 里的 `shell_pty->drain()`）上排空是 M8-04
   设计行为——"交互优先级"通道的输出侧不走事件驱动。若 M9-11 冻结交互
   延迟目标，需评估 drain 触发点（输出即排或缩短 tick），这是参数/产品
   决策而非基准轮改动。

### Round 11（2026-09-13）：M9-11 参数冻结 + 孤儿 staging 清理

交付物：

- `docs/operations/parameter-freeze.md`（冻结表）：三栏语义（默认值 / 硬上限 /
  测量依据）覆盖 Runtime、Relay 客户端、会话与信令、五个服务、LAN 与安全面、
  shell/file root、relay 服务端、无配置面的硬编码设计常量（500ms 节点 tick、
  50ms PTY tick、60KiB SCTP 经验上限、per-domain 通道容量、base/4 jitter 等）
  九族；v1 验收数值对账表（登录 22ms/2s、直连 1021ms/3s、TURN 1077ms/5s 等
  余量 3–90×）+ **结论：默认值零调整**——M9-10/09 实测全部低于验收门，本轮
  只补上限与冻结。冻结语义：改默认值/上限必须同提交更新文档与测试。
- 九处校验补硬上限（全部拒绝式，无静默 clamp；上限普遍为默认值 16–256×）：
  - `validate_config`（`src/client/runtime.cpp`，**新导出**至
    `include/heyaki/runtime.hpp`）：五容量 ≤65536、executor 线程 ≤64/256、
    11 个生命周期超时 ≤10min（原仅 ≥0）。
  - `validate_relay_node_config`（`src/client/node.cpp`，**新导出**至
    `include/heyaki/node.hpp`）：connect/handshake/close ≤60s、
    heartbeat ≤120s（= 租约绝对上限——心跳节奏必须能在租约内续期的不变式）、
    backoff ≤10min/1h、收发队列 ≤65536（原仅非零）。
  - `RelayWssClient::create`：容量 ≤65536、三超时 ≤60s。
  - `validate_channel_budget_config`：per-peer/单通道队列帧 ≤65536、字节
    ≤256MiB（会话内存最大放大器）。
  - `validate_byte_stream_limits`：窗口帧 ≤65536、并发流 ≤1024、pending 写
    ≤64MiB、pending 读/写 ≤4096（原仅非零）。
  - `SignalingCoordinator::create`：attempt 表 ≤65536、候选 ≤4096、attempt_ttl
    ≤10min、入站限速 ≤100000/60s、rate key ≤1Mi（原仅非零）。
  - 五服务 attach（message/event/rpc/file/shell）：全部容量字段上限
    （frame ≤65536、byte ≤64–256MiB、fan-out 双向封顶、send window ≤256MiB、
    并发 send ≤256、rpc 并发 ≤4096）；`result_cache_entries=0 = 禁用重放缓存`
    显式为契约行为（非零 ≤65536）。
  - `validate_shell_profile`：idle ≤24h、absolute ≤7d、max_output ≤1GiB、
    POSIX 输入 pending ≤1MiB（Windows 128KiB 管道帽继续强制）。
  - `validate_relay_server_config`：`control_write_queue_frames` ≤65536、
    lease per-device/per-tenant ≤65536（原仅非零）、限流四 scope 策略校验
    从 `RelayServer::create` 前移到 config 层（配置文件错误即时暴露）。
- 孤儿 staging 清理（Round 8 移交评估项落地）：
  `file_store::sweep_stale_staging(root, 24h)`（`src/client/file_store.cpp`）——
  严格 `.heyaki-<32hex>.part/.state` 匹配（用户文件/目录/symlink 指向目录
  永不触碰、单条目失败静默跳过）、last_write 早于 24h 年龄门才删；接入
  `FileService::attach()` 每接收根向阻塞 worker 投递一次 fire-and-forget 清理
  （不在 strand 扫描、不阻塞会话、失败不通知）。24h 依据：M9-08 整形链路
  最慢传输数十秒量级，年龄门在其三个数量级之外。
- Round 10 移交决策（冻结表 §9 逐项）：shell 500ms tick **冻结保留**
  （p50≈300ms 已实测有界；事件驱动 drain 需改 M8-04 strand 单拍模型，记
  v1.x 候选 + bench shell 段可量化验收）；packetsLost **维持 bytes/rtt**
  （M9-19 切 libnice 后 getStats 面变化，届时统一重估）；per-IP 32/s
  **默认保留** + NAT 共享出口 IP 部署需上调（cap 1024）记 runbook 观察项。
- `tests/unit/m9_parameter_freeze_test.cpp`（18 例，CTest
  `heyaki_m9_parameter_freeze`，labels unit;config;m9;parameters;freezing）：
  八个 defaults 测试钉死九族全部默认值、七个 caps 测试逐一断言"上限 +1 拒绝"、
  sweep 三例（只删陈旧 staging/缺根失败/attach 投递契约）+ 服务层 attach 拒绝
  五例（复用 m6/m8 harness 的会话对，超配 config 在开通道前拒绝）。
- runbook Quick reference 增加冻结表链接与变更纪律（同提交改文档+测试）。

CI 收敛（提交链 58d9a1b→696f81f 两轮 CI 修复，终态 run 34793054222 十 job
全绿——windows network matrix turn_udp/first-initiates 首轮抖动 rerun 即绿，
与 Round 9/10 已知家族同款）：首轮 CI（run 34767278946）四个 Linux job
Build 步失败——include m8_support.hpp 但未用其全部 helper 的测试 TU 触发
`-Werror=unused-function`（本机未开 warnings-as-errors 故未现，Round 8
同款坑），helper 加 [[maybe_unused]]；第二轮（run 34768253190）两个新发现：
(1) 冻结测试 ShellProfileCapsRejectOversized 用 `/bin/sh` 作 argv[0]，被
Windows 可执行语法校验（P2-F1，仅盘符/UNC 根为绝对路径）在 caps 断言前
拒绝——按 m8_support 先例按平台选 argv[0]；(2) Round 10 的
SimultaneousSameKindOpens… 回归测试只对 offerer 轮询重复流拒绝计数器，
但哪一端登记败者流取决于 attach 竞争（对端流先于己方流注册时角色翻转），
sanitizer 负载下连续两轮 asan+tsan 三次红——按"两条流映射一个 kind，必有
一端登记拒绝"的双端容忍修正（内存安全 oracle——注册指针 roundtrip——不变，
本机 -Werror 下 6/6 稳定）。gcc Release 的 m3b onboarding/m6 TUI harness
失败为已知抖动家族（同 run clang Release 同测试绿）。

坑（后续轮避免）：

1. `RelayServerConfig.listen_port = 0` 是**合法语义**（OS 分配临时端口，全部
   服务端测试与嵌入方依赖）——首轮把"端口 0 校验缺失"当缺口补校验后
   m3b/m4/m9 三个服务端测试族全红，已撤销；"硬上限"清单必须先核对既有用法
   再动笔。
2. `validate_config` 原藏在 runtime.cpp 的匿名命名空间（内部链接）——导出公共
   声明时须把定义移出匿名命名空间；注意 `heyaki::detail::{anon}` 内的辅助
   （valid_runtime_text）在 heyaki 作用域要 `detail::` 限定。
3. 服务层校验在 `attach()` 而非 create——测试拒绝路径必须走真 attach（复用
   m6_support 会话对最省事），不要为可测性重构五个服务的构造签名。

本机验证：全量 ctest 61/61 通过（6 环境门控跳过与基线一致）；冻结测试覆盖
的全部拒绝路径逐例断言 configuration 错误码。CI 终态 run 34793054222 十 job 全绿（2026-09-14，提交链 58d9a1b→696f81f；windows matrix 首轮抖动 rerun 即绿）。

### Round 12（2026-09-14）：M9-12 schema N-1/N 兼容、rolling relay upgrade、新旧设备互通

协议面盘点（动笔前对账）：wire 版本协商（`negotiate_protocol`：major 必须相等、
minor 取 min、能力交集、required 位双重校验）已接入 SESSION_HELLO、LAN
presence/hello、relay login/enrollment 四个握手；relay DB 已有 v1→v2 迁移 +
`schema_too_new` 拒绝打开（m3b_relay_database 测试）；ProfileStore 已有 v1 迁移
（m2_profile 测试）。本轮据此定位三个真缺陷并补齐端到端兼容测试面。

三处缺陷修复：

1. **LAN 发现域版本门（新旧互通阻断）**：`validate_lan_presence` /
   `validate_lan_hello` 的 `minor < current_protocol_version.minor` 是 M3a 立项期
   （minor=0 时代）的写法，1.2 出现后语义变成"1.1 设备从 1.2 设备的 LAN 目录
   里整体消失"——与 wire §4 的协商语义（capability gating，而非版本同化）冲突。
   修复：下限改为 `lan_supported_minor_floor = 1`（新公共常量，LAN discovery/
   signaling 位所在的 minor），同 major、minor ≥ 1 准入；1.0 天然被"必须携带
   LAN 位"挡住，异 major 拒绝不变。发现准入从不蕴含会话兼容——后者仍由
   SESSION_HELLO 协商裁决。
2. **重启帧协商能力位强制缺口（越能力驱动）**：`session_restart_*` 帧此前只在
   发起侧入口（Node `begin_session_restart`）检查协商位；接收侧 PeerSession 对
   入站 offer/answer/candidate 无条件转发 handler——一个协商在 1.1 的会话可被
   对端驱动重启流程（wire §4："parseable 不等于 enabled"）。修复：收发两侧都在
   PeerSession 收口——`send_restart_frame` 协商位缺失时显式拒绝
   （`restart_capability_not_negotiated`）；入站重启帧在协商位缺失时计数后忽略
   （不转发、不失败会话，与"无 handler 时跳过"同级处理）。
3. **relay login 完成能力越版授予**：登录完成返回的能力集原为
   `supported & known_capability_bits`，未按协商版本钳制——自报 {1,1} 却声称
   bit 12 的设备能拿到越版授予。修复：按协商 minor 取
   `capabilities_for_version`（由匿名命名空间导出至 `include/heyaki/
   protocol.hpp`）交集后授予，与会话侧语义对齐。

文档修正（与实现长期不一致的两处）：

- wire 协议 §4 "Protobuf unknown fields follow normal proto3 preservation/
  skipping rules" 与实现相反——全部 inter-peer 消息是 canonical 签名对象或有界
  datagram，解析器显式拒绝未知字段（跳过会改变签名输入/静默改行为）。改写为
  "解析器拒绝未知字段；v1.x 增加可选字段/能力是 minor 变更，但发射方必须按
  协商 minor 门控，N-1 接收方永远不会观察到其会拒绝的字段"，并补 canonical
  签名理由。
- wire 协议 LAN presence 段补准入规则成文（同 major、minor ≥ LAN 位引入版；
  发现准入不蕴含会话兼容）。
- runbook 新程序 **"Roll a relay upgrade"**：备份 → `PRAGMA user_version`
  前后对账（只进不退）→ 换二进制重启 → 免重登记验证（`login_completed` 事件
  + schema gauge）→ 验证通过后才取升级后备份；明确 `schema_too_new` 拒绝打开
  是回滚边界。"Roll back a version" 的验证步骤锚定 compat 套件。

测试：`tests/unit/m9_compat_test.cpp`（11 例，CTest `heyaki_m9_compat`）六面：
协商语义（下调/交集/全 minor 映射/异 major/越版 required 拒绝）、1.2↔1.1
loopback 会话（协商 {1,1} 后重启帧发送拒绝 + 入站忽略 + 计数，1.2↔1.2 对照
转发）、relay login（1.1 准入 + 能力钳制 + `incompatible_major_version`/
`required_capability_unavailable` 握手期显式拒绝；未知 required 位在 encode 层
即不可编码，测试注明不重复覆盖）、enrollment 1.1 准入、LAN（1.1 presence/hello
准入；1.0/异 major/缺 LAN 位拒绝）、rolling upgrade（v1 schema + 真实 device 行
→ 原库打开迁移 v2 → 免重登记 login 成功 → 关闭重开再登录 + audit 累积）。
loopback 会话对沿用 m5 harness 模式（双侧预开控制通道，响应方经 hello 采纳
入站通道；`inject_into_left` 经第二控制通道注入裸帧以绕过发送侧门控，单独
覆盖接收侧行为）。

坑（后续轮避免）：

1. 编码层（`encode_relay_login_request` 等）已有 `supported.contains(required)`
   前置校验——"未知 required 位"在客户端就不可编码，wire 级测试只能覆盖
   encode 允许而协商拒绝的形态（异 major、越版 required）；不要为覆盖面在
   测试里手拼绕过 encode 的字节。
2. bootstrap token 带真实墙钟过期校验：测试用固定 kNow（2023）构造 token 会
   在 `create_bootstrap_token` 处失败，enrollment 流测试须用 `now_milliseconds()`。
3. relay/enrollment 的 Result 语义差异：`RelayDatabase::open` 返回
   `Result<RelayDatabase>`（值语义，无 reset），生命周期用作用域块表达；
   `Identifier::bytes()` 只在 Identifier 类上（DeviceId 有、IdentityPublicKey 是
   裸 array 没有）。
4. 本仓库 pinned 依赖目录曾被 in-source `cmake .` 污染（libdatachannel 及其
   plog/usrsctp/libjuice 子模块的生成 Makefile/CMakeFiles），依赖校验
   （`ensure_clean_repository` 连 untracked 都算）会拒绝配置；恢复方式 =
   `git checkout --` 受污染 tracked 文件 + 删除生成物，再跑
   `scripts/fetch_third_party.sh --with-tests` 验证。

本机验证：全量 ctest 62/62 通过（新增 heyaki_m9_compat；7 个 root/coturn/
soak 门控跳过与基线一致）。

CI 收敛（终态 run 34849636945 十 job 全绿，2026-09-14）：首轮 run 34848612328
四个 Linux job Build 失败——`PeerSessionRestartHandler` 指定初始化只写
`on_restart_offer` 触发 `-Werror=missing-field-initializers`（CI 开 Werror
本机未开，Round 11 同款坑族），补全 answer/candidate 成员（0f824b7）。
第二轮九 job 一次绿、windows (Debug) 的 `heyaki_windows_network_matrix`
连续三轮各红一个**不同**场景（turn_udp/first → relay_direct/first →
relay_direct/second，签名 file=0/authenticated=0，其余场景每轮全过）——
与 M9-07/09/10 记录的 first-initiates 抖动家族同因（第 4 次尝试绿）。
compat 套件在 Windows 全平台一次通过。

### Round 13（2026-09-15）：M9-13 fuzz 持续时间扩展、覆盖补缺、regression corpus

交付物：

- **ProfileStore migration fuzz 目标**（M9-13 点名的最后一块 parser/状态机空白）：
  `tests/fuzz/profile_store_fuzz.cpp`（新 libFuzzer entry
  `heyaki_profile_store_fuzzer`，同编译进 `heyaki_fuzz_smoke`）。四种输入模式
  （首字节低 2 位）：合法 v1 fixture（正路径：迁移成功 → backup 存在 → 幂等
  重开）；攻击者字节写入 identity 行 public_key 列（schema 合法、内容恶意）；
  按 fuzz 字节比例截断的 v1 DB；整文件随机字节。oracle 全部为 M2 测试钉死的
  迁移契约：成功必须留下 `migration_backup_path(path, 1)` 且重开成功；失败后
  DB 文件必须仍在磁盘上；**仅当迁移确已开始**（合法 v1 schema）失败时才必须
  留 backup——纯损坏字节在 migrate 前就显式失败，不欠 backup（初版误把 backup
  断言放在全部失败路径上，会被"读得出 user_version=1 但表损坏"的截断文件
  误报）。
- **覆盖审计与补缺**：20 个 harness 目标逐一核对 entry 分发。发现 m6/m7
  service payload parser 只在 smoke 直调、不在任何 libFuzzer entry → 补入
  frame-parser entry（含 VT 在内的 parser 面由此全部进入时长扩展范围）；
  `heyaki_connection_state_fuzzer` 之前只编译、CI 从未运行 → 纳入 CI fuzz 步骤。
- **持续时间**：CI `-runs=100`（实际 <1s/目标）→ 逐目标 `-max_total_time=60`
  （profile 90s，文件系统/SQLite 开销大），clang Debug job 每轮约 5.5min 专项
  fuzz；`-rss_limit_mb=4096` 防内存爆。长跑路径：corpus README 记录
  `-max_total_time=1800` 本地命令。
- **regression corpus**（M9-13 保存要求）：仓库内 `tests/fuzz/corpus/`
  （frame-parser 5 例、protocol-state 1、protobuf-parser 4、
  lan-directory-state 3、connection-attempt-state 2、profile-store 5 +
  README）。README 记录目录→entry 映射表、golden-frame 溯源
  （m1-golden-vectors.json frame.bytes_hex）、最小化纪律（crash →
  `-minimize_crash=1` → 修复合入时同提交最小单元）、长跑命令。smoke 每轮回放
  全部 80 个单元（新 `HEYAKI_FUZZ_REGRESSION_CORPUS_DIR` 编译定义指向源树，
  缺目录即报错）；CI libFuzzer 以 `tests/fuzz/corpus/<entry>` +
  `build/fuzz-corpus/<entry>` 双目录做种子（提交单元持续参与、生成单元不落盘
  仓库）。

坑（后续轮避免）：

1. `ProfileStore::open` 对**数据库文件本身** stat 并拒绝 group/other 位
   （`profile_permissions_too_wide`）——外部构造的 v1 fixture 必须
   `chmod 0600`（M2 fixture 先例 m2_profile_test.cpp:118）；目录链同理（加密
   文件后端拒绝过宽目录，fuzz 根 + case 目录都要 0700）。进程内反复用的
   fuzz 临时根要在创建时立即收紧，不能依赖 umask。
2. smoke 退出码断言勿经管道（`smoke | tail` 后 `$?` 是 tail 的）——首次
   "EXIT=0" 是假象，真实 abort 靠重定向到文件再查发现。
3. libFuzzer entry 是 Clang-only（HEYAKI_BUILD_FUZZERS），本机无 clang 时
   只能以 smoke 验证新目标；entry 的编译/运行验证依赖 CI clang Debug job。

本机验证：全量 ctest 62/62（fuzz label 含新 profile 目标的 smoke 回放全绿）。

CI 收敛（终态 run 34880683984 十 job 全绿，2026-09-15，提交链 ca9bf1a→
e06b8eb→5322a5a）：首轮 clang Debug Build 失败——新 entry 漏 `<cstdint>`
（本机 gcc 经传递头可用，CI clang -Werror 下现形）；第二轮 windows Release
的 `heyaki_fuzz_smoke` 以 0xc0000409（fail-fast）中止——fuzz fixture 用默认
SecretBackendOptions 存身份密钥（Windows 上解析到 OS 凭据库），而
ProfileOpenOptions 强制加密文件后端，open 解析不到已存 handle 即失败触发
目标 abort（Linux CI 无 OS 后端可回落所以本机/首轮不现）——修复为 fixture
与 open 两侧都钉加密文件后端（同 M2 fixture 先例）；第三轮 windows 双 job
转绿、sanitizer (tsan) 在 M3BRelayWssClientTest.
LogsInHeartbeatsPublishesAndQueriesEndpoint 等待 endpoint 查询处超时一次
（tsan 慢负载抖动家族，与本轮纯 fuzz 改动无关），rerun 即绿。

### Round 14（2026-09-15）：M9-14 secret/vuln 扫描、SBOM/许可证门禁、编译加固、发布签名

交付物：

- `apps/release/heyaki_release_sign.cpp` + `heyaki-release-sign` 目标
  （pinned libsodium Ed25519）：`keygen`（私钥 0600、key id =
  SHA-256(pubkey) 前 16 hex）/ `manifest`（正则文件、字节序排序 POSIX
  相对路径、symlink 排除防链接目标走私、严格解析：count 不符/乱序/
  `..` 路径/坏摘要全拒）/ `sign`（64 字节 detached）/ `verify`（签名校
  验）/ `check`（重散列 + 缺失/多余/篡改文件三向对账）。
- `cmake/HeyakiProjectOptions.cmake`：FORTIFY 探针（`-Werror -O2
  -D_FORTIFY_SOURCE=3/2` 阶梯——distro 工具链优化时预定义 fortify，
  异值重定义是警告、同值静默，阶梯最坏落在 distro 自身级别）+ CET
  探针（x86）；`heyaki_configure_target` 对非 STATIC/INTERFACE 目标加
  `-Wl,-z,relro,-z,now,-z,noexecstack`、EXECUTABLE 加 `-pie`；MSVC 加
  `/GS /guard:cf` 编译 + `/GUARD:CF /CETCOMPAT` 链接（x64）。
- 顶层 `CMakeLists.txt`：`HEYAKI_HARDENING`（默认 ON）+ 全局
  `CMAKE_POSITION_INDEPENDENT_CODE ON` + `add_compile_options(
  -fstack-protector-strong [CET] [$<优化配置>:-D_FORTIFY_SOURCE=N])`——
  对象级缓解覆盖 vendored C 库与 pinned in-tree 依赖（链接级缓解只在
  全部对象 PIC 时才成立）。FORTIFY 仅优化配置：-O0 下 glibc 警告不生效，
  在 `-Werror` 下致命。
- `cmake/GenerateSupplyChain.cmake`：heyaki 包入册（版本+commit）、
  版本化 namespace、`heyaki_enforce_license_policy`（见勾选项）；
  `tests/supply_chain/CheckGeneratedSupplyChain.cmake` 断言发布身份
  五要素。
- `scripts/osv_vulnerability_scan.py`（stdlib-only）+
  `deploy/security/osv-triage.tsv` +
  `tests/supply_chain/run_vulnerability_scan_test.sh`（CTest
  `heyaki_m9_vulnerability_scan`，`HEYAKI_REQUIRE_VULN_SCAN` 门控）。
- `scripts/run_secret_scan.sh` + `deploy/security/{gitleaks.toml,
  secret-scan.lock}`（CTest `heyaki_m9_secret_scan`，
  `HEYAKI_REQUIRE_SECRET_SCAN` 门控；pinned gitleaks 8.24.3 sha256
  `9991e0b2…f4ee29c` 与官方 checksums.txt 一致）。
- `tests/supply_chain/run_hardening_check.sh`（CTest
  `heyaki_m9_hardening_check`；sanitizer/非 Linux 注册期排除）与
  `run_release_signing_test.sh`（CTest `heyaki_m9_release_signing`）。
- `.github/workflows/ci.yml` 新 `supply-chain` job：全历史 checkout
  （`fetch-depth: 0`——secret scan 扫的是 git 历史，浅克隆会空转通过）
  + Release 构建 + 双门控 + 全量 ctest + 离线 pin 校验。
- 文档：`docs/operations/release-signing.md`、
  `docs/supply-chain/m9-release-audit.md`（审计总录：六控制矩阵、
  31 命中处置、coturn 镜像/回退包单审、OSV 覆盖限制与补偿）、
  `dependency-policy.md` 更新。

真缺陷/真实发现（本轮扫描产出）：

1. `.mimosa/` 会话工具状态被 48d7ef40/386f82a（2026-08-25）整体误提交
   （5003 个文件、2.1M 行），直至本轮 secret scan 基线才暴露。处置：
   `git rm -r --cached .mimosa` + `/.mimosa/` gitignore（磁盘文件保留，
   不碰正在运行的插件状态）；历史不重写（仓库政策），allowlist 以
   "工具自身哈希/代码标识非凭据"留档至历史老化。教训：`git add -A`
   型提交后无人看 stat 总量。
2. coturn Ubuntu 回退包 4.6.1-1build4 落在多个 2025/2026 CVE 影响域；
   4.10.0 镜像缺 CVE-2026-43915/53448（admin 面板）修复但部署面
   `no-cli` + 无 web-admin → not-affected（审计记录 + 发布时复检项）。

坑（后续轮避免）：

1. CMake `option()` 不拼接相邻字符串字面量——多行描述必须是单个
   引号串（首个本机配置即 fatal）。
2. gitleaks 8.24.3 的 `[[allowlists]]` 数组形态能解析但**不生效**，
   必须用 legacy `[allowlist]` 单表（版本特定行为，config 内注释留档）；
   TOML 正则串用三引号 `'''…'''`，两引号 + 双引号混拼会报
   "array elements must be separated by commas"。
3. allowlist `regexTarget = "match"` 的 match 文本不含规则捕获组外的
   字符（generic-api-key 命中从 `password` 起而非 `"password` 起）——
   正则勿带前引号。
4. `readelf` 输出随 locale 本地化（本机 `类型:`）——任何解析 readelf
   的脚本先 `export LC_ALL=C`。
5. 手写协议要读写同源生成：manifest 计数行写入 `N files` 而解析只认
   纯数字（测试首跑即抓出）；签名单一实现、双端共用常量。
6. GitHub Actions step 名含 `: ` 必须 quoted（首个 push run 秒挂
   "workflow file issue"）。
7. OSV API 对畸形 commit（40 位以外）回 HTTP 400 而非空结果——对照
   commit 常量抄错一位就会把"基础设施失败"误判为"查询干净"。
8. `gitleaks git` 子命令用位置参数传仓库（无 `--source`），全局 flag
   （`--no-banner` 等）与子命令 flag 分开。
9. `set -o pipefail` 下 `tr </dev/urandom | head -c N` 必然 SIGPIPE 141
   （head 读满即退，tr 还在写）杀整个脚本；随机串生成要么限输入流
   （`head -c 4096 /dev/urandom | tr -dc …`，输出量远小于管道缓冲）要么
   纯 bash `$RANDOM` 循环。
10. 验证脚本时 `script | tail` 会把非零退出码换成 tail 的 0——必须显式
    看 `${PIPESTATUS[0]}` 或不经管道直跑（本轮 secret scan 141 曾被
    `| tail -2` 掩盖成"通过"）。

本机验证：build/werror（Debug+Werror+全部加固 flags）全量 ctest 66/66
绿（7 个 coturn/matrix 门控 SKIP + 2 个新扫描门控 SKIP）；带双门控后
五个 M9-14 测试全绿；build/release 的 `heyaki_m9_hardening_check
--expect-fortify` 过；IVA 独立验证 A–E 全 PASS（readelf 八项属性、
manifest 字节确定性、63/64 字节坏签名拒绝、`../` 路径逃逸拒绝、
已知漏洞 commit 负路径 UNTRIAGED 退出 1）。

CI 收敛（终态 run 35000284600 十一 job 全绿，2026-09-15/16，提交链 06f8f91
→9aa37c5（workflow 修复）→3cbfa5c（三修复））：首轮 run 34994202823 因
ci.yml step 名含未加引号的冒号被 workflow 解析器秒拒（坑 6）；
run 34994347040 收敛至三失败（tsan race / ubsan 签名超时 / secret scan
自命中），三修后 windows (Release) 首跑挂在
M3aNodeTest.LanLifecyclePressureRemainsBounded（3s 时序预算等待超时，已知
m3a 抖动家族——本机并行跑 m3a_lan 亦偶发、单独重跑即绿），rerun 即绿。

1. **sanitizer (tsan) 抓出 M4 期真 data race**（全部 gtest 用例 OK 但封装器
   检出 tsan 报告）：主线程 `set_*_handler` 写 `std::function` 成员 vs
   'heyaki-asio' 线程 `handle(OpenEvent&)`/`publish_snapshot` 读同一成员
   （webrtc_transport_session.cpp:1099 写 / :598、:601 读）。生产同样存在
   窗口：对端先行开通道时 OpenEvent 可在 owner 装 handler 前入队派发。
   修复 = 三个 handler 合并为不可变 `HandlerTable`，经
   `std::atomic<std::shared_ptr<const HandlerTable>>` 原子发布，读者
   acquire 载入一致快照（setter 仍单 owner 线程契约）；本机 tsan 8/8 次
   零报告 + peer_session 干净。
2. **sanitizer (ubsan) 的 `heyaki_m9_release_signing` 超时**：本地复现通过
   → 判定非挂起而是 I/O——sanitizer Debug 的 relay 二进制 ~200MB，测试对
   其 4 次哈希 + 3 次拷贝在慢速 runner 磁盘上撑爆 120s。bundle 二进制改
   为签名工具自身（小体积真实产物），bundle 路径取 artifact 基名，
   TIMEOUT 提至 300s；ubsan 本地全过（202MB relay 手工形态亦过）。
3. **supply-chain job 的 secret scan**：驱动脚本自身的正控字面量
   （AWS 形 20 字符伪令牌，精确值见 gitleaks.toml 的逐字符 allowlist 条目）
   被上一提交带入历史（本地跑时脚本未提交所以
   未现形）→ 每次全历史扫描命中 AWS 规则。修复 = 键体改运行时生成（首版
   `tr </dev/urandom | head` 在 pipefail 下必然 SIGPIPE 141 被 IVA 抓出，
   终版纯 bash `$RANDOM`）+ 历史字面量按逐字符精确 allowlist（近似令牌仍
   拒绝，IVA 反证 `…E4OB` 仍 exit 1）+ `--gitleaks` 预装分支补建缓存目录。
   修复过程教训：管道后取输出用 `| tail` 会吞非零退出码，验证必须看
   退出码本身。

### Round 15（2026-09-16）：M9-15 安全回归八面

覆盖矩阵审计（八攻击面 → 控制点 → 既有/新增测试的完整映射见
[../security/m9-security-regression.md](../security/m9-security-regression.md)）：
multicast 洪泛（既有 wire 洪泛 + 编码层篡改）、LAN TLS MITM（既有双指纹
替换拒绝）、降级（M9-12 compat 套件完备）、越权 method/topic（既有五服务
scope 族 + 会话级 default-deny）四面经核对已有覆盖，本轮补齐五个真缺口
族，全部端到端或原语级：

- **LAN wire 伪造/重放**（m3a `ForgedReplayedAndMismatchedPresenceRejected
  OverWire`，真组播 socket）：签名尾字节翻转 → `presence_signature_invalid`；
  32 字节 device_id 字段覆写 → `presence_device_id_mismatch`（派生校验先于
  签名验证）；低序列重放 → `presence_sequence_replay`。目录恒 1 条目、
  datagrams_rejected ≥ 3、authenticated_connections == 0。
- **slowloris 与跨源容量帽**（m3a 两例）：滴注 TLS 记录头 + 部分
  ClientHello 两轮被握手死线回收（timed_out 递增、provisional 归零），
  随后受信真实 peer 在同一 listener 照常认证；127.0.0.2/.3 占满
  capacity=2 后 127.0.0.4 第三连接被 `provisional_connection_capacity_full`
  拒绝（非 Linux 无备用环回源即 SKIP，Linux 上结构性不可跳过——bind 失败
  走 FAIL 分支）。
- **密码面四例**（m5）：退避窗口 1000→2000→4000→4000（clamp）全表 +
  成功清零（fake clock）；A 限流同时 B 即时配对（无全局锁死）；签名翻位
  TrustGrant 接受侧 authentication 拒绝 + TrustStore 零持久化；密码字面量
  泄漏猎杀（审计 detail + profile 根递归全文件字节扫描 + "argon2" 不入
  审计）。relay 侧按协议不接触密码，泄漏面不存在。
- **伪造 grant/candidate/endpoint**：第三方密钥 candidate（绑定字段全照抄、
  攻击者密钥签名）拒绝（m4_signaling 扩展）；endpoint 记录冒名 E2E
  （m4_relay_signaling `EndpointPublishIsBoundToLoggedInSession`：A 会话签发
  B endpoint 的有效签名记录 → `endpoint_record_session_mismatch`，会话
  绑定先于验签；正控先行——`send_error` 恒 close-after-write，拒绝后不能
  再用同一连接）。
- **文法与路径原语**：`trust_scope_covers`（授权匹配原语）精确/前缀通配
  全表——`prefix:*` 只覆盖 `prefix:x`（含更深层），不覆盖裸 prefix/
  `prefix:`，`:*`/`*`/空串不构成全局通配；`safe_logical_file_name` 攻击
  形态全表（NUL/控制字节/反斜杠/空段/尾点尾空格/COM1-9·LPT1-9·CON·PRN·
  AUX 任意大小写+扩展名/512B/32 段边界含恰好达界正值）；m7 终段 symlink
  被 rename 替换不跟随（逃逸目标从未创建、终路径为字节一致常规文件）。
- **relay 放大**（m4_relay_signaling 两例）：服务端 oversized WSS 帧
  （裸 beast 客户端写 16× `max_relay_wss_control_frame_bytes` → 会话丢弃、
  server 保持 running、新客户端照常登录——服务端 `read_message_max` 首次
  有真 socket 对拍）；信令 1:1 无放大（A→B 8 发 = B 恰收 8、第三方 C 与
  发送方零接收、`signaling_forwarded` 恰好 +8）。

交付物清单：`tests/unit/m9_security_regression_test.cpp`（CTest
`heyaki_m9_security_regression`，labels unit;security;m9;regression）；
m3a/m5/m4_signaling/m4_relay_signaling/m7 五文件新增 13 例；
`docs/security/m9-security-regression.md`（八面矩阵 + 残余接受项 + 坑表）；
threat-model §7 增 M9-15 回归门条目。零生产代码变更。

坑（后续轮避免）：

1. `encode_lan_presence` 先验证后编码——签名不符/身份不符的 presence 无法
   经 codec 序列化（`ASSERT_TRUE(datagram)` 在 lambda 里失败只退出 lambda、
   不发报，现象是"对端永远收不到"）；wire 级伪造必须对合法编码做字节手术
   （签名是 payload 末字段，尾字节=签名尾字节；device_id 可按 32 字节模式
   搜索定位）。
2. presence 字节级重复 = 幂等吸收（无错误无计数）；重放错误只在更低序列或
   退役 boot nonce 时出现——触发条件是"先推进再回退"。
3. relay `send_error` 恒 close-after-write（与 `send_signaling_error` 不同）
   ——测试依赖"被拒后继续用同一控制连接"时必须把正控放在拒绝之前。
4. `per_source_provisional_capacity` ≤ `provisional_connection_capacity`
   是 LAN 配置不变式（profile 层 `invalid_lan_configuration` 拒绝）。
5. GCC `std::filesystem` 无 `create_file_symlink`，用 `create_symlink`。
6. m3a 真实 socket 测试的诊断纪律：等待特定 `last_error` detail 的轮询在
   失败时打印实际 detail 与 received/rejected 计数（本轮排障的关键手段，
   已留在测试里）。

本机验证：debug 全量六目标（m9_security_regression 2/2、m5 9/9、m3a
29+4 skip（既有环境门控族，新测试零跳过）、m4_signaling 22/22、
m4_relay_route 9/9、m7 symlink 2/2）；werror 构建零警告（收敛掉一处
sign-conversion）+ werror 下行为全绿；IVA 独立验证 PASS（六目标二连跑
12/12 零抖动、ctest 注册与 labels 核对、m3a 对抗过滤三连跑确认 Linux 上
不跳过且结构性不可跳过、跨序隔离、断言质量逐条核验无空断言）。

CI 终态：run 35099111718（提交 4ba8d77）**十一 job 首跑全绿**（2026-09-16，
零 rerun——含 windows Debug/Release 双 job 与全部 sanitizer/supply-chain/
coturn-topology；Linux 各 job 15-28min、windows 31-38min）。

### Round 16（2026-09-16）：M9-19 TURN/TCP 解封（libnice 双后端）+ TURN/TLS 全后端硬拒绝

**交付形态**：ICE 后端双构建。`HEYAKI_ICE_BACKEND`（默认 `juice`；`nice`
= 系统 libnice，Linux only，pkg-config 探测复用 libdatachannel 自带
FindLibNice/FindGLIB，地板 0.1.21=ubuntu-24.04 线；Windows 显式 FATAL_ERROR
指回独立决策点）。nice 构建编译宏 `HEYAKI_WEBRTC_TCP_TURN=1`（build_config），
新公共谓词 `heyaki::tcp_turn_backend_supported()`（node.hpp 导出；
webrtc_transport_session.cpp 实现——**坑：初版实现落进匿名命名空间，
外部符号未定义、全部链接失败**，移出到具名命名空间修复）；Node 两处
transport config 组装点（start_webrtc_transport/start_restart_transport）
显式镜像谓词值。libjuice 构建行为不变（`allow_turn_tcp` 仍
`tcp_turn_backend_not_verified` 拒绝）。

**TURN/TLS 调研修正（本轮核心发现）**：立项时"libnice 官方支持 TURN/TCP+TLS"
的前提对 TLS 一半不成立——libnice `agent_create_tcp_turn_socket` 的 TLS 包装
只覆盖 GOOGLE/OC2007 兼容模式且是伪 SSL（pseudossl.c）；RFC5245 标准 ICE 下
`NICE_RELAY_TYPE_TURN_TLS` 走 `nice_udp_turn_over_tcp_socket_new` 明文路径。
libdatachannel v0.23.2 把 `turns:` 原样映射 TURN_TLS 交给 libnice。因此
"配置 TLS 实得明文"是必须拒绝的配置谎言：`allow_turn_tls` 候选类 +
`NodeIceServerKind::turn_tls` 服务器在 validate_peer_path_policy 与
transport valid_config 双层拒绝（`turn_tls_backend_not_verified`，
`rtc_config`/candidate_allowed/refresh_path_stats 的 TLS 分支同步收紧为
turn_tcp-only）；矩阵节点 `--turn-transport` 只收 udp|tcp，tls 在 flag
解析期显式拒绝（fail-fast 保持脚本诚实）。`DataPathKind::turn_tls` 与
对应 metrics/signaling 序列化面保留（wire 面 v1 内不可达）。

**NAT 矩阵新场景**：`turn_tcp`——nft forward 链 drop 双私网全部客户端 UDP
（STUN/TURN-UDP/srflx 全灭），双 coturn `listening-port` TCP 监听保留；
`--turn-transport tcp` + 无 STUN（死 STUN 只烧 P95 预算）+ `--srflx-only`，
唯一可达路径 = TURN/TCP relayed 候选；3 循环 P95<5000ms + m6 严格 +
**m7 文件推送严格**（strict-m7：M9-07 遗留 udp_blocked-with-TURN-
unreachable 的完整交付语义）。`run_pair` 的 STUN 参数按 turn_mode 分离
（stun-only/turn 才配 STUN）。coturn 模板 TLS 监听保持（生产基线，
浏览器类 peer 可用），turn_tls 场景未引入（无后端可测）。

**CI**：`coturn-topology` job 配置加 `-DHEYAKI_ICE_BACKEND=nice`、apt 步骤
加装 `libnice-dev`（步骤更名 Install coturn fallback package and libnice
dev）——该 job 的 NAT/故障/soak/bench 全面转 libnice 后端 = 立项要求的
ICE 行为回归全量重跑；其余 job 维持 libjuice。故障矩阵 `turn_restart`
注释更新为后端相关（libnice 实现 RFC 7675 consent freshness，TURN 死亡
可能显式关会话——两种结局都满足"有界存活"断言）。

**安装包**：nice 构建导出的 LibDataChannel target 携带
`$<LINK_ONLY:LibNice::LibNice>`（静态库 PRIVATE 依赖入 INTERFACE），上游
LibDataChannelConfig 不替消费者 find——heyaki 包安装 FindLibNice/FindGLIB
到 `lib/cmake/heyaki/modules/` 并在 heyakiConfig（nice 时）先 find_dependency
再 find LibDataChannel；`heyaki_installed_consumer` 在双后端各验证一遍。

**本机验证（无 sudo 环境）**：libnice 0.1.22 源码构建到用户前缀
（meson 1.12 + `-Dcrypto-library=openssl`——libnice 自身 crypto 仅影响其
遗留伪 SSL/DTLS 面，DTLS 由 libdatachannel 的 OpenSSL 承担；本机无
gnutls-dev）。nice 构建全目标 + ctest 67/67 绿（installed_consumer 需
PKG_CONFIG_PATH 指前缀，CI 系统包无此依赖）；juice debug 67/67 + werror
Release 零警告。IVA 独立验证 PASS（5 项：双后端定向套件、双后端全量、
CLI 契约三形态 + nice 附加对抗），附二进制级佐证（反汇编谓词
juice=false/nice=true；ldd 证 libnice 仅 nice 构建链接；两构建
build_config 宏对账）。TURN/TCP 真数据面（对真 coturn 的 TCP allocation
端到端）本机被 root/coturn 门控 SKIP，由 CI turn_tcp 场景承担。

**CI 首跑抓出分类层真缺陷（第二轮修复）**：turntcp 场景会话/传输全过
（UDP 全灭下 2-3s 建立、m6+m7 严格断言全绿）但标签断言红——
`data_path=turn_udp`。根因是 RFC 5766 协议语义：TURN 分配的服务器侧
中继腿永远是 UDP，TURN/TCP 中继候选在 SDP 里就是 `udp typ relay`，
候选层面无法区分客户端控制连接的传输。修复 = 分类改用配置事实：
`refresh_path_stats` 对 relayed 提名按 ICE 服务器 kind 推导（仅
turn_tcp 服务器 → `turn_tcp`，否则 `turn_udp`）；同类问题 `candidate_
allowed` 的非 UDP relayed 分支同样永远匹配不到 TURN/TCP 候选——改为
"任一 TURN 类允许即准入"并成文（类分离管采集配置，不管远端候选
准入；SDP 无从区分）。NAT 矩阵标签契约注释同步成文。CI 收敛另修：
libnice 是配置期依赖，apt 安装步骤必须前置于 Configure（首跑顺序
沿袭 coturn 运行期位次即红）；strict-m7 门误绑 m7_event（该字段在
矩阵节点场景结构上恒 0——事件服务未订阅），改绑 m7_file。

**soak 揭出 libnice 死端检测窗口（第三轮，上游缺陷确认）**：CI 第三轮
NAT/故障矩阵全绿后 soak Phase A 红——SIGKILL 对端后会话 45s 不关、
循环中断。根因（本机复现 + 源码判读）：libdatachannel v0.23.2 对
libnice 的 `consent-freshness` 用构造后 `g_object_set` 设置，而该属性
是 `G_PARAM_CONSTRUCT_ONLY`——GLib CRITICAL 拒绝（initiator 日志可见），
RFC 7675 consent 从未启用，死端检测退化为普通 keepalive
（`NICE_AGENT_TIMER_KEEPALIVE_TIMEOUT` 50s）。本机实测关闭窗口恒定
≈79-80s（6/6 循环 killed→respawned 间距）；libjuice 为 ~30s（consent）。
处置 = 接受有界窗口：matrix node 关闭等待 45s→120s、harness closed 门
60s→150s（覆盖 +50% 余量），双后端本机 soak 全绿（各 6 循环 + Phase
B/C）。**上游缺陷与重估点**：libdatachannel 应经 `nice_agent_new_full`
的 `NICE_AGENT_OPTION_CONSENT_FRESHNESS` flag 启用 consent（改 pinned
源不可行——CI 重取干净 checkout），下次 libdatachannel pin 升级时修复
并把窗口收回 ~30s；届时 M9-10 基准口径一并重测。v1.x 候选：会话层
应用级心跳使死端检测与 ICE 后端解耦。

**bench Phase T 揭出 libnice loopback 黑洞（第四轮，resolve 升级定因）**：
CI 第四轮 M4/NAT/故障/soak 四矩阵全绿后 bench Phase T 复现性红——
"initiator never authenticated"。本机复现 + strace 双侧抓包 + 多轮假设
排除未果后按升级规约交 resolve 专家，定因：**libnice 对 TURN 中继 socket
绑定物理接口地址并设 `IP_UNICAST_IF` 钉出接口**（`socket/udp-bsd.c`，
by-design 的多接口源地址正确性），发往 127.0.0.1 的数据报**内核静默丢弃**
（sendmsg 返回成功但永不投递；内核探针矩阵钉死：IP_UNICAST_IF+loopback
目的 = 黑洞，去掉即通）。libjuice test-turn-server 只绑 127.0.0.1 →
对 libnice 是物理不可达拓扑。**定性：测试基建拓扑问题，非产品/依赖缺陷**
——libjuice 客户端不设该选项故历绿；coturn 在 netns 非环回地址故 NAT
矩阵绿。修复 = bench Phase T 的 TURN server 改 `--bind 0.0.0.0 --external
<宿主物理 IP>`（harness 以默认路由源地址解析，无物理地址则显式 fail），
节点 `--turn` 指物理地址；test_turn_server.cpp 头注释记录约束（Windows
矩阵维持 loopback——libjuice 客户端不受影响，且 Windows 防火墙对物理
地址监听是额外变量）。连带：非环回 TURN 地址下 libjuice 客户端提名
local-host×peer-relayed 半中转对（`direct_host`）——force-turn 下对端
只发 relayed 候选，数据仍经对端 TURN server，与 Windows 矩阵
`turn_udp|direct_srflx` 半中转契约同类，Phase T 标签门对齐为
`turn_udp|direct_srflx|direct_host`。双后端本机 bench 全绿（nice
turn_p95=663ms、juice 1094ms，M9-11 重估输入就位）。**上游观察项**：
libnice `IP_UNICAST_IF`+loopback 的静默丢弃无任何日志/错误，可向
libnice 提低优先级 issue；M4 期"relayed<->relayed 提名停滞（pinned
stack）"边界与 libjuice 客户端行为相关，nice 后端下 relays 对的提名
行为待 CI 观察。

**坑（Round 16）**：①`tail` 管道吞构建退出码（已知家族再犯——后台构建
命令经 `| tail -5` 汇报 exit 0 实则失败，重跑勿用管道取退出码）；
②libnice meson 选项是 `-Dcrypto-library`（非 `crypto`）；③`Result<T>::
value_if()` 返回 `T*`——T 为 shared_ptr 时须 `(*p)->method`（初版测试
`p->method` 把 close 打在 shared_ptr 上）；④repo 根 9月14日遗留 in-source
cmake 污染（vendored/、根 Makefile、Config.cmake、tests/ 生成物——与 M9-12
libdatachannel 内污染同族），按恢复法清除；⑤libjuice 的
`heyaki-test-turn-server` 在 nice 构建下需手工补 add_subdirectory
（libdatachannel 不再自带，EXCLUDE_FROM_ALL 隔离）；⑥`pkill -f` 模式
出现在自身复合命令行时自杀整条 shell（两次踩中）——清理进程用
`for pid in $(pgrep -f …); do kill $pid; done` 且模式避开命令正文；
⑦strace 抓网络须 `-e trace=network`（glib 用 sendmsg/recvmsg，且
libjuice server 收包线程的 poll 不属 network 类——单看 sendto/recvfrom
会误判 server 死亡）；⑧"python 探针得到响应"≠"同样请求得到响应"——
裸 20 字节 Allocate 与 libnice 的 40 字节请求不同构，server 健康证明
被高估（resolve 专家纠偏）。

**CI 终态**：run 35178705793（提交链 569d596 主交付 → e823ac3 CI 步骤
顺序 → b530a62 relayed 标签分类 → b3c064e/124737c strict-m7 门（远端经
API 回退提交，443 断连家族）→ d34105a soak 窗口 → ae18e0f bench TURN
拓扑 → a37e01f m3b 计数器轮询 → 85f590f TUI driver 超时）**十一 job
全绿**（2026-09-17，coturn-topology 25m：libnice 后端下 M4 矩阵 + NAT
矩阵 turn_tcp + 故障矩阵 + soak + bench 全部通过；收敛期另历经 m3b/
TUI/m3a 抖动家族轮转与三处测试基建加固——m3b 计数器改 wait_until 轮询
（asan/tsan 双红同用例两轮后加固）、TUI enrollment driver 35s→60s
（慢 runner 下连续三次双 attempt 超时，本机 3/3 十秒绿对照）、
LogsInHeartbeats 用例同前）。

### Round 17（2026-09-17）：M9-16 安装/配置/部署/API/故障排查文档 + 示例同步测试

交付物：

- `docs/README.md`：文档索引（14 个领域 → 文件映射表）+ 示例同步纪律
  说明（三种围栏标签的语义与 CI 锚点）。README 的 Documentation 节前置
  该索引与六条用户文档链接。
- `docs/getting-started.md`：前置依赖表（工具链/OpenSSL/libnice 可选）、
  `fetch_third_party` + preset 构建流、配置选项表（ICE 后端/加固/
  sanitizer/fuzzer/auto-install）、`cmake --install` 前缀安装、已安装包
  CMake 消费片段（与 tests/consumer 同源，由 `heyaki_installed_consumer`
  验证）、首次 relay（openssl 自签 + 最小配置 + check-config/health）、
  TUI 首跑（platform state 目录路径、enrollment、视图索引）、七个
  demo/工具二进制表。
- `docs/configuration.md`：relay 配置文件格式语义（key=value 行式、64KiB
  帽、路径按 config 文件位置解析、证书加载期存在性检查）、全部 24 个
  文件键的默认值/约束/含义三列表、struct-only 旋钮（control_write_
  queue_*、endpoint TTL、四 scope 限速）成文、"拒绝式不 clamp"语义、
  CLI 覆写与 `--check-config`、稳定错误 detail 串清单、设备侧
  struct 配置模型（七个配置结构体 → 校验器映射表）+ 平台 profile 目录。
- `docs/deployment.md`：ASCII 拓扑图（控制面/数据面/coturn 分离）、
  relay 主机要求（证书+leaf pin、端口、持久 DB、Linux 为 CI 验证平台）、
  systemd 单元样例（--check-config 前置 + 加固指令）、bootstrap token
  创建面（RelayDatabase API + demo 指引 + runbook 轮换程序）、coturn 与
  observability 部署锚点、设备机队（初始化/enroll/配对/防火墙端口——
  组播组 239.192.72.89 / ff12::4845:5941:4b49、UDP 49189、hop limit 1）、
  升级/备份/回滚/轮换/吊销/磁盘满/过载 → runbook 程序锚点表、安装树
  布局。
- `docs/api.md`：六 target 表、executor 并发契约（无自建线程/回调在
  executor 上下文/全队列有界）、错误模型（Result/ErrorCode/component/
  safe_detail ≤64B）、profile store（default root、endpoint_for、权限、
  secret backend）、Node 生命周期（含本地初始化——create_password_
  verifier → initialize_local → NodeConfig → create/shutdown 完整可运行
  示例）、发现与会话（endpoints/connect/connect_lan/restart_session、
  data_path 标签语义、PairingRestricted→Authorized）、配对与信任
  （pair_peer、scope 交集、轮换、审计环、trust_scope_covers 文法示例）、
  五服务表（语义要点：peer_offline 即时失败、outcome_unknown、reliable_
  live、TransferId 续传、shell 默认关）、safe_logical_file_name 示例、
  指标、relay 注册、协议兼容（版本交集/拒绝未知字段/N-1/前向 schema）。
- `docs/troubleshooting.md`：诊断采集法（TUI --status/metrics/QUEUES、
  relay /metrics 与 JSON 日志、join 键、三组 state gauge 语义）、六域
  症状表（发现/配对信任/会话路径/relay 设备侧/文件 shell/relay 运维，
  每行症状→原因→查什么）、平台注记（WFP loopback 豁免、turns: 全后端
  拒绝、跨 OS runner 阻断）。
- 示例同步测试（`tests/docs/`）：`extract_doc_examples.cmake`（configure
  期执行；string(FIND) 配对扫描 ``` 标记——**不能 split 成 CMake list，
  C++ 示例内容本身的 `;` 即列表分隔符**；info string 正则匹配
  `heyaki-cpp <slug>`/`heyaki-relay-config <slug>`；重复 slug/空块/
  未配对围栏/整表零提取一律 FATAL）+ `run_doc_examples.cmake`（CTest
  driver：逐示例建 0700 工作目录——**ProfileStore 拒绝 group/other 位
  目录链**——运行每个编译出的示例，再逐 config 跑 checker）+
  `relay_config_doc_check.cpp`（把提取的 config 连同相对路径引用的空
  stub 文件部署进 scratch 目录，先断言缺证书负路径（certificate_
  missing/private_key_missing），再断言 load 成功）。
- `tests/CMakeLists.txt` 注册：五篇文档为 CMAKE_CONFIGURE_DEPENDS；
  每个 cpp 块编译为独立 `heyaki-doc-example-<slug>` 可执行（链 heyaki::
  client + executor；node-lifecycle 加 executor 异常适配源）；CTest
  `heyaki_m9_docs_examples`（labels unit;docs;m9，TIMEOUT 300）经 cmake
  -P driver 运行全部示例（多配置生成器二进制定位用 `$<TARGET_FILE:>`
  逐个经 add_test 参数传递）。

设计说明：

- 文档示例的三种同步形态：(1) `heyaki-cpp` 块 = 提取即编译即运行（示例
  既是文档也是测试源码，漂移即红）；(2) `heyaki-relay-config` 块 = 经真
  配置解析器/校验器加载（含负路径）；(3) CMake 消费片段 = 与
  tests/consumer 同内容，由 `heyaki_installed_consumer` CI 验证。文档
  索引明示该纪律，后续贡献者改示例必须留在围栏标签内。
- relay 配置键表以 `load_relay_config_file` 解析器 + `validate_relay_
  server_config`（M9-11 上限）为源核对；struct-only 旋钮单列成文防
  "文件键存在"的误读。
- 全部七个示例均可运行断言（无网络依赖：profile/node 生命周期用临时
  目录，纯函数示例直接断言语义——包括"故意配错必须被拒"的负示例）。

坑（Round 17）：

1. CMake `string(FIND)` 无起始位置参数（与 findstring 不同）——区间扫描
   必须切 remainder 子串再 FIND 后回加偏移。
2. CMake `string(SUBSTRING)` 的长度参数不做算术——`"${a}-${b}"` 形态
   直接报错，须先 `math(EXPR ...)`。
3. C++/配置示例内容含 `;`，任何"split 成 CMake list"的提取模型都会被
   内容击穿（首个版本 8 围栏 split 出 66 段）——标记配对扫描是唯一稳
   姿势。
4. add_test COMMAND 里经变量传递的 `$<TARGET_FILE:...>` 不会二次展开
   （genexp 求值先于变量展开）——动态目标列表必须把 genexp 字面拼进
   add_test 参数。checker 的单目标直接字面书写即过。
5. Node::create 拒绝未本地初始化的 profile（not_registered/local_
   profile_not_initialized）——文档示例必须演示完整初始化流（verifier
   → initialize_local），这恰好是 API 文档应讲的核心概念。
6. 指定初始化器跳过聚合成员在 CI -Werror（missing-field-initializers）
   下致命（Round 12 同族）——文档示例一律"默认构造 + 成员赋值"姿势。
7. `Node::metrics()` 在首个 prune tick 前返回默认构造快照（device_id
   全零）——文档示例演示 snapshot()（实时）与 metrics()（周期聚合）的
   差异。

本机验证：debug 与 werror（Release+Werror+全加固 flags）双构建零警告；
`heyaki_m9_docs_examples` 两构建全绿（5 cpp + 2 relay-config 全部通过，
含 node-lifecycle 真实建节点 + shutdown）；全量 werror ctest 除 m3a/m3b
并行抖动（单跑绿，既有家族）与旧构建目录缺产物（补建后绿）外全绿。

### Round 18（2026-09-17）：M9-17 打包与干净机安装/卸载验证

交付物：

- 版本定版：`project(heyaki VERSION 0.0.0 → 1.0.0)`——`HEYAKI_VERSION_STRING`
  经 build_config 直出 `--version`/SBOM namespace/heyakiConfigVersion
  （SameMajorVersion），打包产物名 heyaki-1.0.0-linux-<arch>。无任何
  "0.0.0" 断言测试（grep 核对）。
- 安装树补齐（`CMakeLists.txt`）：
  - coturn 示例配置四件套（turnserver.conf、docker-compose.yml、
    heyaki-turn.env.example、README）→ `${CMAKE_INSTALL_DATADIR}/heyaki/
    coturn/`——打包件自带部署基线，不用回仓库找。
  - licenses.lock 全部许可文本：configure 期解析锁文件，逐条
    `install(FILES … RENAME <name>-<basename>)` → `share/heyaki/licenses/`
    （40 个：boost 26 族归并到 BSL 文本仍按 name 各装一份、libsodium/
    blake3/sqlite/executor/FTXUI/libdatachannel/protobuf/abseil/
    googletest…）；许可文件缺失即 FATAL（与 GenerateSupplyChain 的
    存在性检查同语义，二道闸）。THIRD_PARTY_LICENSES.md 表格中的路径
    由"仓库相对路径"升级为"随包可寻"。
  - nice 构建（M9-19 遗留项闭环）：`deploy/licenses/lgpl-2.1.txt`
    （GNU 官方文本，与 Debian common-licenses 逐字节一致）+
    `deploy/licenses/NOTICE-libnice.md`（动态链接=重链接义务满足、
    源码指路 libnice/GLib upstream、版本地板引 dependency-policy）→
    `share/heyaki/licenses/`；juice 构建不装（NOTICE 内明示适用范围）。
- `cmake/cmake_uninstall.cmake` + `uninstall` target：manifest 驱动卸载
  （install_manifest.txt 逐文件删除，目录仅在空时自底向上移除）；
  **-P 脚本模式没有构建目录上下文——manifest 路径必须显式传参**
  （`-DHEYAKI_INSTALL_MANIFEST=<build>/install_manifest.txt`），经典
  模板里 `${CMAKE_CURRENT_BINARY_DIR}` 的假设不成立。卸载语义 =
  "前缀零常规文件"，目录树残留不属于非包管理器安装的违约。
- `scripts/package_release.sh`（Linux；bash，set -Eeuo pipefail）：
  1. 取构建树（`--build-dir` 复用；缺省时全新 RelWithDebInfo
     out-of-source 配置构建——发布件携带调试信息的默认路径）；
  2. `cmake --install` 进全新 stage 前缀（"干净机器"形态）并复制
     install_manifest.txt（防后续 build 的 heyaki-deploy ALL 安装
     覆写指向）；
  3. M9-17 清单断言：8 个安装二进制、5 个代表性公共头、
     lib/cmake/heyaki 三件、proto、coturn 四件套、SBOM +
     THIRD_PARTY_LICENSES.md + ≥30 个许可文本；
  4. 符号拆分：readelf -S 探测 .debug_info → objcopy
     --only-keep-debug 到 dbg 镜像树 + --strip-debug 原件；
     **零符号构建（plain Release）退出 77**（CTest skip 语义），
     有符号但 <5 个 = 不一致即 FATAL；
  5. strip 后 relay/TUI `--version` 复跑；
  6. 主 tar.gz（干净前缀全量）+ `-dbg.tar.gz` + SHA256SUMS；
     解包后 --version + coturn 配置存在性冒烟；
  7. 卸载仿真：cmake -P cmake_uninstall（日志落盘、失败才 tail），
     断言 stage 零常规文件。
- `heyaki_m9_package` CTest（tests/CMakeLists.txt）：Linux + 非
  sanitizer + objcopy/readelf/tar/bash 齐备才注册（Windows 不注册——
  Windows 安装验证由既有 heyaki_installed_consumer 矩阵承担，tarball
  打包为 Linux-only 发布形态）；SKIP_RETURN_CODE 77；TIMEOUT 900。
- CI（.github/workflows/ci.yml supply-chain job）：Release 配置加
  `-DCMAKE_CXX_FLAGS=-g -DCMAKE_C_FLAGS=-g`（distro 式 release+调试
  信息；FORTIFY/RELRO 等加固不受影响，hardening check 仍过），该 job
  的全量 ctest 于是真跑打包流；其余 Linux job（无 -g）经 77 跳过。
- `docs/deployment.md` 打包产物节更新为终态布局（coturn/、licenses/、
  supply-chain/ 三目录）+ 发布流描述（脚本与签名是两个程序：脚本管
  清单/符号/卸载，签名按 release-signing.md 由操作者执行）。

坑（Round 18）：

1. `file(REMOVE_DIRECTORY)` 不是 file() 子命令——空目录删除用
   `REMOVE_RECURSE`（仅在 GLOB 判空之后执行）。
2. 管道吞退出码再犯（自查时 `script | tail; echo $?` 显示 0 掩盖
   失败）——验证脚本必须直接取 `$?` 或显式落盘日志。
3. `install(FILES)` 的 RENAME 只对单文件生效——成对重命名必须逐条
   循环，不能把 (src, name) 对拼进一个列表。
4. add_test 里经 CMake wrapper -P 脚本无法传播 77（message 无退出码
   通道）——skip 语义要么测试命令直调脚本 + SKIP_RETURN_CODE，要么
   别包 wrapper。

本机验证：debug 全流程 PACKAGE_OK heyaki-1.0.0-linux-x86_64（11 个
调试文件、双 tar + SHA256SUMS、解包冒烟、卸载零残留）；plain Release
重配置后 Skipped（77 路径）；nice 构建安装 42 个许可文件（40+LGPL+
NOTICE）、juice 40 个且无 LGPL；版本升级后 installed_consumer /
supply_chain_inventory / m9_release_signing / m9_docs_examples 四测
全绿；debug 全量构建零错误。

### Round 19（2026-09-17）：M9-18 v1 release checklist + M9-01 指标语义评审收尾 + 最终验收对账

交付物：

- `docs/operations/release-checklist-v1.md`（M9-18，内容见勾选项）。
- M9-01 语义评审（收尾）：
  - 全量审计两导出器 397 族（node 298 + relay 99，渲染面实测）：前缀、counter `_total`、
    gauge 反 `_total`、HELP/TYPE 配对、单位命名、标签基数。
  - **两处真修复**：`heyaki_node_relay_enrollment_generation`/
    `lease_generation` 由 counter() 改 gauge()（HELP 原文自述
    "(gauge semantics)"，TYPE 行与语义矛盾——消费端会误用 rate()）；
    `heyaki_event_lag_total_sequences` → `heyaki_event_lag_sequences_total`
    （counter 命名一致性）。dashboard/规则/golden 零引用，改名无破坏。
  - 约定成文：deploy/observability/README.md 新节 "Metric semantics
    conventions"——命名空间、counter/gauge 规则与直方图三元组例外、
    毫秒单位决策（ingest 侧换算）、标签基数（relay 单 instance 标签、
    设备侧无 per-peer 标签）、零值全渲染（absent() 语义）。
  - 机械化强制：`heyaki_m9_slo_rules` 新测试
    `MetricFamiliesFollowNamingConventions`（渲染两导出器，断言
    heyaki_ 前缀 / counter⇒_total（直方图三元组白名单）/ gauge⇒非
    _total / HELP 先于 TYPE / 新毫秒族必须进冻结允许表）——新例外
    必须同提交扩表并改文档。
  - Known limitations 陈旧指针更新（丢包面"revisit after M9-10" →
    冻结表 §9.3 的 pin 升级重估）。
- 最终验收对账：11 项全部勾选，逐项证据指针（基准/NAT 实测数字、
  覆盖套件名、阻断结论文档位置）。
- `docs/README.md` 索引补 release-checklist 行。

本机验证：heyaki_m9_slo_rules（含新约定测试）与 heyaki_m9_metrics
全绿（后者证明改名/改型未破 golden）；全量 debug ctest 69/69 绿（9 个
环境门控跳过与基线一致）。IVA 独立验证 PASS（含独立渲染探针核对两处
修复的 TYPE 行与旧名零残留、checklist 全链接/锚点/事实抽查（协议版本、
coturn digest、35+5 pin、40 许可、11 job 计数）、todolist 零未勾条目；
两处记录笔误——状态词与族数 376→397——已按报告修正）。

**M9 收官 CI 终态**：Round 17（M9-16 文档）run 35242112880、Round 18
（M9-17 打包，supply-chain job 首跑 `heyaki_m9_package` 真实打包流）run
35244546917、Round 19（本轮）run 35246768481——三个 run 各自十一 job
全绿零 rerun（2026-09-17）。v1.0.0 发布按
[release-checklist-v1.md](../operations/release-checklist-v1.md) 执行，
tag 与发布是产品所有者动作。

### 剩余范围（M9-01 完成前）

- ~~注册成功率/租约续期失败计数器、信令 fallback/winner 聚合、TUI 队列/渲染
  导出~~：Round 2 已交付（见上）。
- ~~丢包估计（packetsLost 缺口）取舍~~：Round 11 已决策——维持 bytes/rtt
  现状替代面，随 M9-19 后端切换统一重估（参数冻结表 §9.3）。
- ~~Prometheus 指标族语义评审（命名/标签/类型过一遍 scrape 消费视角）~~：
  Round 19 已交付（见上）。
- ~~M9-03 correlation ID 与 instance 标签打通~~：Round 4 已交付（见上）。
- ~~M9-02 relay 侧导出~~：Round 3 已交付（见上）。M9-04/05 dashboard 与
  runbook 以 Round 1/2/3 指标族与日志事件为输入。
