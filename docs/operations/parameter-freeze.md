# 参数冻结表（M9-11）

状态：**v1 冻结**（2026-09-13）。本文档是 [M9 计划](../todolists/m9-production-hardening.md)
`M9-11` 的核心交付物：每一条默认值都有测量依据，每一条容量/水位/超时/重试参数都有
硬上限。冻结语义：

- **默认值**是 v1 发布随二进制走的行为；改动默认值必须在同一提交里更新本文档与
  `tests/unit/m9_parameter_freeze_test.cpp`（该测试钉死下表全部默认值与上限，漂移即红）。
- **硬上限**在配置校验层强制（超限直接 `configuration` 拒绝，不做静默 clamp——与
  仓库"拒绝式校验"惯例一致）。上限普遍取默认值的 16–256 倍，覆盖合法扩容空间，
  同时保证失控配置无法放大内存或拖死生命周期。
- **测量依据**标注每条默认值的来源：M9-10 基准、M9-09 长稳、M9-06/07 网络矩阵、
  M9-08 故障注入的实测数据，或代码内已验证的设计不变式。

## 测量依据来源

| 来源 | 运行 | 与本表相关的结论 |
|---|---|---|
| M9-10 基准 harness（runbook "Run a performance benchmark"） | CI run 34755338925（Release）；本机 debug/loopback | 登录 P95 22ms、直连 P95 1021ms、TURN P95 1077ms、消息 RTT P95 2.7ms、顺序 RPC P95 2.3ms、并发 RPC（16 窗口）P95 8.5ms、单文件 8MiB/s、双并发 9MiB/s、shell 敲键 p50≈300ms、fan-out 3 订阅者 10/10 |
| M9-09 soak harness（会话/设备 churn + 容量过载） | CI run 34698025758（Release） | initiator RSS 21.4→22.5MiB、fds 18→15、replay_peak 12（6 循环）；relay 五 gauge 族有界；tight relay（3 连接/2 目录）拒绝计数器点燃且幸存者可用 |
| M9-06 NAT 矩阵 | CI run 34390321528 | cone 类打洞直连 P95≤2059ms；symmetric/CGNAT TURN 中转 P95≤1356ms——全部低于 5s 门限 |
| M9-08 故障注入 | CI run 34686617215 | slow_receiver：2MiB 过 4mbit/50ms 整形链路（有效 ~1mbit）有界完成；TURN 死亡后会话存活由 ICE consent（RFC 7675，30s）界定 |
| 设计不变式（单测钉死） | m3b_relay_ttl/endpoint、m4_signaling M4ReplayCache 等 | 租约/目录 TTL、replay cache 容量与 TTL、限速四 scope、连接容量拒绝均为行为验收对象而非拍脑袋数值 |

### v1 验收数值对账（M9-10 实测 vs 验收门）

| 指标 | 验收门 | M9-10 实测（loopback，本机 debug） | 余量 |
|---|---|---|---|
| 登录 P95 | < 2s | 22ms | ~90× |
| 直连 P95 | < 3s | 1021ms | ~3×（含发现/信令全链路） |
| TURN fallback P95 | < 5s | 1077ms | ~4.6× |
| 消息 RTT / RPC / 并发 RPC P95 | 无绝对门（≤500ms 保守界） | 2.7 / 2.3 / 8.5ms | — |
| 文件吞吐 | 无门（提交+BLAKE3 正确性） | 8–9 MiB/s（受 60KiB SCTP 消息经验上限钳制，见下） | — |

结论：现有默认值在验收门下余量充分，本轮**不调整任何默认值**，只补齐上限校验并
冻结。跨提交趋势基线由 bench harness 的 `BENCH_METRIC` 行承担（P95 恶化超门限会被
harness 拒绝，见 runbook 基准程序）。

## 1. Runtime / executor（`RuntimeConfig`）

校验：`validate_config`（`include/heyaki/runtime.hpp` 声明，`src/client/runtime.cpp`）。
默认值依据：M9-09 soak 中 executor 任务 gauge 有界、M9-10 基准 Phase L 无队列拒绝。

| 参数 | 默认 | 硬上限 | 依据 |
|---|---|---|---|
| callback_capacity | 1024 | 65536 | soak/基准无 callbacks_rejected；上限 64× |
| shutdown_hook_capacity | 64 | 65536 | 关闭钩子数量级固定 |
| executor_queue_capacity | 1024 | 65536 | 有界准入（ledger S2）；上限 64× |
| executor_min/max_threads | 2 / 4 | 64 / 256 | 设备节点非 CPU 服务，256 线程已远超任何部署面 |
| 11 个生命周期 timeout（worker_start … shell_worker_stop） | 1000–5000ms | 600000ms（10min） | 关闭分阶段预算（design/concurrency-and-shutdown.md）；默认最深层 5s，10min 上限覆盖嵌入式慢盘 |

## 2. Relay 客户端（`RelayNodeConfig` / `RelayWssClientConfig`）

校验：`validate_relay_node_config`（`include/heyaki/node.hpp`）、
`RelayWssClient::create`（`src/client/relay_wss_client.cpp`）。
默认值依据：M9-10 Phase R/T（connect 5s、handshake 5s 在 P95 1s 量级实测下充分）；
租约 45s/心跳 15s/丢 3 次在 fault matrix lease_expiry 与 M9-09 churn 中行为正确。

| 参数 | 默认 | 硬上限 | 依据 |
|---|---|---|---|
| connect/handshake/close_timeout | 5000/5000/2000ms | 60000ms 各 | 与 relay 服务端 handshake_timeout 上限同口径 |
| heartbeat_interval | 15000ms | 120000ms | ≤租约绝对上限（120s）：心跳节奏必须能在租约内续期 |
| lease_duration | 45000ms | 120000ms | 既有校验保留 |
| missed_heartbeat_limit | 3 | 64 | 既有校验保留 |
| minimum/maximum_backoff | 1000/60000ms | 600000/3600000ms | 指数退避 + jitter（base/4）；1h 上限防重连风暴下无限沉默 |
| receive/send_capacity | 64/64 | 65536 各 | M9-02 信令背压告警以该队列水位为对象；64× 余量 |

## 3. 会话与信令（`ChannelBudgetConfig` / `ByteStreamLimits` / `SignalingCoordinatorConfig`）

校验：`src/client/session_channels.cpp`、`src/client/byte_stream.cpp`、
`SignalingCoordinator::create`（`src/client/signaling_coordinator.cpp`）。
默认值依据：M9-10 文件/流/事件套件与 M9-09 soak 的队列 depth@peak 全部远低于默认
水位；M4 信令矩阵在 attempt_ttl=15s 下收敛。

| 参数 | 默认 | 硬上限 | 依据 |
|---|---|---|---|
| per_peer_queued_frames / bytes | 1024 / 8MiB | 65536 / 256MiB | 会话内存最大放大器，128× 封顶 |
| max_channel_queued_frames / bytes | 1024 / 8MiB | 65536 / 256MiB | 同上 |
| default_receive_window_frames | 64 | 65536 | 流控窗口；帧数上限防失控 |
| max_concurrent_streams | 16 | 1024 | ByteStream 并发 |
| pending_write_bytes / max_pending_reads / writes | 512KiB / 16 / 16 | 64MiB / 4096 / 4096 | 慢消费者背压面（m5 队列族验收对象） |
| max_pending/inbound_attempts | 64 / 64 | 65536 各 | 信令 attempt 表 |
| attempt_ttl | 15000ms | 600000ms | ≤ signed validity 上限口径内；M4 attempt_expired 语义 |
| max_candidates_per_attempt | 128 | 4096 | 候选洪泛防线（M9-15 安全回归的输入） |
| inbound_rate_limit / window / rate_key_capacity | 32 / 1000ms / 256 | 100000 / 60000ms / 1048576 | 与 relay 四 scope 同形 |

## 4. 服务层（message / rpc / event / file / shell）

校验：各服务 `attach()`（`src/client/*_service.cpp`）。
默认值依据：M9-10 套件逐项实测（消息/RPC/事件/文件/shell 全段零队列拒绝）、
M9-09 soak 会话 churn 下 pending/overflow 计数有界。

| 参数 | 默认 | 硬上限 | 依据 |
|---|---|---|---|
| message.dedup / pending_ack / frame / byte | 512 / 256 / 256 / 1MiB | 65536 / 65536 / 65536 / 256MiB | dedup 表是常驻内存面 |
| event.subscriber_queue_items / max_subscriptions_per_peer / frame / byte | 256 / 64 / 256 / 2MiB | 65536 / 4096 / 65536 / 256MiB | fan-out 内存 = 订阅数 × 队列，双向封顶 |
| rpc.max_concurrent_server_calls | 16 | 4096 | M9-10 并发 RPC 以 16 窗口打满（P95 8.5ms）；准入拒绝是语义非缺陷 |
| rpc.result_cache_entries / bytes | 64 / 256KiB | 65536 / 256MiB | **entries=0 = 禁用重放缓存（契约行为，允许）** |
| rpc.max_pending_client_calls | 64 | 65536 | 与并发窗口 16 配比 |
| file.max_concurrent_sends / send_window_bytes | 2 / 2MiB | 256 / 256MiB | 发送窗口是主要在途字节预算；M9-10 双并发文件实测 9MiB/s |
| shell.frame / byte / output_window / retained_terminal | 128 / 512KiB / 256KiB / 64 | 65536 / 64MiB / 64MiB / 4096 | M8 输出洪泛终止语义的上游水位 |

## 5. LAN（`LanConfiguration`）与安全面

已有完整上下限校验（`validate_lan_configuration`、`validate_security_policy`、
`validate_pairing_policy`），本轮**不新增上限**。默认值与依据：

- 通告 5000ms ±500ms jitter、presence 租约 15000ms：m3a 网络 harness 多场景实测
  （multicast 发现/接口切换），通告/租约比 1:3 吸收单次丢失。
- replay_capacity 8192 / diagnostic_capacity 1024：M9-09 soak replay_peak 12，
  千倍余量；诊断史环 1024 是 finished_peer_sessions 排空断言的封顶口径。
- handshake 5000ms / hello 3000ms / presence_lease 上限 120s：既有校验保留。
- 密码/Argon2 参数：安全策略（`PasswordSecurityPolicy`）为**安全冻结**——
  argon2 目标 250–750ms 窗口、operations ≤6、memory ≤512MiB，调整须走安全评审，
  不在本表权限内。

## 6. Shell profile 与文件根（`ShellProfileConfig` / `FileRootConfig`）

校验：`validate_shell_profile`（`src/core/shell_protocol.cpp`）。

| 参数 | 默认 | 硬上限 | 依据 |
|---|---|---|---|
| idle_timeout | 600000ms（10min） | 86400000ms（24h） | 会话空闲回收；M8 交互语义 |
| absolute_timeout | 3600000ms（1h） | 604800000ms（7d） | 生命周期兜底 |
| max_output_bytes | 64MiB | 1GiB | 总输出预算；洪泛终止的上游 |
| max_input_pending_bytes | 64KiB | 1MiB（Windows 仍 128KiB 管道帽） | POSIX 侧新增上限；Windows 由 kShellWindowsInputPendingCap 继续强制 |
| terminate_grace | 5000ms | 60000ms | 既有校验保留 |

`FileRootConfig`（max_file_bytes 1GiB / max_total_bytes 8GiB / concurrent_receives 2）
**不在配置层设上限**：配额语义是磁盘占用策略（流式落盘，不放大内存），磁盘满路径
由 M9-08 磁盘满注入与 runbook"磁盘满"程序承担；传输层字节数由 `Limits.max_file_bytes`
（16GiB，协议面）兜底。

## 7. Relay 服务端（`RelayServerConfig`）

校验：`validate_relay_server_config`（`src/relay/relay_config.cpp`）。本轮新增：
`control_write_queue_frames` 上限 65536（原仅非零）、lease 两个子容量上限 65536
（原仅非零）、限流四 scope 策略前移到 config 校验（原来滞后到 `RelayServer::create`）。
默认值依据：M9-09 Phase B/C（设备 churn 与 tight relay 过载的 gauge/拒绝计数全部
按默认容量校准）、M9-02 采样与背压告警。

| 参数 | 默认 | 硬上限 | 依据 |
|---|---|---|---|
| max_connections | 1024 | 65536 | 既有 |
| handshake/shutdown_timeout | 5000 / 2000ms | 60000ms | 既有 |
| control_write_queue_frames / bytes | 64 / 1MiB | **65536（新）** / 64MiB | 每会话控制面水位；endpoint_offline 背压语义 |
| lease.capacity / per_device / per_tenant | 4096 / 64 / 4096 | 65536 / **65536（新）** / **65536（新）** | 子容量与全局租约帽同阶 |
| lease.default / maximum | 45000 / 120000ms | 120000ms | 既有（= 设备侧 heartbeat 上限口径） |
| endpoint_directory.capacity / maximum_ttl | 4096 / 300000ms | 65536 / 300000ms | 目录 TTL ≤ maximum_signed_validity（签名面不变式） |
| endpoint_query_max_results | 256 | 4096 | 既有 |
| signaling_rate_per_second | 32 | 1024 | 既有 |
| rate_limits 四 scope + entry_ttl | connection 16/s、request 256/s、tenant 64/s、ip 32/s、entry_ttl 60s | policy 校验前移至 config 层（capacity/max_keys ≤ 1e6、window ≤ 1h） | loopback 基准证明 per-IP 32/s 在单 IP 多身份下会触发（Round 10 坑 5：300ms 拨号间隔规避）；生产每设备独立 IP 不受影响——**NAT 共享出口 IP 的部署需上调 ip scope（cap 1024）**，已记 runbook 观察项 |

其余（sweep 周期 1s、信令滑窗 1s、HTTP header_limit 8KiB、TLS 1.3、challenge
capacity 256 / validity 60s）为**协议/安全冻结常量**：无配置面，调整等于协议变更。

## 8. 硬编码设计常量冻结

无配置面的行为常量，本轮逐一核可并冻结（改动须重新过对应矩阵）：

| 常量 | 值 | 位置 | 依据 |
|---|---|---|---|
| 节点维护 tick | 500ms | src/client/node.cpp expiry tick | M8-04 设计：TTL/deadline/diagnostics/shell drain 单拍驱动；shell 输出延迟见决策 2 |
| PTY worker 轮询 tick | ≤50ms | src/client/shell_pty.cpp | spawn verdict 5s 兜底、升级梯判定粒度 |
| 背压恢复水位 | send_queue_bytes/2 | webrtc_transport_session.cpp | 滞后带防振荡 |
| SCTP 单消息经验上限 | 60KiB | src/client/file_service.cpp kEmpiricalSctpMessageCap | M7 实测 65536B 帧丢失；文件吞吐的物理钳制点（升级传输栈时重估） |
| per-domain 通道容量 | bulk 1MiB / shell 128KiB / standard 256KiB | src/client/peer_session.cpp | 交互/ bulk 分级；M9-10 shell 竞争段验证 |
| 业务违规终判 | 2 次 | src/client/peer_session.cpp | 协议完整性防线 |
| relay 重连 jitter | base/4 随机 | src/client/node.cpp | 重连惊群抑制 |
| TURN consent | RFC 7675 30s | pinned libjuice | M9-08 turn_restart 证伪"consent 杀会话"后的真实保证口径 |
| 会话丢失/重启预算族 | 15s（file-pull RPC deadline / session_restart_deadline / attempt_ttl） | 三处独立 | 语义不同、数值巧合；全部由矩阵验证，不强行统一 |

## 9. 移交决策处置（Round 8/10 → M9-11）

### 9.1 孤儿 staging 清理 —— 已实现

进程死亡中途的传输会残留 `.heyaki-<32hex>.part/.state` staging 文件（M9-08 崩溃
矩阵的已知缺口，原靠 root 磁盘配额兜底）。本轮实现：

- `file_store::sweep_stale_staging(root, max_age)`（`src/client/file_store.cpp`）：
  扫描接收根目录，删除最后写入早于 **24h 年龄门**的 staging 残留。匹配严格按
  `.heyaki-` + 32 个十六进制字符 + `.part/.state` 后缀——用户文件（如
  `notes.heyaki-report.part`）永不触碰；目录（含指向目录的 symlink）永不删除；
  每条目失败静默跳过，扫描失败有命名错误。
- 接入点：`FileService::attach()` 对每个接收根向 executor 阻塞 I/O worker 投递一次
  fire-and-forget 清理（不在 strand 扫描、不阻塞会话建立、失败不通知——清理是
  自愈优化而非会话前置条件）。
- **年龄门 = 24h 的测量依据**：M9-08 整形链路（4mbit/50ms，有效 ~1mbit）实测最慢
  传输在数十秒量级；24h 是最慢观测的三个数量级之外。活跃传输的 staging 只有多
  秒龄，永不落入清理窗。
- 验收：`M9ParameterFreeze.StagingSweep*`（陈旧清理/新鲜保留/用户名保留/目录保留/
  缺根失败）+ `M9ParameterFreeze.FileServiceAttachPostsStagingSweep`（attach 投递
  契约）；M9-08 崩溃矩阵的"残留 staging 不阻塞不毒化"语义不受影响（probe 残留
  均为秒龄）。

### 9.2 Shell 交互延迟 —— 冻结 500ms tick，事件驱动 drain 记为 v1.x 候选

M9-10 实测 shell 敲键→回显 p50≈300ms（PTY 输出经 500ms 维护 tick 上排空，M8-04
设计行为）。**本轮决策：保留 500ms tick。**理由：

1. 延迟有界且已实测（p50 300ms < tick 500ms），v1 验收清单对 shell 无更低延迟门；
2. 事件驱动 drain（worker 通知 strand 即排）需改动 M8-04 的 strand 单拍模型，属
   产品级变更，必须带基准回归独立成轮，不属参数冻结轮；
3. 真实部署中 WAN RTT（50ms+）叠加后，tick 贡献小于总延迟的一半；局域网/快速链路
   下 300ms 对终端交互可感但可接受。
4. tick 同时驱动消息 TTL、RPC deadline、五服务 prune——单独为 shell 缩短会改变
   全部服务的唤醒/误差模型。

若 v1 用户反馈不可接受：方案为"输出即排"（ShellService sink 出口直接 flush）+
tick 保留为兜底，预期 p50 降至 <100ms（PTY worker 50ms tick 成为下界）；该改动
随 bench shell 段（p50/p95 采样）可量化验收。

### 9.3 丢包估计（packetsLost）—— 维持现状，随 M9-19 重估

pinned libdatachannel v0.23.2 的 stats API 仅暴露 bytes/rtt（M9-01 已知限制）。
应用层从不可靠通道序列缺口推导丢包率的复杂度与误报风险不划算，且 M9-19（TURN/
TCP/TLS）计划切换 libnice 后端，届时 getStats 面会变化。**决策：维持 bytes/rtt
作为现状替代面，丢包估计推迟到 M9-19 后端切换后统一重估。**

### 9.4 relay per-IP 限速 —— 默认保留 + 部署观察项

M9-10 基准证明 per-IP 32/s scope 在"单 IP 多身份"（loopback、NAT 共享出口）下
会被信令突发触发并引发客户端重连。生产部署每设备独立 IP 不受影响；共享出口
IP 的机队应上调 ip scope（上限 1024/s）。"客户端被拒后重连"行为已记 runbook
观察项；重连本身由 1000ms 起步的指数退避 + base/4 jitter 抑制惊群（第 2 节上限
保证最坏 1h）。

## 10. 已知导出缺口（非本轮范围，留档）

- relay 控制面无字节计数器（`RelayServerSnapshot` 不含 WSS 字节）：带宽以
  `signaling_forwarded_total` 代行（M9-10 已记录）。
- packetsLost/jitter：见 9.3。
- `PairingServiceConfig.failure_table_capacity` 在 Node 装配处硬编码 256U（Node 未
  暴露该键）：实际是冻结值而非可调参数，在此声明。
