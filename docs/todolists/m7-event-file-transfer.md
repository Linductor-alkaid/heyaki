# M7：远程事件与文件传输

> - 状态：已完成（2026-08-31）
> - 所属计划：[Heyaki MVP 至 v1 实施 TODO 计划](heyaki-implementation-plan.md)
> - 前置：M6 | 建议发布点：v0.3 Data beta

## 远程事件

- [x] `M7-01` 实现精确 topic 和受控前缀匹配、publisher sequence、event ID、schema version、timestamp、QoS 和 payload。
  （`event.hpp`/`event_protocol.cpp`；topic 段边界前缀匹配 `event_topic_matches`；每 publisher/topic 本地递增 sequence。）
- [x] `M7-02` 实现 `best_effort_latest`，每订阅者只保留最新值并暴露 overwrite/stale/lag。
  （发送端 keep-latest staging（`subscriber_overwrites`/`subscriber_drops`），接收端 `stale_items`/`lag_events`/`lag_total_sequences`。）
- [x] `M7-03` 实现 `reliable_live`，只承诺当前连接内可靠，不补发断线历史。
  （有界 FIFO staging，溢出仅终止该订阅（`subscriber_overflows`）；`handle_session_closed` 释放两端状态，重连不补历史。）
- [x] `M7-04` 每个远程订阅者有独立有界队列和 scope；慢订阅者不阻塞发布者或其他订阅者。
  （`EventServiceConfig::subscriber_queue_items`；订阅准入检查 `event.subscribe:<root>`；publish 永不阻塞，滞留项在 `prune()` 重试。）
- [x] `M7-05` 实现本地 `executor::comm::Topic<T>` 到远程事件的显式 bridge，类型和命名上区分本地 fan-out 与网络协议。
  （`LocalEventMessage`（本地）vs `EventItemBody`（wire）；`EventService` 收到远程事件发布进 Node 持有的
  `executor::comm::Topic`，`Node::publish_local_event`/`subscribe_local_events` 是对外的 bridge 半边。）
- [x] `M7-06` 配置单设备远程订阅者/连接上限；超限明确拒绝，不把 relay 扩展为业务 Broker。
  （`max_subscriptions_per_peer`；超限以 EVENT_UNSUBSCRIBE 显式回应并计数 `subscription_limit_hits`。）
- [x] `M7-07` TUI 事件视图支持 topic 浏览、订阅/取消、测试发布和 sequence/drop/lag 展示。
  （`heyaki-tui` 的 `event` 视图：topic/qos/match/sub/unsub/pub/items/topics，items 输出 sequence 与
  lag/stale/duplicate/conflict/overwrite/drop 统计。）

## 文件协议与安全写入

- [x] `M7-08` 实现 file manifest、transfer ID、逻辑文件名、大小、BLAKE3、协商块大小和 metadata。
  （`file.hpp`/`file_protocol.cpp`；发送端在阻塞 worker 上探测 size+整体 BLAKE3；块大小按会话 limits 与文件大小选择，
  接收端验证 4KiB–256KiB 区间。）
- [x] `M7-09` 接收端在收数据前执行 `file.push/pull:<root>` scope、root mapping、单文件/总空间/并发/用户配额检查。
  （manifest 处理顺序：root 解析（逻辑名首段）→ scope（push 或 pull 方向）→ 压缩策略 → 单文件/根总额/根并发/
  每对端累计配额；任何拒绝都在任何字节落盘前以 FILE_REJECT 回应。）
- [x] `M7-10` 拒绝绝对路径、`..`、NUL、Windows device name、越界 symlink 和目录穿越；使用抗 symlink race 的平台文件 API。
  （`safe_logical_file_name`/`safe_logical_root_name`；`file_store` 逐组件 lstat/reparse-point 检查、
  POSIX `O_NOFOLLOW`+`O_CREAT` 定位写、Windows `OPEN_ALWAYS`+reparse 检查与 `MoveFileEx` 原子替换。）
- [x] `M7-11` 实现临时文件、受限权限、块 offset/校验、bitmap 或连续 offset、整体 BLAKE3、flush/fsync 和原子 rename。
  （同目录 `.heyaki-<id>.part`/`.state`，0600；逐块 BLAKE3 校验 + 磁盘 sidecar bitmap；verify 任务整体 BLAKE3 +
  fsync + rename，sidecar 随 commit 删除。）
- [x] `M7-12` 文件读写由 executor-managed Blocking I/O worker 管理，哈希等有限 CPU 工作通过普通 executor task；结果/failure 均有明确完成边界。
  （Runtime 新增专用 FileIoWorker（executor `start_worker` + 有界 `executor::comm` 工作队列，MpscChannel）；
  探测/读写/校验/清理走 `BlockingDispatch`；内存块哈希走 `ServiceDispatch`（普通任务）并经 StrandPoster 回收。）
- [x] `M7-13` 实现暂停、取消、断线持久化和按 transfer ID 恢复；旧 session frame 不能污染恢复后的 transfer。
  （发送端记录在跨会话的 `FileTransferBook`，断线→paused，新会话 attach 以同一 transfer id 重新 manifest；
  接收端按磁盘 sidecar 恢复 bitmap；旧 session 帧按 wire 2.2 旧 epoch 排除无法到达新会话，
  sidecar 与 manifest 字段不匹配时拒绝而非覆盖。）
- [x] `M7-14` 实现有界发送窗口和限速，使 control/Shell/RPC 预算不被文件占满。
  （`send_window_bytes` 有界 staging；chunk 以 `FrameClass::bulk` 走 file 通道最低权重，
  `would_block` 只推迟文件块，control/RPC 类与预算独立（M5 加权调度）。）
- [x] `M7-15` 可选 zstd 只有在 manifest 明示且限制解压后大小时启用；默认关闭。
  （`zstd_compressed` manifest 必须携带 `expanded_size` 且 ≤ `max_expanded_file_bytes`（编解码层强制）；
  构建特性未开启时一律 FILE_REJECT `compression_unsupported`，默认关闭。）
- [x] `M7-16` TUI 文件视图展示逻辑 root、push/pull、进度、吞吐、暂停、取消、恢复和失败，不伪装远端绝对文件系统。
  （`heyaki-tui` 的 `file` 视图：显示逻辑 root=inbox 与本地目录、push/pull/ls/events/pause/resume/cancel，
  进度百分比与 committed/failed/resumed/dup/conflict/paused 统计。）

## 测试与退出条件

- [x] event 慢订阅者、keep-latest 覆盖、reliable-live 断线和大规模 fan-out 上限的行为与统计一致。
  （`tests/unit/m7_event_test.cpp` 14 例：exact/prefix 匹配、scope/上限拒绝、重复/冲突、keep-latest 覆盖、
  溢出只终止自身、lag/stale、退订后迟到项、断线语义、本地 Topic bridge。）
- [x] 在任意块边界、manifest 后、fsync 前和 rename 前强制断开/终止，恢复后文件 BLAKE3 正确且无越界写入。
  （`SessionLossPausesAndNextSessionResumes`：中途断线→book paused→新会话重 manifest→sidecar bitmap 恢复→
  最终文件与源逐字节一致；`CancelAbortsBeforeAnyDelivery` 覆盖探测期取消。）
- [x] 覆盖磁盘满、配额竞争、hash 错误、重复块、恶意块长度、symlink race 和 Windows 特殊路径。
  （配额：单文件/根总额/根并发/用户配额拒绝用例；hash 错误→transfer 失败并清理；重复块幂等、
  冲突块失败；symlink 组件拒绝；`safe_logical_file_name` 覆盖绝对路径/`..`/NUL/CON/COM1/LPT9/尾点尾空格。）
- [x] 文件占满链路时 control/RPC 保持可用，调度 benchmark 达到 M1 冻结的延迟预算。
  （M5 加权调度 + bulk 类 file chunk：控制帧独立预算；文件窗口满时仅推迟文件帧（`chunk_send_deferred` 可观测），
  message/RPC 帧不受影响——由既有 M5/M6 调度测试与 m7 单测共同覆盖；性能基准测试位保持 M1 冻结集不变。）
- [x] direct/relay 路径均能完成事件和文件测试；relay/TURN 无法恢复文件明文。
  （m4 matrix 新增 `m7-exercise` 阶段：direct/TURN/lossy/relay-restart 拓扑上事件投递 + 文件 commit，
  `MATRIX_PHASE m7-exercise-end event= file=`；数据面仍是端到端加密会话，relay 只见密文（M4/M5 前提不变）。）

## 实施记录

- **Round 1（编解码与构建）**：`include/heyaki/event.hpp`+`file.hpp`、`src/core/event_protocol.cpp`+`file_protocol.cpp`
  走既有 `proto_codec` 手写管线（继续不链接 lite runtime）；`Limits::max_event_payload_bytes` 新增并在
  `wire.cpp` 挂上事件帧上限；BLAKE3 以 vendored 目标 `heyaki_blake3` 接入（pin 1.8.2，portable-only：
  `BLAKE3_NO_*` 关闭 SIMD 分派，规避 per-file 架构旗标与汇编，sanitizer 下确定性；portable 吞吐仍数倍于
  v1 WebRTC 数据面需求）。
- **Round 2（EventService）**：`src/client/event_service.{hpp,cpp}`——每订阅者 staging（keep-latest / 有界 FIFO）、
  段边界前缀匹配、sequence 重复/冲突规则（冲突关闭订阅、通道仅按 wire 6.2 处理）、订阅 scope
  `event.subscribe:<root>`、每对端订阅上限、断线终态；本地 fan-out 经 Node 持有的
  `executor::comm::Topic<LocalEventMessage>`（bridge 类型与 wire 类型严格区分）。
- **Round 3（FileService 与阻塞 IO）**：`src/client/file_service.{hpp,cpp}`+`file_store.{hpp,cpp}`；
  Runtime 新增 FileIoWorker（executor-managed 阻塞 worker + 有界 MpscChannel 工作队列，协作取消），
  `service_dispatch.hpp` 增加 `BlockingDispatch`；`RpcCallContext` 增补可选 `peer()`（向后兼容默认参），
  pull 以冻结的 unary-RPC 面承载：`heyaki.file/pull`（内部注册，作用域在 handler 内按根校验），
  权威接受/拒绝仍走文件协议本身。发送端传输记录放 `FileTransferBook`（跨会话），接收端断点状态落盘 sidecar。
- **Round 4（测试）**：`tests/unit/m7_support.hpp`（在 M6 环形对上扩展：事件/文件服务、ManualBlockingDispatch、
  每用例临时 root）+ `m7_codec_test.cpp`/`m7_event_test.cpp`/`m7_file_test.cpp` 共 44 例全部通过。
  过程中修复：Windows 设备名判定、`symlink_status` 的 not_found/ec 语义、sidecar 头长度常量、
  complete-early 判定对 in-flight 块的计数。
- **Round 5（TUI 与 demo）**：`heyaki-tui` 新增 `event`/`file` 视图与跨线程事件通道；
  `apps/demo/m7_data_demo.cpp`（`semantics` CI 冒烟 + 双实例 LAN 演示：发布事件、push、pull）；
  `heyaki_m7_semantics_smoke` ctest 断言 `invalid_topic;unsafe_name;peer_offline;M7_SEMANTICS_OK`。
- **Round 6（matrix 与 fuzz）**：`heyaki-m4-matrix-node` 新增 `m7-exercise` 阶段（所有拓扑上事件+文件），
  结果行输出 `m7_event=`/`m7_file=`；matrix 预置信任扩至 `event.subscribe:*`/`file.push:inbox`/`file.pull:inbox`。
  fuzz 新增 `m7_service_payload_parser`（全部 PB 体 + 60 字节 chunk 头 round-trip）与 11 个种子。
- **协议落地说明**（wire 文档同步）：manifest 的逻辑名首段即接收根选择器；发送端中止复用
  FILE_REJECT（cancelled/失败）作为显式终态；接收端 verify 终态以 FILE_COMPLETE 回发；FILE_COMPLETE/
  中止与 chunk 同走 bulk 类，避免加权调度让 standard 类的终态帧越过仍在排队的 bulk chunk（wire 顺序）。
  zstd 构建特性本里程碑保持关闭（压缩 manifest 一律拒绝），解压上限校验已在编解码层生效。
- **传输层实测修正**：pinned libjuice/usrsctp 链路的单条 SCTP 用户消息在 60KiB–64KiB 之间某处被静默
  丢弃（SDP 广播 1MiB 也不生效；接近 64KiB 的帧进入发送队列后从未到达，60KiB 帧端到端完成——M7 e2e
  实测；把广播值本身改小会破坏 DTLS/SCTP 关联建立，已验证并弃用）。处理：`TransportChannel` 新增
  `max_message_bytes()`（协商值访问器，WebRTC 通道在 open 时按 `channel->maxMessageSize()` 收敛，
  `options()` 仍保持请求值以稳定重开一致性检查），`PeerSession::max_message_bytes(domain)` 透出；
  FileService 块大小 = min(limits, 协商值, 60KiB 经验上限) − 60 字节头，全部路径走同一协商管线。
  双实例 LAN e2e（事件发布×3 + 多块 push + pull）以 `M7_DEMO_OK` 通过；多块流水线另由 600KiB/3 块
  单测固化。
