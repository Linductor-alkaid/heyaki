# Executor 反馈台账（Feedback Ledger）

本台账记录 heyaki 开发过程中发现的 executor 依赖（`third_party/executor`）能力缺口与"将就"点，
作为 executor 后续恢复开发的输入，也用于检验 executor 公共 API 是否如其文档所述完备。

- 起始日期：2026-08-29（M5 关闭后盘点，覆盖 M0–M5 全部开发史）
- 维护规则：开发中每次遇到"executor 不够用 / 语义别扭 / 只能绕过"的时刻，按 AGENTS.md 的上报
  流程记录到本台账，不再让反馈停留在口头或代码注释里。
- 每条记录字段：现象（heyaki 侧 workaround 与位置）、executor 缺口（行为 + API 层面原因）、
  建议的最小能力、影响与优先级。

条目分级：
- **P1**：系统性将就，影响面覆盖整个 client/relay 代码面，executor 不可见大量任务派发。
- **P2**：结构性将就，某个子系统的通信/调度模式整体绕开 executor 设施。
- **P3**：有而未用，executor 已提供对应能力但 heyaki 尚未接入（属于 heyaki 侧待办，非 executor 缺口）。
- **违规**：违反 AGENTS.md 明文，heyaki 侧需自行整改，不依赖 executor 变更。

---

## 上游收敛状态（2026-08-29 回写）

executor 上游已按本台账实施一轮收敛（executor 侧
`third_party/executor/docs/todolists/client_feedback_update_plan.md`，
heyaki pin 于 2026-08-29 从 `077d854` 升至 `4e8e8eb`，PR #176/#177）：

- **P1-3 已闭环（上游 C1）**：`task_cancellation.hpp` + `submit_cancellable*`（StopToken 注入
  callable 首参）+ `request_task_cancel`，排队/运行中两类取消语义，取消计数进独立
  `CancellationStatus`（不进 failure 体系）。heyaki 侧迁移待办：EXEC-07 的自建 deadline 取消。
- **P1-2 部分闭环（上游 T1）**：`timer.hpp` 的 `TimerHandle`/`ScopedTimerHandle` 提供取消/
  重排/状态查询（`submit_delayed_with_handle` 等）。一期**不绑定 asio strand / 外部序列化
  上下文**（上游 T2/S2 门控），因此与 IO 对象同 strand 销毁的 `steady_timer` 仍不可替换；
  仅不依赖 strand 所有权的定时工作可迁移。
- **P1-1 仅文档（上游 S1）**：`third_party/executor/docs/external_event_loop_interop.md`
  互操作指南与示例已落地；`submit_on` 类 API 属 S2，未实现。
- **P2-1 有官方指引（上游 G1）**：中英文"如何选择通信组件"指南新增"什么时候允许裸回调"
  一节，heyaki 侧可据此引用豁免。
- **P2-2 维持延后**：按台账结论待 M6/M7 真实压测后重估。
- 行为变更影响评估：shutdown 时未到期 delayed 任务 future 异常改为 `TaskCancelled(Shutdown)`、
  `ExecutorSnapshot` schema 2→3——heyaki 均未使用受影响路径，升级验证
  （debug/UBSan 全绿，ASan/TSan 仅 libglib/libsecret 内部竞争与本机 ASLR 环境问题）。
- **2026-08-29 heyaki 侧迁移（已落地）**：runtime handler 任务改用 `submit_cancellable`
  （`src/client/runtime.cpp` 的 dispatch 路径），`TrackedTask` 保存 `TaskHandle`；
  shutdown drain 超时后对未完成任务调用 `request_task_cancel`（排队任务直接终止，
  运行中任务收到协作停止请求），`observe_ready_task` 把 `TaskCancelled` 映射为
  `OperationState::cancelled`。node/relay 内与 asio 对象同 strand 的 `steady_timer`
  （deadline、announce/expiry、relay heartbeat 等）**维持现状**：上游 T1 明确不承诺
  strand/外部上下文绑定，且这些 timer 的回调须与 IO 对象同上下文销毁，迁移须等上游
  T2/S2 验收；task_sweep timer 同理（其状态非线程安全，不能挪到 executor 池）。

## P1-1 指定 backend 上的延续执行（strand 派发不可见）

- **现象**：`RuntimeAccess::io_executor()`（`src/client/runtime.cpp:1056-1061`，声明于
  `runtime_access.hpp:15`）把 Runtime 内部 `io_context` 的 executor 直接交给应用层；node、
  relay_server、relay_wss_client 各自创建 `boost::asio::strand` 并以 `boost::asio::post(strand, ...)`
  做跨上下文派发（`src/client/node.cpp:910`、`src/relay/relay_server.cpp:97`、
  `src/client/relay_wss_client.cpp:149` 及全文数十处 post 调用点）。
- **executor 缺口**：没有"在指定 backend / 指定序列化上下文上提交任务"的公共 API。asio 网络回调
  天然运行在 io_context 上，strand 是零拷贝延续；executor 的 `submit` 只面向自身 worker 池，
  无法承载"从 asio 回调延续到既有序列化上下文"的场景。
- **影响**：经 `asio::post` 提交的回调不进入 executor 的 admission、统计与失败事件体系——executor
  对 heyaki 内最大量的一类任务派发完全不可见。这是全仓面积最大的灰色地带。
- **建议能力**：executor 提供序列化上下文（serial execution context）原语或 `submit_on(context, task)`
  等价物，使 strand 类派发纳入 admission/监控；或提供官方文档化的 asio backend 延续指南。
- **备注**：整个 io_context 经 `AsioWorker`（`runtime.cpp:279-295`）作为 executor blocking worker
  托管、以 `PhaseGate` 收尾，这一点是 EXEC-02/EXEC-10 批准的合规路线；缺口只在 post 级派发不可见。

## P1-2 与 IO 对象绑定的定时任务（asio steady_timer 替代 submit_delayed/periodic）

- **现象**：约 7+ 处 `boost::asio::steady_timer` 承载周期/延迟工作：announce/expiry/interface/
  readiness/relay_poll/relay_heartbeat/relay_reconnect（`src/client/node.cpp:5015-5021`）、
  deadline timer（`node.cpp:537, 5046, 853`）、relay sweep/会话 timer（`src/relay/relay_server.cpp:164, 507`）、
  task_sweep（`runtime.cpp:946`）、relay_wss_client（`relay_wss_client.cpp:211`）。
- **executor 缺口**：`submit_delayed` / `submit_periodic` 存在，但无法绑定网络对象生命周期
  （timer 需要与 asio 对象同 strand 销毁），且缺少 per-timer 的独立取消/重排语义。
- **影响**：这些定时任务完全不在 executor 统计与生命周期视图内。
- **建议能力**：可取消、可与执行上下文绑定的 delayed/periodic 句柄（类似 asio timer 的
  cancel/expires_at 语义），并纳入监控。

## P1-3 运行中任务的 deadline / 协作取消（上游已落地 C1，heyaki 迁移待办）

- **现象**：EXEC-07（`docs/todolists/heyaki-implementation-plan.md:61`）正式记录：不把 executor 的
  queued soft timeout 当作运行中任务的取消；每个 operation 用 asio `steady_timer` deadline
  自建取消（`node.cpp:537, 5046`）。
- **executor 缺口**：~~取消语义只覆盖排队超时，没有面向"已开始运行的任务"的协作取消令牌
  （cancellation token / stop callback）机制。~~ 上游 C1 已提供 `submit_cancellable` +
  `StopToken`/`StopSource`（pin 4e8e8eb）；缺口转为 heyaki 侧未迁移。
- **影响**：所有长时操作（连接、配对、中继登录）的取消逻辑是 heyaki 私有实现，executor 无法
  观测"任务被取消"这一生命周期事件。
- **建议能力**：任务级协作取消令牌，提交时可选传入，取消事件进入 failure/status 体系。
- **M6 追加（2026-08-29）**：M6-10 的 RPC handler 协作取消在
  `src/client/rpc_service.cpp`（`ServerCallState::cancel_requested`，atomic bool 经
  `RpcCallContext::cancelled()` 观察）又落了一份私有 token——wire 层 RPC_CANCEL/deadline 需要
  在任务仍在排队时即可置位，且测试注入同步 dispatcher，故先以私有标志实现。迁移
  `submit_cancellable` 时应把 `RuntimeAccess::dispatch_general` 与 M6 handler 派发一并纳入，
  使取消事件进入 executor 生命周期视图。

## P2-1 裸 std::function 回调替代 executor::comm

- **现象**：peer_session / byte_stream / pairing_service / node 之间的事件与判定全部走
  `std::function`：`TrustAuthorizer`、`PairingEvaluator`、`PairingResultSink`、observer
  （`src/client/peer_session.hpp:54-123, 153-155`，注入点 `node.cpp:2966-3001`）；
  `BusinessFrameHandler`/`DomainFrameHandler` map（`peer_session.hpp:70-75, 252-253`）；
  `ReadHandler`/`WriteHandler`/`InboundHandler`（`src/client/byte_stream.hpp:94-98, 132, 138, 193, 212, 251`）；
  `wall_clock`/`audit_sink`（`src/client/pairing_service.hpp:66-67`）。
- **executor 缺口**：这些多为同 strand 同步调用，不违反"跨上下文必须用 comm"的条文；但 comm
  组件缺少"同上下文内的观察者/信号槽"形态，导致绕开了容量、背压与通信统计的可观测性。
  `Topic` 面向跨上下文广播，语义不匹配（无订阅端背压语义的同上下文 signal）。
- **影响**：授权判定、审计事件、帧到达等关键路径的通信量对 executor stats 不可见。
- **建议能力**：同上下文 signal/slot 或带统计的 observer 原语；或明确文档指引何时允许裸回调。

## P2-2 多优先级/加权/双限额调度队列（session_channels 自建）

- **现象**：`src/client/session_channels.hpp:279` 用 `std::map<std::uint8_t, std::deque<...>>`
  自建带字节+帧双限额、加权 deficit 轮转、reject/drop-oldest/keep-llatest 策略的调度队列
  （容量策略 86-97 行，等待 ticket 用 `Completion = std::function`，137 行）。
- **executor 缺口**：`executor::comm` 的有界 channel 是单优先级 FIFO，无多类别的加权调度、
  字节维度限额或 per-class drop 策略。因该队列仅 PeerSession 内单线程使用，不构成
  AGENTS.md 意义上的私造跨线程队列。
- **影响**：调度健康（各 class 积压、drop 计数）需 heyaki 自行导出，不与 comm stats 汇合。
- **建议能力**：带优先级/权重与可插拔 drop 策略的 channel 变体，或提供构建此类队列的公共骨架。

## P3 executor 有而 heyaki 未用（heyaki 侧待办，非缺口）

- `executor::monitor::ExecutorMonitor` 快照聚合（近期失败列表、in-flight 诊断）：零引用；
  runtime 仅 `set_failure_callback` 计数（`src/client/runtime.cpp:328-333, 129-160`）。
- `Topic`、`LatestMailbox`、`RealtimeChannel`、`SnapshotStore`：零使用（WebRTC 事件用了
  `MpscChannel`+`DoubleBuffer`，`src/transport/webrtc/webrtc_transport_session.cpp:31-34, 752-753`，合规）。
- `submit_priority`、依赖图 `submit_after`/`when_all`、realtime task 路径：零使用。
- M9-01（`docs/todolists/m9-production-hardening.md:9`）要求业务指标与 executor
  failure/status 关联——已列入 M9 待办，届时再评估上述组件是否满足。
- 应用层自建健康计数（TUI `UiBridge::rejected` 原子计数 `apps/tui/main.cpp:68`、
  relay_login/turn 自维护 stats）属 EXEC-08 允许范围，但缺少与 executor 事实源的字段级关联。

## 违规（heyaki 自行整改，不依赖 executor 变更）

- **V-1 TUI pairing 共享状态**：`apps/tui/main.cpp:77` `std::mutex pairing_mutex` 保护的
  `pairing_peer/pairing_error/pairing_scopes` 由 node strand 写、渲染循环读（514-520、351-352），
  违反 AGENTS.md"不得以共享可变状态 + mutex 替代 executor 通信"。同文件 67 行已用
  `executor::comm::MpscChannel` 处理 signaling events，pairing 状态应改走
  `LatestMailbox`/`DoubleBuffer`。规模小（UI 层），列入近期整改。

---

## 恢复 executor 开发的建议输入顺序

1. P1-3（协作取消）——语义清晰、影响所有长时操作，且不引入新抽象。
2. P1-2（可绑定生命周期的定时句柄）——与 P1-3 组合可消灭 heyaki 内绝大多数量 asio timer。
3. P1-1（序列化上下文/strand 纳管）——收益最大但设计面广，建议先出文档化指南再定 API。
4. P2-1/P2-2 —— 待 M6/M7 的消息与文件传输真实压测后再定形，避免过早抽象。

## 变更记录

- 2026-08-29：初始盘点（M0–M5），7 条 P1/P2、1 条违规、P3 待办清单。
- 2026-08-29：executor 上游落地 P1-3（C1）与 P1-2 的 T1 部分，S1 指南与 G1 裸回调指引同步
  上线；heyaki pin 升至 `4e8e8eb`（dependencies.lock 同步），新增"上游收敛状态"一节。
  heyaki 侧迁移待办：EXEC-07 deadline 取消改用 `submit_cancellable`；非 strand 定时器改用
  `TimerHandle`。
- 2026-08-29：M6 开发在 P1-3 追加 rpc_service 私有取消 token 的实例（迁移待办扩围至
  dispatch_general + M6 handler 派发）；M6 的 strand 回投（StrandPoster）与 ServiceDispatch/
  ScopeCheck 回调分别归入既有 P1-1、P2-1 条目形态，不另立新条。
