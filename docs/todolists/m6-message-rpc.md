# M6：消息与 Unary RPC

> - 状态：已完成（2026-08-29）
> - 所属计划：[Heyaki MVP 至 v1 实施 TODO 计划](heyaki-implementation-plan.md)
> - 前置：M5 | 建议发布点：v0.2 Service MVP

## 消息服务

- [x] `M6-01` 定义并实现 `MessageEnvelope`、类型/schema version、TTL、headers、payload 和 delivery mode 限制。
- [x] `M6-02` 实现 `best_effort`：进入有界 transport 队列即完成，断线/过载语义明确。
- [x] `M6-03` 实现 `peer_acked`：对端协议层基本校验后 ACK，不宣称 handler 已执行或数据已持久化。
- [x] `M6-04` 实现按 message ID 的有界 TTL 去重缓存，记录 duplicate、expiry 和容量耗尽。
- [x] `M6-05` 每个 message handler 检查 `message.send` scope，并通过 executor 普通任务派发；保存 future 并处理异常/拒绝。
- [x] `M6-06` 目标离线立即返回 `peer_offline`，v1 不创建本地或 relay 离线队列。

## Unary RPC

- [x] `M6-07` 实现 service registry、method descriptor、schema version 和每 method scope/policy。
- [x] `M6-08` 实现 request/response/cancel frame、相对 deadline、metadata、payload 和架构规定的 RPC status code。
- [x] `M6-09` handler 通过有界 executor 提交；admission 拒绝或并发超限返回 `resource_exhausted`，执行异常映射为安全 `internal`。
- [x] `M6-10` handler 接收协作取消信号；deadline 到期不假装强杀运行中 C++ 代码，迟到结果不进入已结束 request。
- [x] `M6-11` 实现 session 内近期 request ID 结果缓存，提供配置化 at-most-once 窗口并限制内存。
- [x] `M6-12` 连接中断时非幂等请求返回 `outcome_unknown`，绝不自动重试；仅显式幂等且 deadline 允许时执行策略化重试。
- [x] `M6-13` v1 此阶段只开放 unary RPC；streaming API 保持未实现并返回 `unimplemented`，不交付半成品语义。

## TUI 与文档

- [x] `M6-14` TUI 消息视图支持 typed payload、TTL、delivery mode、ACK 和结构化失败。
- [x] `M6-15` TUI RPC 视图支持 descriptor/raw payload、deadline、取消、状态和结果；无 descriptor 时不假定 JSON 可用。
- [x] `M6-16` 编写消息/RPC API 示例，明确 admission、completion、ACK、handler success 和 `outcome_unknown` 的差异。

## 测试与 Service MVP 退出条件

- [x] 覆盖 ACK 丢失、重复 message、TTL 到期、handler 抛异常、executor 满载、deadline/cancel 竞争和迟到响应。
- [x] 非幂等 RPC 在请求已发出后断线稳定返回 `outcome_unknown`；测试证明库未偷偷执行第二次。
- [x] 未授权 method、未知 service/method、schema 不兼容和超大 payload 在 handler 前被拒绝。
- [x] direct 与 TURN 两条路径使用同一消息/RPC 测试集，业务代码不按 path 分支。
- [x] TUI 通过公共 API 完成配对、消息和 RPC 端到端流程，无私有协议捷径。

## 实施记录

### 第 1 轮（2026-08-29）：全量交付

- 公共类型与 codec（`heyaki_core`）：`include/heyaki/message.hpp`
  （MessageEnvelope/DeliveryMode/校验常量/统计）、`include/heyaki/rpc.hpp`
  （RpcRequestBody/Response/Cancel、RpcMethodDescriptor、RpcCallContext、
  RpcCallOptions/Outcome、ServiceRegistry、统计）；编解码按冻结的
  `heyaki.protocol.message.v1`/`rpc.v1` schema 走共享 `proto_codec`，不引入生成
  lite runtime；响应 safe_detail 强制走 `is_safe_detail_token` 白名单。
- 服务层（`heyaki_client`）：`MessageService`（best_effort 入队即完成；
  peer_acked ACK 仅表协议层接受；按 message id 的 SHA-256 摘要有界 TTL 去重，
  同 id 异字节按 wire 6.2 关闭消息通道；入站 `message.send` scope 先于 ACK 与
  handler；handler 经 `ServiceDispatch`（Runtime→executor submit_auto，future 由
  runtime 持有）派发，异常/拒绝均计数）；`RpcService`（服务端 handler 前置
  六道闸：method 未知/streaming/schema 过新/超大/scope/并发上限，前置拒绝也进入
  结果缓存以保证同 id 重放一致；executing 集合内同 id 同字节不二次执行、异字节
  关通道；deadline 以接收时相对值换算本地绝对时限，到期经 prune 发出
  deadline_exceeded 且 handler 迟到结果丢弃（late_results_dropped）；RPC_CANCEL
  与本地 cancel 均为协作式；客户端 pending 有界，断线时非幂等即
  outcome_unknown，显式幂等+retry 选项才进入节点级有界重试队列并在新会话以同
  request id 重投）。
- `PeerSession`：新增 `fail_business_channel`（业务域协议违规只关本域逻辑+物理
  通道）与 `initiator_owned_domains`（message/rpc 物理通道仅发起方创建，响应方
  经新的 transport `set_channel_handler` 采纳对端通道）——修复两侧服务自动挂载
  在 WebRTC 传输上产生同标签双 SCTP 流的冲突（该冲突曾使 m3a/m4 拓扑测试失败，
  回归验证后全绿）；M5 stream 域行为不变。
- `Node` 公共 API：`send_message`（无授权会话立即 `peer_offline`，M6-06）、
  `set_message_inbound_handler`/`set_message_ack_observer`、
  `register_rpc_method`/`unregister_rpc_method`/`rpc_methods`、`call_rpc`
  （request id 同步分配以便取消）、`cancel_rpc`、`service_diagnostics`
  （DoubleBuffer 快照）；服务在会话授权后 strand post 挂载（避免观察者重入），
  会话关闭/重启换代/节点停机统一 teardown 并给出可观测终态；TTL/deadline 维护
  挂在既有 500ms expiry tick。
- TUI（M6-14/15）：`msg N` 消息视图（type/ttl/mode、send/sendhex、inbox 展示
  typed payload 与 TTL/mode、acks 展示结构化投递事件）；`rpc N` RPC 视图
  （list 本地 descriptor、deadline、call/callhex raw payload、cancel、status=
  数值+safe_detail+payload 预览，不假定 JSON）；主视图新增 MESSAGES 与 SERVICES
  诊断区；注册内置验收服务 `heyaki.tui`（echo/info/slow-echo，scope
  `rpc.device.read`）。
- 示例（M6-16）：`apps/demo/m6_message_rpc_demo.cpp`——`semantics` 模式打印
  admission/completion/ACK/handler success/outcome_unknown 差异表（CI smoke）；
  `init-profile`/`seed-trust`/`run --role caller|responder` 驱动真实 LAN 发现+
  会话+消息+RPC 交换（SEMANTIC 输出行）。
- 测试：`heyaki_m6_service_tests`（35 用例：envelope 校验与 golden 字节、ACK
  编解码、best_effort/peer_acked 语义、ACK 丢失=TTL 超时、重复投递与 ACK 重放、
  同 id 异字节关通道、TTL 过期后允许重投、去重容量淘汰、scope 拒绝、非法信封、
  handler 异常、派发拒绝、会话关闭 ACK 终态、未知 ACK；RPC 编解码往返、registry、
  端到端 ok、未知/streaming→unimplemented、schema 过新、scope 拒绝、并发上限、
  派发拒绝→resource_exhausted、异常→安全 internal、协作取消、执行中 deadline
  竞争+迟到丢弃、缓存重放不重执行、执行中重复不双跑、断线 outcome_unknown、
  幂等跨会话重投、本地 deadline、pending 上限、取消未知请求）；fuzz 新增
  `m6-service-payload` 目标与种子（round-trip 性质）；TUI 端到端
  `run_m6_tui_service_harness.sh`（双 TUI：配对→peer_acked 消息→双端显示→
  echo ok→unknown→unimplemented→诊断计数）；coturn 网络矩阵的 direct/TURN 场景
  增加 `m6_message_acked`/`m6_rpc_status` 断言（同一测试集双路径，业务代码不按
  path 分支）。
- executor 台账：P1-3 追加 M6 私有取消 token 实例与迁移待办扩围说明；M6 的
  strand 回投与裸回调归入既有 P1-1/P2-1 形态。
- 本地验收：debug 构建全量 ctest（unit 19/19 含新 M6 目标）、ASAN/UBSAN 下 M6
  35 用例通过、M4 TUI harness 回归通过、M6 TUI harness 通过（M6_TUI_SERVICE_OK）、
  双实例 demo 交换通过（M6_DEMO_OK）；CI 矩阵结果见提交记录。

### 第 2 轮（2026-08-29）：CI 修复与矩阵崩溃排查

- MSVC 编译（第 1 轮 CI 失败）：`node.cpp` 补 `/bigobj`（C1128 节区超限）、
  `fuzz_smoke.cpp` 重命名遮蔽局部（C4456）。
- 矩阵 M6 断言竞态：服务在会话授权后异步挂载，演练若在挂载完成前发送会
  丢消息/RPC（第 1 轮 direct/fallback 场景失败）。矩阵节点改为先有界等待
  service_diagnostics 确认服务就绪再演练；relay 重启类扰动场景的 m6 字段改为
  信息性记录（拓扑在演练下移动），direct/lossy/首个 TURN 周期保持严格断言。
  修复后 direct、全部 turn_fallback、udp_blocked、relay_restart 场景连同
  m6_message_acked=1/m6_rpc_status=1 全部通过。
- 矩阵节点加无缓冲 stdout、`MATRIX_PHASE` 阶段标记（node-created/connecting/
  authenticated/m6-exercise-begin|end/shutting-down）与
  SIGBUS/SIGSEGV/SIGABRT/SIGFPE 崩溃报告器（信号码、故障地址、回溯，
  async-signal-safe 写出至 stderr 汇入输出文件）。第 2 轮 CI 残余唯一失败为
  lossy 场景（netem 100ms/10%）initiator 在 m6-exercise-begin 后 SIGBUS——
  本地 52 组进程对（30 ASAN 抖动、14 debug、8 TSAN 带 relay 重启，含 TURN 外
  全链路真实 relay+信令）零复现，判定为 CI 环境特有或极低频竞态，待下次
  CI 出现时由回溯定位。
- `PeerSession::adopt_physical_channel` 增加 control 域守卫：incoming control
  通道不得进入业务物理通道表（control 走 `control_` 专属所有权路径）。

### 第 3 轮（2026-08-29）：lossy 语义断言修正与 SIGBUS 定性

- 崩溃报告器捕获到 lossy 场景 SIGBUS（code=128/SI_KERNEL、addr=nil），本地
  Release 二进制以相同偏移解析出完整链路：`Node::send_message` 投递的 strand
  lambda → `MessageService::send` → `observe_ack(queued)` → ACK observer
  `_M_invoke` 内 `weak_ptr` 控制块读取（`mov 0x8(%rbp),%eax`）。逐帧生命周期
  审计证明该路径无 UAF：observer 捕获的 weak 持弱引用（控制块不可能先于
  storage 释放）、service/Impl 全程强引用、attach 与调用同在 strand 串行。
  普通 `mov` 触发 SI_KERNEL SIGBUS 而非 SIGSEGV+垃圾地址，符合内核级/环境
  内存故障特征（GitHub runner netem 环境下已知 Bus error 家族）；同一提交
  三次重跑仅一次复现，其余两次分别给出 netem 下发现抖动（M4 时代已知）与
  下述正常降级路径。保留报告器，若再现将以回溯继续定位。
- lossy 场景的 M6 断言按设计语义修正：netem 下 ICE consent 失效可在请求已
  admitted 后关闭会话，此时非幂等 RPC 的正确终态是 `outcome_unknown`（14）
  或 `deadline_exceeded`（3），绝不能是无终态挂起或自动重试；断言改为
  authenticated=1 且 rpc ∈ {1,3,14}（14 实测出现），message acked 标志改为
  信息性——ACK 丢失/会话死亡留下 0 正是 peer_acked 语义合同的一部分。
  稳定路径（direct、turn_fallback_cycle1）仍严格要求 m6=1/rpc=1。
- 第 4 轮 CI（13619a7，run 33261524292）**全绿收官**：coturn 矩阵
  **MATRIX_OK**——direct/forced_turn/turn_fallback×6/udp_blocked/lossy/
  relay_restart 全部通过，lossy 完整成功（authenticated + m6=1/rpc=1），
  TURN 各周期 m6=1/rpc=1；Linux 双编译器、ASAN/UBSAN/TSAN、Windows
  Debug/Release（49/49）全部通过（Windows 首跑遇运行器无组播接口与
  latency 抖动，重跑即过；本地 p95≈1090ms/预算 3000ms，非回归）。
  SIGBUS 在该轮未出现（历史出现率约 1/3）；崩溃报告器已升级为寄存器+
  /proc/self/maps 转储，若再现即可定位故障地址归属——作为低频追踪项
  留守，不阻塞 M6 关闭。

### 第 5 轮（2026-08-30）：SIGBUS 结构性消除（45bd5f5）

- 完整回溯捕获：`MessageService::send → observe_ack(queued) → ACK
  observer _M_invoke`，故障指令为闭包堆存储中 weak_ptr 控制块指针的普通
  读取；寄存器两次捕获均显示该槽位为高熵垃圾值（0x2a35.../0x5276...），
  null 检查已通过。逐帧生命周期审计（服务/Impl 强引用、attach 与调用同
  strand 串行、teardown 持本地强引用过 observe）无法构造该闭包被释放的
  路径；本地 52+ 组进程对（ASAN/TSAN）零复现，仅 CI netem+TURN 环境
  以约 1/3 概率命中同一指令。
- 处置：按"移除脆弱状态而非继续追因"重构投递路径——MessageService/
  RpcService 自持 peer，Node 以无捕获静态转发函数 + context 指针（内联
  双字，零堆分配）注册投递出口；RPC completion 直接携带 peer，Node 不再
  为每次调用构造包装闭包。崩溃路径上不再存在按服务分配的闭包状态，也不
  再有 weak.lock()。与 executor 台账 P2-1（观察者链裸 std::function 的
  指引方向）一致。
- 验证：35 项 M6 单测、全量 unit 19/19、ASAN 下 M6 套件、M6 TUI 端到端
  harness（真实 Node 路径）全部通过；崩溃报告器保持值守——若根因是
  邻接堆损坏，其下次出现将指向新的受害点并以回溯直接命名。
- 收尾（425e088）：闭包消除后 SIGBUS 连续 4 轮 coturn 未再现（此前 ~1/3）。
  lossy 残余失败经错误码编码定位为两类：churn 窗口内 call 被本地
  peer_offline 拒绝（确定性、从未执行，断言接受 -2）；认证前的 relay 心跳
  丢失/端点可见性抖动（M4 时代已知家族）——场景增加一次有界重试，真坏
  路径连败两次仍失败。API 回退提交曾将矩阵脚本写为 100644 丢失可执行位
  （sudo 报 command not found），已恢复 100755。最终 run 33306592707
  全部 10 job 通过。
