# Heyaki 并发与关闭设计

> 状态：M2 冻结版  
> 日期：2026-08-15  
> 适用范围：`heyaki::Node`、`PeerSession`、`heyaki-relay`、`heyaki-tui` 与阻塞 I/O 适配器

## 1. 所有权边界

Heyaki 只允许一个明确 owner 初始化和关闭每个 executor 实例。库对象可以借用 executor，
但不能因自身析构而关闭共享执行资源。

| 运行形态 | executor owner | Node 模式 | Asio owner | 关闭 executor |
| --- | --- | --- | --- | --- |
| 链接 Heyaki 的库应用 | 调用方进程 | 借用 | 调用方或共享 runtime | 仅调用方 |
| `heyaki-tui` | `main()` | 借用进程 runtime | 进程 runtime | `main()` |
| `heyaki-relay` | `main()` | 不适用 | 进程 runtime | `main()` |
| 单元/集成测试 | fixture | 显式借用或隔离实例 | fixture | fixture |

独立应用使用独立 `executor::Executor`，在第一次提交前调用 `initialize_ex()`。只有明确需要
全进程共享资源时才使用 `Executor::instance()`。Node 配置必须携带借用的 executor/runtime，
不得在库内部偷偷创建第二套线程池。

## 2. 执行上下文与完成边界

| 上下文 | 承载方式 | 状态所有权 | 完成事实源 |
| --- | --- | --- | --- |
| Asio 网络循环 | executor 注册的 `BlockingIoWorker` | 进程 runtime | worker status + Asio work 收敛 |
| Node 状态机 | Node 专属 Asio strand | 仅 strand 内修改 | operation 终态 callback/result |
| PeerSession 状态机 | session 专属 Asio strand | 仅 strand 内修改 | session 终态与 close reason |
| 普通 handler | 借用的 executor async pool | handler 自有输入 | 保存的 future 或 failure event |
| 阻塞文件/PTY/设备 I/O | executor `BlockingIoWorker` | worker 内部 | worker status + 协作 stop |
| 外部 callback | `MpscChannel<CallbackEvent>` | strand 消费 | channel admission + operation 终态 |

队列 admission 不是操作完成。executor 提交成功只表示任务被接受；Heyaki 必须保存 future，
或为明确的 fire-and-forget 路径配置 failure callback。worker `ready` 只表示线程已进入 `run()`，
不表示网络、设备或协议已经就绪。

## 3. 通信组件与容量

| 数据 | executor 组件 | 默认容量 | 满载策略 | 必须观测 |
| --- | --- | ---: | --- | --- |
| libdatachannel/外部 callback | `MpscChannel` | 每 Node 1024 条 | 拒绝新消息；关闭后拒绝 | reject、peak depth、lag |
| TUI 离散事件 | `MpscChannel` | 1024 条 | 普通事件拒绝；控制事件预留容量 | reject、render lag |
| Node/PeerSession 低频状态 | `DoubleBuffer` | 两份快照 | 发布失败显式报告 | sequence、stale、consumer lag |
| 可覆盖指标/进度 | `LatestMailbox` | 1 个最新值 | overwrite | sequence、overwrite、lag |

所有容量必须可配置并在启动时校验。未知或为零的关键控制容量是配置错误。通信组件的
`CommStats` 和 callback 不会自动进入 executor task failure 统计；runtime 只把低频 comm 事件
桥接到 Heyaki 诊断，不复制 executor 的 task health 计数。

跨执行上下文传递的 payload 必须拥有其内存。callback 不得把指向第三方临时 buffer 的
`span` 投递到 strand 或 handler。

## 4. Operation 与安全上下文

每个外部操作分配 `OperationId`，提交封装至少携带：

- operation ID 与 session epoch；
- 本地 application ID；
- 已验证的 peer/device/endpoint（如适用）；
- deadline/cancellation；
- handler 所需的授权 scope。

封装只负责关联上下文和将异常映射为安全错误。任务拒绝、任务异常、等待超时和 executor
生命周期状态仍以 executor future、failure event、status 和 snapshot 为事实源。

## 5. 固定关闭顺序

关闭状态为单向状态机：`Running -> StoppingAdmission -> Draining -> Stopped`。

1. 原子停止 Node/relay admission，新操作返回 `cancelled` 或 `would_block`。
2. 取消重连、心跳、租约和其他生产者定时器，不再向 callback channel 产生新消息。
3. 请求取消消息/RPC/事件/文件/Shell operation，并记录仍未完成的 operation ID。
4. 关闭 PeerSession 和 transport；外部 callback 只允许投递终态/关闭事件。
5. 注销 relay endpoint；超过注销预算时记录 timeout，继续本地关闭。
6. 关闭 callback `MpscChannel`，strand 消费到 closed，随后释放 session 状态。
7. 释放 Asio work guard，唤醒并停止承载 `io_context::run()` 的 Blocking I/O worker。
8. 在预算内等待本 Node 提交的 future/operation；借用模式不得等待或 drain 其他组件任务。
9. 刷新 ProfileStore、文件恢复状态和审计记录。
10. 仅进程 owner 调用 executor `wait_for_completion_ex()`，再按结果选择
    `shutdown(true)` 或记录后执行 `shutdown(false)`。

依赖数据（ProfileStore、handler registry、诊断 sink、channel 和 Asio objects）必须晚于引用
它们的任务收敛。`shutdown(false)` 不是强杀，不能修复悬空捕获或不可中断 I/O。

## 6. 预算与超时动作

| 阶段 | 默认预算 | 超时后的事实源 | 后续动作 |
| --- | ---: | --- | --- |
| relay 注销 | 2 秒 | operation error/status | 记录并继续本地关闭 |
| peer close | 3 秒 | session close status | reset transport，标记非优雅关闭 |
| Node operation drain | 5 秒 | operation registry | 取消未开始任务；持久化可恢复状态 |
| Asio worker stop | 2 秒 | Blocking I/O status | 再次 wakeup，报告 runtime timeout |
| owner executor drain | 5 秒 | `WaitResult` + snapshot | owner 选择继续等待或快速关闭 |

所有等待使用 monotonic deadline。禁止无限等待，也禁止用固定 sleep 推断任务完成。

## 7. 可观测性与测试门禁

runtime 必须暴露：admission rejection、callback reject/closed、comm overwrite/stale/lag、
executor failure event、worker stop reason、drain timeout、未完成 operation ID、关闭阶段和耗时。

测试至少覆盖 executor overload、提交拒绝、任务/callback 异常、关闭期间提交、Node 多次关闭、
借用 executor 不被关闭、worker wakeup、drain timeout，以及 ASAN/TSAN 下 callback bridge 与状态
转换无悬空引用和数据竞争。
