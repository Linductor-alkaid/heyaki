# M8：Remote Shell

> - 状态：已放行（2026-09-04 安全评审签字后生产启用解禁，限 POSIX；开发完成于 2026-09-03，46 项 M8 单测全绿、本机全仓 51 项 ctest + m8 ASan 绿、CI 全矩阵含 Windows ConPTY 生命周期；评审报告见 [docs/security/m8-remote-shell-security-review.md](../security/m8-remote-shell-security-review.md)）
> - 所属计划：[Heyaki MVP 至 v1 实施 TODO 计划](heyaki-implementation-plan.md)
> - 前置：M7 | 建议发布点：v0.4 Shell beta

## 服务端 Shell

- [x] `M8-01` 定义 `ShellProfile`：固定程序、OS 用户、工作目录、环境 allowlist、资源、空闲和绝对时限；默认配置无 profile。已交付：`include/heyaki/shell.hpp`（`ShellProfileConfig`+`validate_shell_profile`），`NodeConfig::shell_profiles` 为空即整体关闭，owned runtime 仅在配置了 profile 时启动 PTY worker。
- [x] `M8-02` 实现独立 scope `shell.open:<profile>`、本地 `ShellAuthorizer` 和并发会话限制，请求方不能覆盖 executable 或任意环境变量。已交付：`shell_open_scope` + ShellService 在 spawn 前实时检查会话 scope 与 per-profile 并发上限；`ShellOpen` wire 结构无 executable/env 字段（结构性不可覆盖），环境由本地 allowlist + 字符集校验后的 TERM/locale 组成；信号策略 allowlist 以 `SHELL_ERROR unimplemented` NACK。
- [x] `M8-03` 实现 `OPEN/STDIN/OUTPUT/RESIZE/SIGNAL/EOF/EXIT/ERROR/CLOSE`，明确 PTY 合流 stdout/stderr 的语义。已交付：`src/core/shell_protocol.cpp`（PB bodies + 28 字节 RAW ShellData 头，`Limits::max_shell_data_bytes`/`max_shell_control_bytes` + wire 层拒绝）与 `src/client/shell_service.cpp` 全状态机；两个后端都合流 stdout/stderr，POSIX master 无半关闭故 EOF 以 EOT 表达、ConPTY 关输入管道（wire 文档 §6.3 M8 notes 已记录）。
- [x] `M8-04` Linux 使用受控 PTY/进程组，Windows 使用 ConPTY/job object；子进程 wait 与阻塞 I/O 纳入 executor worker 生命周期。已交付：`src/client/shell_pty.cpp` 第三个 executor 托管阻塞 worker（forkpty+进程组 / ConPTY+KILL_ON_JOB_CLOSE job object）；fork 前 ChildPlan 预构建（子进程仅 async-signal-safe 调用），exec 判决带 5s 上界，poll/WaitForMultipleObjects 单线程驱动全部会话；记录见 executor ledger 2026-09-03。
- [x] `M8-05` 实现合作取消 -> TERM/受控信号 -> 超时后终止进程树的升级策略，断线默认终止。已交付：worker 内 grace 升级（SIGTERM/CTRL_BREAK -> `terminate_grace` -> SIGKILL/TerminateJobObject），洪泛与输入背压跳过优雅阶段；会话断开走同一阶梯并审计 `session_closed`；worker 停止硬杀+有界回收（M8ShellPtyWorker.EscalationLadder/ShutdownReclaims 测试）。
- [x] `M8-06` 实现输出速率/缓冲上限、空闲/绝对时限和资源约束；control/exit 不得被 stdout 洪泛饿死。已交付：总量 `max_output_bytes`、暂存 `max_output_pending_bytes`（worker 与服务窗口双重）、待写 stdin `max_input_pending_bytes`、空闲/绝对时限全部由 worker 强制；事件队列满即停读 PTY 形成背压；SHELL_OUTPUT 走 interactive、EXIT/ERROR/CLOSE 走 standard 类，加权调度 + 每对等保留额度保证不被 bulk 洪泛饿死（M8ShellScheduler 测试钉死该性质）。
- [x] `M8-07` 审计只记录发起设备、profile、时间、退出码和字节数，默认不记录终端原始内容。已交付：`ShellAuditRecord`（仅元数据字段）经 AuditSink 进入 Node 有界（256 条）审计队列，`Node::shell_audit_records()` 只读；被拒绝的打开尝试同样入审计；类型层面不存在内容字段（M8ShellService.AuditNeverCarriesTerminalContent）。

## TUI 安全终端

- [x] `M8-08` 选用经过验证的 VT parser/terminal widget，记录版本和安全维护状态；不得把远端 bytes 直接写宿主终端。已交付：自研保守安全子集渲染器 `include/heyaki/shell_terminal.hpp`（版本 heyaki-shell-terminal/1，决策理由记录于本文件"关键实现决策"第 4 条与头文件注释；DEC-06 已在 decisions/m0-product-defaults.md 冻结）：不引入新第三方依赖（供应链/审计面最小），模型渲染而非透传，远端 bytes 永不写宿主终端。
- [x] `M8-09` 限制 OSC、剪贴板、标题修改、超长/未知 escape sequence；不支持的控制序列拒绝或安全降级显示。已交付：OSC（标题 0/2、剪贴板 52、超链接 8 等一切载荷）、DCS/SOS/PM/APC、DEC 私有序列、charset、超长（>max_sequence_bytes）或未知序列一律丢弃并计数；SGR 降级为纯文本；UTF-8 校验（非法字节替换 U+FFFD）；所有缓冲有界（M8SafeTerminal 套件 + m8_vt_terminal_parser 模糊目标）。
- [x] `M8-10` 实现 profile 选择、交互输入、resize、signal、EOF、exit status 和显式关闭。已交付：Node 公共 API（open_shell/shell_send_input/shell_resize/shell_signal/shell_send_eof/close_shell + 事件观察者）与 TUI `run_shell_view`（从会话授予 scope 列出候选 profile，`shell N` 进入，视图命令覆盖全部操作，输出经安全渲染器显示）。
- [x] `M8-11` TUI 退出/网络断开时按 profile 策略关闭 Shell，并等待 executor-managed operation 收敛。已交付：视图退出显式 close + 有界等待收敛；会话断开由 ShellService.handle_session_closed 走终止阶梯并等待 worker 回收（M8ShellService.SessionCloseTerminatesServingChildren、M8ShellPtyWorker.ShutdownReclaimsRunningChildren）。

## 安全测试与退出条件

- [x] 覆盖未授权/过期 grant、任意 executable/env 注入、输出洪泛、输入背压、resize storm、signal 竞争和断线进程树回收（m8_shell_test：OpenWithoutScope/UnknownProfile/WireOpenCannotOverride、OutputFlood、InputBackpressure、ResizeStorm、SignalPolicy、SessionClose、PeerClose；grant 过期即 scope 实时检查的默认拒绝路径）。
- [x] fuzz VT parser 和 Shell frame；恶意 OSC/escape 不触达宿主剪贴板、标题、文件或命令执行（m8_shell_frame_parser/m8_vt_terminal_parser 进入 libFuzzer 入口与 smoke 种子：OSC 剪贴板/标题、DCS、非法 UTF-8、超长序列；渲染器无任何宿主副作用面——纯内存模型）。
- [x] Linux PTY 生命周期测试通过（m8_pty_test：round-trip、升级阶梯、空闲超时、stdin 往返、shutdown 回收、spawn 失败）；exit 事件即 waitpid 回收证明，无僵尸。Windows ConPTY 路径已实现（ConPTY 动态解析 + job object + overlapped 管道），生命周期用例跨平台编写（cmd.exe 变体），由 CI Windows 矩阵验证。
- [x] 文件持续传输时 Shell 交互延迟满足冻结预算；退出和取消 control 帧始终有保留容量（M8ShellScheduler.BulkBacklogCannotStarveShellFrames 钉死 interactive/standard 对 bulk 的加权优先与提前穿插；control 保留额度沿 M5-04 既有性质）。
- [x] 独立安全评审签字后才允许生产构建启用 Shell；否则 v1 保持编译存在但配置默认禁用。（后半句已满足并测试：默认无 profile 即关闭、未配置 worker 的 borrowed runtime 打开请求以 failed_precondition 拒绝。签字：2026-09-04 用户批准——依据 [docs/security/m8-remote-shell-security-review.md](../security/m8-remote-shell-security-review.md)（无 P0/P1），放行条件为 P2-F2 先修复并 CI 全绿；F2 已修（PTY worker 会话上限拒绝现以 `spawn_failed`/`worker_session_limit` 事件可观测、`SHELL_ERROR` 透传失败 detail，`SessionLimitRefusalIsObservableNotSilent` 钉死），残余风险 P3-F4/P3-F5 已记入威胁模型；放行范围限 POSIX，Windows 待 P2-F1 路径校验修复，当前保持 fail-closed 禁用态。）

## 实施记录（2026-09-03）

交付物：`include/heyaki/shell.hpp`、`include/heyaki/shell_terminal.hpp`、
`src/core/shell_protocol.cpp`、`src/core/shell_terminal.cpp`、
`src/client/shell_pty.{hpp,cpp}`、`src/client/shell_service.{hpp,cpp}`、
runtime/node/TUI 接线（runtime 第三阻塞 worker、Node 公共 API 与审计队列、
`shell N` 视图）、`heyaki_m8_service_tests` 与两个新 fuzz 目标。
提交序列：ab255d2（主体交付）→ 1a69a30 → 36c4ec8 → ef5b50e → 1ba6b2d →
9585a74（Windows ConPTY 修复链）；最终 CI 全矩阵 10/10 job 绿。

### 逐轮工作日志

- **Round 1（协议与公共类型）**：`ShellId`（ids.hpp/ids.cpp，`hysh1_` 前缀）、
  `Limits::max_shell_data_bytes`/`max_shell_control_bytes`（含校验与 wire 层
  `shell_data_limit`/`shell_control_limit` 拒绝）、`include/heyaki/shell.hpp`
  （profile/scope/事件/审计/全部 wire body 声明）、`src/core/shell_protocol.cpp`
  （PB bodies 走 proto_codec、sint32 zigzag exit_code、28 字节 RAW ShellData）。
- **Round 2（PTY worker）**：`src/client/shell_pty.{hpp,cpp}`——第三个 executor 托管
  BlockingIoWorker；POSIX forkpty/进程组与 Windows ConPTY/job object 双后端；
  有界命令/事件 MpscChannel + wake 原语（POSIX self-pipe / Windows event）；升级阶梯、
  空闲/绝对时限、输出总量/暂存与输入 pending 上限全部在 worker 强制；runtime.cpp
  接线（条件启动、shutdown 顺序、RuntimeAccess 扩展）。
- **Round 3（ShellService 与 Node API）**：`src/client/shell_service.{hpp,cpp}`——
  wire §6.3 全状态机（偏移/resize 覆盖/EOF 幂等/exit 不可变/迟到帧计数）、scope 与
  per-profile 并发、内容无关审计、洪泛与输入背压终止；`node.cpp/hpp` 接线
  （ensure/teardown/prune/diagnostics、open_shell 等 6 个公共 API、有界审计队列）。
- **Round 4（安全 VT 渲染器）**：`include/heyaki/shell_terminal.hpp` +
  `src/core/shell_terminal.cpp`（自研 heyaki-shell-terminal/1：OSC/DCS/私有/未知
  序列丢弃计数、SGR 降级、UTF-8 校验替换、charset 单字节消费、全缓冲有界）。
- **Round 5（TUI）**：`apps/tui/main.cpp`——shell 事件通道、`run_shell_view`
  （按授予 scope 列 profile、open/文本即 stdin/resize/signal/eof/close/stats/view、
  输出经 SafeTerminalModel 渲染、退出显式 close + 有界收敛等待）、`shell N` 命令。
- **Round 6（测试与 fuzz）**：`tests/unit/m8_support.hpp`（M7 环形对 + ManualPtyDispatcher）
  与 codec/service/VT/PTY/调度公平五组用例；`m8_shell_frame_parser`/
  `m8_vt_terminal_parser` 进入 libFuzzer 入口与 smoke 种子；修正既有 NodeConfig
  全字段初始化测试（6 个文件 + TUI）。
- **Round 7（Linux 实测修复）**：三处实测缺陷——①fork 后子进程 malloc 死锁（arena 锁）
  → fork 前 ChildPlan 预构建、子进程仅 async-signal-safe 调用；②错误管道 dup2 后
  CLOEXEC 丢失导致长驻子进程挂死 exec 判决读 → 重设 FD_CLOEXEC + 5s 判决上界；
  ③快速退出子进程丢尾部输出 → harvest-before-reap（输出先于 exit 事件）。ASan 套件绿。
- **Round 8（Windows CI 修复链，与用户并行修复汇合）**：①MSVC `L'-o'` 多字符宽常量
  （1a69a30）；②ConPTY 不接受 overlapped 管道句柄（microsoft/terminal#262）→ 改文档化
  CreatePipe + PeekNamedPipe 轮询（36c4ec8）；③reap 后管道剩余输出丢失 → 最终排水
  （ef5b50e）+ conhost 异步冲洗静默窗口（9585a74）；④根因：宿主 stdout 被重定向时
  子进程继承重定向句柄绕过伪控制台（#11276）→ STARTF_USESTDHANDLES 清空 std 句柄
  （1ba6b2d，用户提交）。最终 Windows Debug/Release 全绿。

### 关键实现决策

1. **PTY 并发边界**：沿用 FileIoWorker 模式新增第三个 executor 托管阻塞 worker，
   命令/事件各有界 MpscChannel，事件由节点周期 tick 在 strand 上 drain；队列满时
   worker 停读 PTY，背压交给内核缓冲（EXEC-09 记录见 executor ledger）。
2. **fork 安全**：见 Round 7；该缺陷类别（多线程 fork + 子进程分配器）是 PTY 代理的
   经典坑，实现注释与 ledger 均有记录。
3. **输出先于回收**：exit 事件本身即 waitpid 完成的证明（无僵尸）；两侧后端都在
   exit 前做最终收割。
4. **VT 渲染器**：自研保守安全子集。理由：冻结 wire 协议明确允许"拒绝而非透传未知
   序列"；自研状态机使供应链与审计面最小，且 fuzz 不变量（有界、前进、字节全记账）
   可全量表达。未引入新第三方依赖。
5. **signal NACK 语义**：`SHELL_ERROR unimplemented` = 信号策略 NACK，shell 保持
   active；其余 status 终态关闭（与 wire §6.3 信号行/ERROR 行的表面冲突按此收敛，
   已写入 wire 文档 M8 notes）。

### 测试与验收

`heyaki_m8_service_tests` 交付时 45/45（codec 10、profile 2、service 17、调度 1、
VT 10、PTY 6，Windows 上 stdin 往返用例按平台跳过）；安全评审后 F2 修复新增
`SessionLimitRefusalIsObservableNotSilent`，现为 46/46。fuzz smoke 含 6 个 M8 种子；
本机全仓 ctest 51/51 绿 + m8 套件 ASan 绿；交付时 CI 全矩阵
（gcc/clang×Debug/Release、MSVC×2、asan/ubsan/tsan、coturn-topology）10/10 绿。

### 遗留（不阻塞 M8 关闭）

安全评审已签字（2026-09-04，记录见上），生产启用解禁（限 POSIX）；Windows 启用待 P2-F1
（profile 路径校验拒绝原生绝对路径）修复，评审硬化项 P4-F6..F9 随后续里程碑顺带处理。TUI
shell 视图为行式交互（与既有视图一致），全屏交互式终端不属于本里程碑范围；Windows stdin
交互往返用例以平台差异为由跳过，输出/生命周期路径已被其余用例覆盖。
