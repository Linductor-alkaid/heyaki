# M8 Remote Shell 独立安全审计报告

- 审计日期：2026-09-04
- 审计对象：M8 Remote Shell 交付面（提交 ab255d2 起系列，最终 9585a74；CI 全矩阵 10/10 绿）
- 审计人：ZCode 代理审计（M8 里程碑退出条件要求的独立安全评审；本报告供人工批复参考，签字决定权在用户）
- 审计基线：master @ 37e59a4 工作区代码

## 0. 批复记录（2026-09-04）

用户批复：**放行 M8 生产启用（限 POSIX）**，条件为 P2-F2 先修复并 CI 全绿。

- F2 已修复（提交 9c73d9a）：PTY worker 会话上限拒绝现以
  `spawn_failed`/`worker_session_limit` 事件可观测，`ShellService` 把 worker 失败
  detail 透传到 `SHELL_ERROR`；新增 `M8ShellPtyWorker.SessionLimitRefusalIsObservableNotSilent`
  （46/46 绿，本机 ASan 亦绿），CI run 33786631870 全矩阵 10/10 绿
  （gcc/clang×Debug/Release、MSVC×2、asan/ubsan/tsan、coturn-topology；首轮
  linux-gcc-Release 挂在 m3b 中继 harness 的 TUI driver 超时——与本次改动无代码
  路径交集的既有抖动，重跑该 job 后绿）。
- Windows 保持 fail-closed 禁用态，待 P2-F1 修复（届时一并处理 P3-F3 与 P4-F7）。
- 残余风险 P3-F4（POSIX 进程组逃逸）与 P3-F5（会话期权限快照）已记入
  `docs/security/threat-model.md`，知情接受。
- P4-F6..F9 为硬化项，随后续触碰相关文件的里程碑顺带处理。

### 遗留处置记录（2026-09-05）

Windows 启用三件套已修复（M8 遗留任务，本仓库工作区）：

- **P2-F1 已修**：`validate_shell_profile` 按平台语法校验 argv[0]——Windows 接受盘符根
  （`X:\`/`X:/`）与 UNC 根（`\\server\share`），`/` 前缀（盘符相对形式）与 `..` 穿越
  两种语法下都保持拒绝；文法以 `valid_shell_executable_path(path, grammar)` 显式导出，
  双语法在所有平台可测（`M8ShellProfile.ExecutablePathGrammarPerPlatform`，含
  fail-closed 回归断言）。
- **P3-F3 已修**：Windows 下 `max_input_pending_bytes` 上限封顶为
  `kShellWindowsInputPendingCap`（128 KiB），与 `shell_pty.cpp` 创建 ConPTY 输入管道的
  缓冲共享同一常量（`M8ShellProfile.WindowsInputPendingCapMatchesConPTYPipe`）。
- **P4-F7 已修**：ConPTY 命令行改用规范 MSVCRT argv 转义
  （`quote_windows_argument`：引号转义、前置反斜杠run翻倍、空参数包裹），跨平台单测
  钉死转义规则；argv 仍仅来自操作员配置。
- **P4-F9 顺带修复**（shell_protocol.cpp 同文件随工）：`parse_shell_exit`/`parse_shell_close`
  对 status 增加闭合校验（1..14，拒绝 unspecified 与未知值），
  `M8ShellCodec.ExitAndCloseRejectUnknownStatusValues`。
- 测试基建同步：`shell_test_profile()` argv[0] 改为平台语法路径（否则 Windows CI 上
  既有用例会被新文法拒绝）。本机 M8 套件 49/49、全仓 ctest 51/51 绿；Windows 路径由
  CI 矩阵验证。
- 批复条件回顾：原批复"Windows 待 P2-F1 修复（届时一并处理 F3/F7）"的条件已满足；
  Windows 生产启用与 POSIX 同姿态（仅显式列 profile 的配置启用）。P4-F6（VT overlong
  UTF-8）与 P4-F8（审计 close_reason 语义）待后续触碰 `shell_terminal.cpp`/
  `shell_service.cpp` 的里程碑（M9-13 fuzz 扩展与可观测性工作）顺带处理。

## 1. 审计范围与方法

逐行精读 M8 全部交付物（约 5000 行 M8 专属代码），并追踪其接线点：

| 面 | 文件 |
| --- | --- |
| Profile 配置与校验 | `include/heyaki/shell.hpp`、`src/core/shell_protocol.cpp` |
| Wire 协议解析 | `src/core/shell_protocol.cpp`（+ `src/core/wire.cpp` 限额拒绝、`src/core/limits.cpp`） |
| 服务状态机与授权 | `src/client/shell_service.{hpp,cpp}` |
| PTY worker（双后端） | `src/client/shell_pty.{hpp,cpp}` |
| 安全 VT 渲染器 | `include/heyaki/shell_terminal.hpp`、`src/core/shell_terminal.cpp` |
| Node/TUI 接线与审计 | `src/client/node.cpp`、`src/client/runtime.cpp`、`apps/tui/main.cpp` |
| 测试与 fuzz | `tests/unit/m8_*.cpp`（45 项）、`tests/fuzz/*`（2 个 M8 目标 + 种子） |
| 文档一致性 | `docs/design/heyaki-wire-protocol.md` §6.3 M8 notes、`docs/security/threat-model.md`、`docs/executor-feedback-ledger.md` |

方法：对 todolist 声明的每条安全性质（M8-01..M8-11 及退出条件）定位实现并核实执行点；
对授权、注入、进程逃逸、资源耗尽、终端转义、审计泄漏六类威胁做定向攻击面检查；
对四个关键安全用例（OpenWithoutScope / WireOpenCannotOverride / AuditNeverCarriesTerminalContent /
OpenUnknownProfileAndDisabledWorkerFailClosed）核对断言体与名字一致。未重跑测试（CI 状态以记录为准）。

发现分级：**P0**（可利用漏洞，阻塞启用）/ **P1**（高危缺陷）/ **P2**（中危，建议启用前修复）/
**P3**（低危/残余风险，需记录）/ **P4**（硬化建议，不阻塞）。

## 2. 结论摘要

**未发现 P0/P1 级问题。** M8 声明的安全性质全部在代码中核实成立，且有对应测试钉死。
默认禁用姿态完整；授权路径默认拒绝且结构上不可从 wire 覆盖进程参数；资源上限双层强制；
VT 渲染器为纯内存模型、无宿主副作用面；审计记录类型层面不存在内容字段。

发现 2 项 P2、3 项 P3、4 项 P4（详见第 4 节）。其中：

- **P2-F1 阻塞 Windows 生产启用**（fail-closed，非漏洞）；Linux 启用不受影响。
- **P2-F2 是授权对等端可触发的活性缺陷**（静默丢弃 open 命令），修复成本低，建议启用前修。

**建议批复口径**：Linux 生产启用可在修复或书面接受 F2 后放行（F1 天然把 Windows 挡在禁用态，
不构成风险）；三项 P3 作为残余风险记入威胁模型即可。

## 3. 声明性质逐条核实（全部通过）

1. **默认禁用（M8-01）** ✓ — `NodeConfig::shell_profiles` 为空则不启动 PTY worker
   （`node.cpp:5969` 仅在非空时置 `shell_pty_worker_enabled`）；borrowed runtime 无 worker 时
   `ShellService` 收到 open 以 `failed_precondition shell_disabled` 拒绝（`shell_service.cpp:614`）；
   `deploy/` 无任何 shell 配置；TUI 构造节点显式 `shell_profiles = {}`（`main.cpp:1844`）。
   测试 `OpenUnknownProfileAndDisabledWorkerFailClosed` 覆盖两条路径。
2. **实时 scope 检查、默认拒绝（M8-02）** ✓ — spawn 前调用 `scope_check_(shell_open_scope(profile))`，
   接线为 `session_scope_covers(*session, scope)`（`node.cpp:3335`）：遍历会话当前
   `authorized_scopes()` 精确/一层通配匹配，空集合即拒绝。scope 集合来自
   `trust_authorizer(now)` 实时裁决（`peer_session.cpp:590` 区域），未授权会话 `authorized_scopes` 被清空。
   拒绝路径同样入审计（测试断言 `scope_rejected==1` 且审计记录 0 字节、无内容字段）。
3. **结构性不可覆盖 executable/env（M8-02）** ✓ — wire `ShellOpenBody` 无 executable/env/user/cwd 字段
   （`shell.hpp:207-214`）；`build_spawn_spec`（`shell_service.cpp:62-98`）只从本地
   `ShellProfileConfig` 取进程参数；请求方可影响的仅 `TERM`/`LANG` 两个固定名，值经
   `safe_terminal_type`（`[A-Za-z0-9._-]`）/`safe_locale`（加 `@`、`=`）字符集校验，
   且本地 profile 规则排在其后可覆盖。execve/env 块按 (name,value) 对构造，无字符串拼接注入面。
   测试 `WireOpenCannotOverrideProgramOrEnvironment` 断言 spec 全字段等于本地配置。
4. **Profile 校验（M8-01）** ✓ — 名称 `[a-z0-9-]` 有界（64B）；argv 无 NUL、≤4096B、argv[0] 绝对路径
   且无 `..`；并发 ∈[1,16]；超时正且 idle≤absolute；grace ∈(0,60s]；输出/暂存/输入上限为正且有序；
   env 名字符集安全、≤64 条、值无 NUL；信号枚举闭合。Node 启动（`node.cpp:6036`）与
   `ShellService::attach` 双重校验，失败即拒绝启动。
5. **Wire 解析健壮（M8-03）** ✓ — protobuf 体经共享极简 codec（拒绝尾字节、超长、非规范 varint）；
   所有控制体受 `max_shell_control_bytes`（wire 层 + codec 双检查）；`ShellData` 28 字节头精确
   长度匹配、`max_shell_data_bytes` 上限、零 ID 拒绝；columns/rows ∈[1,1024]（resize storm 在解析层
   有界 + worker 侧 best-effort）；signal 枚举闭合；`safe_detail` ≤256 且无控制字节
   （error 通道不能携带终端转义序列）。
6. **状态机纪律（wire §6.3）** ✓ — 双向偏移严格连续（重复幂等、gap/conflict 终态关闭）、EOF 幂等、
   EOF 后输入为协议违规并终止、exit 不可变（`finish_terminal` 早退）、迟到帧计数忽略、
   终态记录保留有界（`max_retained_terminal=64`）。
7. **资源上限双层强制（M8-06）** ✓ — worker 层：总输出预算、暂存输出界（事件队列满即停读该会话 PTY，
   背压交内核缓冲，超界洪泛终止）、待写 stdin 界、空闲/绝对时限；service 层：256KiB 输出窗口超界
   洪泛终止。EXIT/ERROR/CLOSE 走 standard 帧类不排在交互输出之后（`M8ShellScheduler.
   BulkBacklogCannotStarveShellFrames` 钉死）。
8. **进程控制（M8-04/M8-05）** ✓ — 单 executor 托管阻塞 worker 拥有全部子进程；POSIX forkpty
   会话首进程 + 进程组信号；ChildPlan fork 前物化，子进程仅 async-signal-safe 调用（无 fork 后
   malloc）；exec 判决 pipe CLOEXEC 语义正确（dup2 后重设）+ 5s 上界；os_user 切换仅 root、
   非 root 只许自身，`setgroups(1,gid)` 清补充组；Windows ConPTY 动态解析 +
   `KILL_ON_JOB_CLOSE` job object + 挂起启动后 assign + 清空 std 句柄（防重定向继承绕过 PTY）；
   升级阶梯（graceful → grace → SIGKILL/TerminateJobObject），洪泛/输入背压跳过优雅阶段；
   worker 停止硬杀 + 每子进程 2s 有界回收；exit 事件即 waitpid 证明（无僵尸）。
   会话断开走同一阶梯并审计（`SessionCloseTerminatesServingChildren`、`ShutdownReclaimsRunningChildren`）。
9. **安全终端（M8-08/M8-09）** ✓ — `SafeTerminalModel` 纯内存模型，无任何系统调用/剪贴板/标题/文件面；
   OSC（含剪贴板 52、标题 0/2、超链接 8 的一切载荷）、DCS/SOS/PM/APC、DEC 私有、charset、
   未知序列一律丢弃并计数；SGR 降级纯文本；UTF-8 校验非法替换 U+FFFD；全缓冲有界
   （scrollback 4096 行、每行 columns×12 字节上限、序列缓冲 4096B 超限整段丢弃重同步）；
   TUI 输出仅经 `render_tail` 以文本行显示，远端字节永不写宿主终端。
   fuzz 目标 `m8_vt_terminal_parser` 含剪贴板/标题/DCS/非法 UTF-8/超长种子。
10. **内容无关审计（M8-07）** ✓ — `ShellAuditRecord` 仅元数据字段（类型层面无内容成员，测试以
    static_assert + 值断言双钉）；授予与拒绝的打开均入审计；Node 侧 256 条有界队列、只读访问器。
11. **并发边界合规** ✓ — 无 std::thread/async/自制池；命令/事件各有界 MpscChannel + wake 原语 +
    PhaseGate 退出；executor ledger 2026-09-03 条目记录完整（EXEC-09，无新增 executor 缺口）。

## 4. 发现清单

### P2-F1：`validate_shell_profile` 拒绝一切 Windows 原生绝对路径（阻塞 Windows 启用，fail-closed）

- 位置：`src/core/shell_protocol.cpp:192-197`（`executable.front() != '/'` 无平台条件）。
- `Node::create`（`node.cpp:6036`）对每个 profile 强制该校验。Windows 原生路径
  `C:\Windows\System32\cmd.exe` 不以 `/` 开头 → 配置含真实 Windows 路径的节点无法启动 shell
  （fail-closed，无安全后果），而 `/` 前缀路径对 `CreateProcessW` 是未定义的驱动器相对形式。
- 证据：Windows CI 的 ConPTY 生命周期测试（`m8_pty_test.cpp:108` 用 `C:\...`）走 worker 层
  spec、绕过 profile 校验，所以矩阵全绿掩盖了该层缺口。
- 建议：启用 Windows 前加平台条件（Windows 接受盘符 `X:\`/`X:/` 与 UNC `\\`，保留 `..` 拒绝）。
  在此之前 Windows 生产启用天然被挡（可视为默认禁用的额外保障），**不构成放行 Linux 的阻塞项**。

### P2-F2：PTY worker 24 会话上限静默丢弃 open 命令（授权对等端可触发的活性缺陷）

- 位置：`src/client/shell_pty.cpp:961-965`（`sessions.size() >= kWorkerSessionLimit` 时 `break`，
  不发任何事件）。
- 触发面：service 层并发检查是 per-profile（≤16/Profile），worker 层全局上限 24；多 profile 配置
  （Σ max_concurrent_sessions > 24）下，授权对等端开满 24 个存活 shell 后，后续 open 命令被
  worker 静默丢弃——`ShellService` 已登记 record 并发出 `opening` 事件，但永远等不到
  `started`/`spawn_failed`，客户端该 shell 无限挂起且无错误可观察（服务层无 open 超时）。
- 影响评估：无越权、无资源泄漏（record 受并发计数约束有界），但违反仓库
  "Do not accept silent task or message loss" 原则，且是授权端不需恶意构造即可触发的活性洞。
- 建议：启用前修复——拒绝时 emit `spawn_failed`（detail `worker_session_limit`），或把
  worker 上限纳入 service 层准入。修复量约 5 行。

### P3-F3：Windows stdin `WriteFile` 在管道满时可阻塞整个 worker（依赖操作员配置）

- 位置：`src/client/shell_pty.cpp:535`（`kInputPipeBytes = 128 KiB`）、`929-951`（同步 WriteFile）。
- 注释假设管道缓冲 ≥ 待写 stdin 预算，这只对默认 64 KiB 成立；`validate_shell_profile` 未约束
  `max_input_pending_bytes` 相对 128 KiB 的上界。操作员配大预算 + 子进程停止排水 → 单线程 worker
  卡死在 `WriteFile`，全部 shell 停摆、shutdown 的 PhaseGate 等待超时。POSIX 路径 O_NONBLOCK 不受影响。
- 建议：校验层加 `max_input_pending_bytes ≤ 128 KiB`（或写侧按管道容量分块）。启用前修一行校验
  即可消除；否则记入已知限制。

### P3-F4：POSIX 进程组不能约束自行 `setsid`/守护化的子孙进程（平台固有，需记入威胁模型）

- `kill(-pid)` 只覆盖进程组；孙进程调用 `setsid()`（如用户在 shell 里跑 `setsid ...` 或守护化
  程序）后脱离升级阶梯的 SIGKILL 范围。这是无 cgroup 的 PTY 方案的经典局限（OpenSSH 同）；
  Windows job object 无此问题（无 breakaway 权限时全树覆盖）。
- 现有缓解：绝对时限（默认 1h）不适用于逃逸进程本身；会话断开终止只达组内。
- 建议：在 `docs/security/threat-model.md` 显式记录该残余风险与操作员缓解（限制 profile 程序、
  最小权限 os_user）；pidfd/namespace 属后续里程碑。**批复时应知情接受此条。**

### P3-F5：grant 过期不回收已开 shell（与会话期权限模型一致的既定语义，需记入威胁模型）

- scope 检查查会话升级时裁决的 `authorized_scopes` 快照；grant 在会话存续期间过期不会使已开
  shell 终止。现有缓解：会话生命周期本身有限 + profile 空闲/绝对时限（默认 1h 硬上限）+
  断线终止。与 message/RPC/file/event 四服务的授权姿态完全一致（非 M8 引入的偏差）。
- 建议：威胁模型补一句会话期权限快照语义；如需更紧可在后续里程碑加会话级重裁决。

### P4 硬化建议（不阻塞启用）

- **P4-F6**：VT 渲染器接受非规范 overlong UTF-8（`E0 80-9F..`/`F0 80-8F..` 起始）。
  仅显示模型、重编码为规范形式、无下游解释面（TUI 无复制到 shell 的集成），无实际利用路径；
  建议为严格性补起始字节范围检查（2 字节 overlong 已被 `>=0xC2` 起始检查排除）。
- **P4-F7**：ConPTY 命令行拼接对含 `"` 的参数只包裹不转义（`shell_pty.cpp:599-612`）。
  argv 仅来自操作员配置（wire 不可达），无注入面；建议 Windows 侧校验拒绝 argv 含 `"` 或做
  规范转义。
- **P4-F8**：scope 拒绝/未知 profile 的审计 `close_reason` 记为 `protocol_error`，语义上是
  权限拒绝；建议增设独立 reason（或改用 `terminated`），便于审计离线分析。
- **P4-F9**：`parse_shell_exit`/`parse_shell_close` 对 `status` 字段未验证枚举值
  （任意 u64 直接 cast 为 `StableStatus`）；客户端侧 switch 有 default 兜底，无行为危害，
  建议加闭合校验以保持协议面一致。

## 5. 启用建议（供批复参考）

| 事项 | 建议 |
| --- | --- |
| Linux 生产启用（配置显式列 profile 前提下） | **可放行**；建议先修 P2-F2（5 行），或书面接受该活性缺陷 |
| Windows 生产启用 | **暂缓**，P2-F1 修复前无法配置合法路径（当前即 fail-closed 禁用态）；修复 F1 时一并处理 P3-F3/P4-F7 |
| 威胁模型更新 | 记录 P3-F4（进程组逃逸）、P3-F5（会话期权限快照）两条残余风险 |
| 配置基线 | 首个生产 profile 建议：`max_concurrent_sessions` 取小值（1-2）、`allowed_signals` 保持默认 {int, term}、`absolute_timeout` ≤1h、`os_user` 用非特权账户 |
| 后续硬化 | P4-F6..F9 随下一个触碰这些文件的里程碑顺带处理 |

## 6. 审计限制

- 静态审计 + 测试/文档核对；未重跑测试矩阵（以 CI 记录 33768920608 全绿为准）。
- 未做跨版本互操作、性能与全屏交互式终端（明示不在 M8 范围）评估。
- executor 依赖本身按 pin 版本视作已审计边界（ledger 无未决缺口）。
