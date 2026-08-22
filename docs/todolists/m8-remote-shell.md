# M8：Remote Shell

> - 状态：未开始（独立安全里程碑，默认关闭）
> - 所属计划：[Heyaki MVP 至 v1 实施 TODO 计划](heyaki-implementation-plan.md)
> - 前置：M7 | 建议发布点：v0.4 Shell beta

## 服务端 Shell

- [ ] `M8-01` 定义 `ShellProfile`：固定程序、OS 用户、工作目录、环境 allowlist、资源、空闲和绝对时限；默认配置无 profile。
- [ ] `M8-02` 实现独立 scope `shell.open:<profile>`、本地 `ShellAuthorizer` 和并发会话限制，请求方不能覆盖 executable 或任意环境变量。
- [ ] `M8-03` 实现 `OPEN/STDIN/OUTPUT/RESIZE/SIGNAL/EOF/EXIT/ERROR/CLOSE`，明确 PTY 合流 stdout/stderr 的语义。
- [ ] `M8-04` Linux 使用受控 PTY/进程组，Windows 使用 ConPTY/job object；子进程 wait 与阻塞 I/O 纳入 executor worker 生命周期。
- [ ] `M8-05` 实现合作取消 -> TERM/受控信号 -> 超时后终止进程树的升级策略，断线默认终止。
- [ ] `M8-06` 实现输出速率/缓冲上限、空闲/绝对时限和资源约束；control/exit 不得被 stdout 洪泛饿死。
- [ ] `M8-07` 审计只记录发起设备、profile、时间、退出码和字节数，默认不记录终端原始内容。

## TUI 安全终端

- [ ] `M8-08` 选用经过验证的 VT parser/terminal widget，记录版本和安全维护状态；不得把远端 bytes 直接写宿主终端。
- [ ] `M8-09` 限制 OSC、剪贴板、标题修改、超长/未知 escape sequence；不支持的控制序列拒绝或安全降级显示。
- [ ] `M8-10` 实现 profile 选择、交互输入、resize、signal、EOF、exit status 和显式关闭。
- [ ] `M8-11` TUI 退出/网络断开时按 profile 策略关闭 Shell，并等待 executor-managed operation 收敛。

## 安全测试与退出条件

- [ ] 覆盖未授权/过期 grant、任意 executable/env 注入、输出洪泛、输入背压、resize storm、signal 竞争和断线进程树回收。
- [ ] fuzz VT parser 和 Shell frame；恶意 OSC/escape 不触达宿主剪贴板、标题、文件或命令执行。
- [ ] Linux PTY 与 Windows ConPTY 生命周期测试通过，无僵尸进程、遗留 job 或 executor worker。
- [ ] 文件持续传输时 Shell 交互延迟满足冻结预算；退出和取消 control 帧始终有保留容量。
- [ ] 独立安全评审签字后才允许生产构建启用 Shell；否则 v1 保持编译存在但配置默认禁用。
