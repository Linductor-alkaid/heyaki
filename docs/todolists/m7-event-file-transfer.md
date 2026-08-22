# M7：远程事件与文件传输

> - 状态：未开始
> - 所属计划：[Heyaki MVP 至 v1 实施 TODO 计划](heyaki-implementation-plan.md)
> - 前置：M6 | 建议发布点：v0.3 Data beta

## 远程事件

- [ ] `M7-01` 实现精确 topic 和受控前缀匹配、publisher sequence、event ID、schema version、timestamp、QoS 和 payload。
- [ ] `M7-02` 实现 `best_effort_latest`，每订阅者只保留最新值并暴露 overwrite/stale/lag。
- [ ] `M7-03` 实现 `reliable_live`，只承诺当前连接内可靠，不补发断线历史。
- [ ] `M7-04` 每个远程订阅者有独立有界队列和 scope；慢订阅者不阻塞发布者或其他订阅者。
- [ ] `M7-05` 实现本地 `executor::comm::Topic<T>` 到远程事件的显式 bridge，类型和命名上区分本地 fan-out 与网络协议。
- [ ] `M7-06` 配置单设备远程订阅者/连接上限；超限明确拒绝，不把 relay 扩展为业务 Broker。
- [ ] `M7-07` TUI 事件视图支持 topic 浏览、订阅/取消、测试发布和 sequence/drop/lag 展示。

## 文件协议与安全写入

- [ ] `M7-08` 实现 file manifest、transfer ID、逻辑文件名、大小、BLAKE3、协商块大小和 metadata。
- [ ] `M7-09` 接收端在收数据前执行 `file.push/pull:<root>` scope、root mapping、单文件/总空间/并发/用户配额检查。
- [ ] `M7-10` 拒绝绝对路径、`..`、NUL、Windows device name、越界 symlink 和目录穿越；使用抗 symlink race 的平台文件 API。
- [ ] `M7-11` 实现临时文件、受限权限、块 offset/校验、bitmap 或连续 offset、整体 BLAKE3、flush/fsync 和原子 rename。
- [ ] `M7-12` 文件读写由 executor-managed Blocking I/O worker 管理，哈希等有限 CPU 工作通过普通 executor task；结果/failure 均有明确完成边界。
- [ ] `M7-13` 实现暂停、取消、断线持久化和按 transfer ID 恢复；旧 session frame 不能污染恢复后的 transfer。
- [ ] `M7-14` 实现有界发送窗口和限速，使 control/Shell/RPC 预算不被文件占满。
- [ ] `M7-15` 可选 zstd 只有在 manifest 明示且限制解压后大小时启用；默认关闭。
- [ ] `M7-16` TUI 文件视图展示逻辑 root、push/pull、进度、吞吐、暂停、取消、恢复和失败，不伪装远端绝对文件系统。

## 测试与退出条件

- [ ] event 慢订阅者、keep-latest 覆盖、reliable-live 断线和大规模 fan-out 上限的行为与统计一致。
- [ ] 在任意块边界、manifest 后、fsync 前和 rename 前强制断开/终止，恢复后文件 BLAKE3 正确且无越界写入。
- [ ] 覆盖磁盘满、配额竞争、hash 错误、重复块、恶意块长度、symlink race 和 Windows 特殊路径。
- [ ] 文件占满链路时 control/RPC 保持可用，调度 benchmark 达到 M1 冻结的延迟预算。
- [ ] direct/relay 路径均能完成事件和文件测试；relay/TURN 无法恢复文件明文。
