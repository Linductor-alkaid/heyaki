# M6：消息与 Unary RPC

> - 状态：未开始
> - 所属计划：[Heyaki MVP 至 v1 实施 TODO 计划](heyaki-implementation-plan.md)
> - 前置：M5 | 建议发布点：v0.2 Service MVP

## 消息服务

- [ ] `M6-01` 定义并实现 `MessageEnvelope`、类型/schema version、TTL、headers、payload 和 delivery mode 限制。
- [ ] `M6-02` 实现 `best_effort`：进入有界 transport 队列即完成，断线/过载语义明确。
- [ ] `M6-03` 实现 `peer_acked`：对端协议层基本校验后 ACK，不宣称 handler 已执行或数据已持久化。
- [ ] `M6-04` 实现按 message ID 的有界 TTL 去重缓存，记录 duplicate、expiry 和容量耗尽。
- [ ] `M6-05` 每个 message handler 检查 `message.send` scope，并通过 executor 普通任务派发；保存 future 并处理异常/拒绝。
- [ ] `M6-06` 目标离线立即返回 `peer_offline`，v1 不创建本地或 relay 离线队列。

## Unary RPC

- [ ] `M6-07` 实现 service registry、method descriptor、schema version 和每 method scope/policy。
- [ ] `M6-08` 实现 request/response/cancel frame、相对 deadline、metadata、payload 和架构规定的 RPC status code。
- [ ] `M6-09` handler 通过有界 executor 提交；admission 拒绝或并发超限返回 `resource_exhausted`，执行异常映射为安全 `internal`。
- [ ] `M6-10` handler 接收协作取消信号；deadline 到期不假装强杀运行中 C++ 代码，迟到结果不进入已结束 request。
- [ ] `M6-11` 实现 session 内近期 request ID 结果缓存，提供配置化 at-most-once 窗口并限制内存。
- [ ] `M6-12` 连接中断时非幂等请求返回 `outcome_unknown`，绝不自动重试；仅显式幂等且 deadline 允许时执行策略化重试。
- [ ] `M6-13` v1 此阶段只开放 unary RPC；streaming API 保持未实现并返回 `unimplemented`，不交付半成品语义。

## TUI 与文档

- [ ] `M6-14` TUI 消息视图支持 typed payload、TTL、delivery mode、ACK 和结构化失败。
- [ ] `M6-15` TUI RPC 视图支持 descriptor/raw payload、deadline、取消、状态和结果；无 descriptor 时不假定 JSON 可用。
- [ ] `M6-16` 编写消息/RPC API 示例，明确 admission、completion、ACK、handler success 和 `outcome_unknown` 的差异。

## 测试与 Service MVP 退出条件

- [ ] 覆盖 ACK 丢失、重复 message、TTL 到期、handler 抛异常、executor 满载、deadline/cancel 竞争和迟到响应。
- [ ] 非幂等 RPC 在请求已发出后断线稳定返回 `outcome_unknown`；测试证明库未偷偷执行第二次。
- [ ] 未授权 method、未知 service/method、schema 不兼容和超大 payload 在 handler 前被拒绝。
- [ ] direct 与 TURN 两条路径使用同一消息/RPC 测试集，业务代码不按 path 分支。
- [ ] TUI 通过公共 API 完成配对、消息和 RPC 端到端流程，无私有协议捷径。
