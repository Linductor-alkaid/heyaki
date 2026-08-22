# M5：会话授权、调度与 ByteStream

> - 状态：未开始
> - 所属计划：[Heyaki MVP 至 v1 实施 TODO 计划](heyaki-implementation-plan.md)
> - 前置：M4 | 建议发布点：会话安全 beta

## Framing 与通道调度

- [ ] `M5-01` 实现增量 frame encoder/decoder，覆盖 varint、最大长度、零拷贝所有权和未来 transport 兼容。
- [ ] `M5-02` 实现 control、pairing、message、RPC、event、file、shell 逻辑通道创建规则和各自默认可靠性/顺序选项。
- [ ] `M5-03` 实现每 peer 总预算、每 channel 字节/消息预算和控制帧保留额度；配置非法时启动失败。
- [ ] `M5-04` 实现加权调度：control/Shell > RPC/message > event/file，并以可重复 benchmark 验证无饥饿。
- [ ] `M5-05` 满队列按协议选择 `reject/drop-oldest/keep-latest`，向调用方返回 `would_block` 或可取消容量等待，禁止静默 drop。
- [ ] `M5-06` 实现 capability/版本协商和局部通道关闭；单个可选业务协议错误不应无条件破坏整个 session。

## Pairing 与 TrustGrant

- [ ] `M5-07` 完整实现 `PairingRestricted` 状态，只接受大小、时长、尝试次数受限的 pairing frame。
- [ ] `M5-08` pairing 发起方必须先在实际 DataChannel 上完成长期设备身份、endpoint、DTLS fingerprint 与 signaling transcript 验证；匿名 LAN/relay 来源不进入 pairing channel。
- [ ] `M5-09` 在端到端认证通道中提交密码、requested scopes 和一次性 nonce，目标用本地 Argon2id verifier 验证。
- [ ] `M5-10` 实现按来源设备、目标、连接/IP 的失败计数、指数退避和审计；不使用可被远程触发的永久全局锁死。
- [ ] `M5-11` 签发有方向的 TrustGrant，绑定双方 ID、scope、generation、grant ID、签发时间和可选 expiry。
- [ ] `M5-12` 实现 grant 出示、签名/范围/有效期/撤销检查，以及请求 scope、grant 与 endpoint/service policy 的交集裁决。
- [ ] `M5-13` 实现撤销、仅轮换密码、轮换并撤销旧 generation grant 三种明确操作。
- [ ] `M5-14` 会话升级后才允许创建业务通道；失败、禁用或超时发送稳定 `AUTH_DENIED` 并关闭受限会话。

## ByteStream

- [ ] `M5-15` 实现 `STREAM_OPEN/DATA/WINDOW_UPDATE/FIN/RESET` 和 stream ID/offset 校验。
- [ ] `M5-16` 实现接收字节与 frame 双重窗口；窗口耗尽时发送方停止产生 DATA，不只依赖 SCTP buffer。
- [ ] `M5-17` 实现 `async_read_some`、`async_write`、`shutdown_write` 和 `reset` 的 deadline/cancellation/partial completion 语义。
- [ ] `M5-18` 明确成功 write 只表示进入受控发送窗口，不表示对端应用读取；普通 stream 不跨重连自动恢复。
- [ ] `M5-19` TUI 配对与信任视图支持请求 scope、输入一次性密码、查看/撤销 grant 和密码轮换。
- [ ] `M5-20` TUI Stream 视图支持文本/十六进制收发、半关闭、reset、窗口和背压状态。

## 测试与退出条件

- [ ] pairing-only 越权、错误密码、重放 nonce、伪造 grant、过期/撤销 grant 和 endpoint scope 收窄全部默认拒绝。
- [ ] 在每种队列满载下 control cancel/window/close 仍可发送；文件或事件流量不能饿死 control。
- [ ] frame/stream parser fuzz 覆盖截断、重复、乱序 offset、窗口溢出、未知必需 frame 和跨 session epoch 迟到数据。
- [ ] 所有队列在持续过载测试中保持配置上限，RSS 无持续线性增长，drop/reject/timeout 与统计一致。
- [ ] 已授权设备重连无需再次输入密码；被撤销设备持有旧 grant 也无法恢复权限。
