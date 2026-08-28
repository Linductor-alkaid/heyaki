# M5：会话授权、调度与 ByteStream

> - 状态：已完成（第 1 轮实施 + 第 2 轮收尾 + 第 3 轮 CI 修复：默认拒绝、
>   配对/TrustGrant、调度与 ByteStream 交付，CI 全绿收官，2026-08-28）
> - 所属计划：[Heyaki MVP 至 v1 实施 TODO 计划](heyaki-implementation-plan.md)
> - 前置：M4 | 建议发布点：会话安全 beta

## Framing 与通道调度

- [x] `M5-01` 实现增量 frame encoder/decoder，覆盖 varint、最大长度、零拷贝所有权和未来 transport 兼容。
  - `include/heyaki/frame_stream.hpp` + `src/core/frame_stream.cpp`：`FrameStreamDecoder`
    以任意字节边界投递解析冻结帧布局（拆分/合并均支持，逐字节与任意切分点测试），
    声明长度在保留前校验，保留上限为一个最大帧；`take_frame()` 在整缓冲单帧时零拷贝移出。
    `FrameStreamEncoder` 支持先写头再补 payload 的增量编码。
    域级 payload 上限检查与一次性 parser 共享（`wire.hpp` 导出
    `frame_payload_limit_error`）。libFuzzer `heyaki_frame_parser_fuzzer`
    增加该 decoder 与 pairing/trust-grant parser 目标。
- [x] `M5-02` 实现 control、pairing、message、RPC、event、file、shell 逻辑通道创建规则和各自默认可靠性/顺序选项。
  - `src/client/session_channels.hpp/cpp`：channel 0 为控制通道（session/pairing/
    liveness 帧共用）；业务帧走非零逻辑通道，每通道绑定单一域；发起方占用奇数
    channel id、响应方偶数，双方无需协商即可开通道。`default_frame_class` 给出每类
    帧的调度级别；`PeerSession::ensure_physical_channel` 为每域提供默认
    reliability/ordering/优先级物理通道选项（transport::ChannelKind 新增 `stream`）。
- [x] `M5-03` 实现每 peer 总预算、每 channel 字节/消息预算和控制帧保留额度；配置非法时启动失败。
  - `ChannelBudgetConfig` + `validate_channel_budget_config`（PeerSession::create 与
    ByteStreamService::attach 前置校验，非法即失败）；控制类帧独立记账，永不占用
    业务预算；peer 预算耗尽一律 would_block（测试 `PeerBudgetExhaustionAlwaysRejects`）。
- [x] `M5-04` 实现加权调度：control/Shell > RPC/message > event/file，并以可重复 benchmark 验证无饥饿。
  - 权重 8:8:4:1 的 deficit 加权轮转：控制类最高优先；所有有积压类别 token 耗尽时
    统一补充，保证 bulk 在持续控制负载下仍有非零份额、控制帧永不被 bulk 积压卡死。
    可重复基准 `tests/performance/m5_scheduler_benchmark.cpp`（固定种子/帧型/轮数）：
    20000 轮 control+bulk 混合，control 零赤字、bulk 全部发出，输出
    `M5_SCHEDULER_OK`；单测 `ControlFramesFlowWhileBulkBacksUp`、
    `BulkIsNotStarvedUnderContinuousControlLoad` 覆盖双向无饥饿。
- [x] `M5-05` 满队列按协议选择 `reject/drop-oldest/keep-latest`，向调用方返回 `would_block` 或可取消容量等待，禁止静默 drop。
  - `QueueFullPolicy` 按通道语义选择；reject 返回 would_block 并可注册
    `CapacityWaitTicket`（容量出现即完成、销毁/取消即回执 cancelled，各恰好一次）；
    drop-oldest 淘汰本通道最旧一帧并计数；keep_latest 每次入队先清旧帧（只保留最新，
    latest-only 语义）。所有 drop/reject/wait 计数进入 `ChannelQueueStats`。
- [x] `M5-06` 实现 capability/版本协商和局部通道关闭；单个可选业务协议错误不应无条件破坏整个 session。
  - 业务域帧必须协商出对应 capability bit 才可流动（`capability_for_domain`）；
    未知可选帧跳过不改状态；未知 REQUIRED 帧只关闭其逻辑通道；未注册通道的入站帧
    交给域处理器学习（对端发起的 stream 通道由 ByteStreamService 收养）；
    `close_business_channel` 只丢弃本通道队列与等待。随机化测试
    （`RandomizedMisbehavingDataNeverCorruptsTheSession`，64 轮 × 6 类敌意输入）
    验证会话与传输始终存活。

## Pairing 与 TrustGrant

- [x] `M5-07` 完整实现 `PairingRestricted` 状态，只接受大小、时长、尝试次数受限的 pairing frame。
  - hello 验证后未受信会话进入 pairing_restricted：仅接受 channel 0 的
    PAIRING_REQUEST/RESULT 与 liveness 帧；payload ≤ `max_pairing_payload_bytes`、
    会话内尝试 ≤ `max_pairing_attempts_per_session`（`PairingRequestAdmission`），
    受限会话生命周期受 `pairing_deadline`（默认 60s，惰性到期检查，测试注入时钟）。
- [x] `M5-08` pairing 发起方必须先在实际 DataChannel 上完成长期设备身份、endpoint、DTLS fingerprint 与 signaling transcript 验证；匿名 LAN/relay 来源不进入 pairing channel。
  - pairing 帧仅在 `SessionHelloAdmission` 接受签名 hello（transcript/nonce/epoch/
    fingerprint 绑定已在 M4 冻结）之后处理；hello 前的 pairing 帧以
    `pairing_frame_before_hello` 关闭会话；匿名 discovery/TLS 来源本就不存在已验证
    会话，无法投递 pairing 帧。
- [x] `M5-09` 在端到端认证通道中提交密码、requested scopes 和一次性 nonce，目标用本地 Argon2id verifier 验证。
  - `PairingRequestBody`（request_id + 32B 一次性 nonce + 密码 + scopes）仅在
    channel 0 端到端密文内传输；`PairingService::evaluate` 用 `verify_password`
    （Argon2id，密码库常量时间比较）验证；发起方 `PairingService::accept_grant`
    校验签名/双方身份/nonce 回显/scope 子集后持久化 received grant。
- [x] `M5-10` 实现按来源设备、目标、连接/IP 的失败计数、指数退避和审计；不使用可被远程触发的永久全局锁死。
  - 每来源设备失败表（有界 256 项，满则按最旧淘汰）：阈值（默认 3）后指数退避
    （base×2^n，封顶），验证成功清零；退避期内在密码验证前即拒绝
    resource_exhausted。结构化审计事件（attempt/denied_*/granted/rotated/...）
    不含密码、verifier 或签名字节。按 IP/连接的维度在 transport 侧（LAN provision
    与 relay 限速已在 M3/M4 落地），本层以来源设备为键。
- [x] `M5-11` 签发有方向的 TrustGrant，绑定双方 ID、scope、generation、grant ID、签发时间和可选 expiry。
  - `SignedTrustGrant` 按冻结域 `heyaki.trust-grant.v1` 规范化签名（含 U16 范围的
    scope-list 编码，与 `signing.cpp` 的域规则一致）；目标存 issued、发起方存
    received，方向不可互换。
- [x] `M5-12` 实现 grant 出示、签名/范围/有效期/撤销检查，以及请求 scope、grant 与 endpoint/service policy 的交集裁决。
  - 会话建立与协议 1.2 重启会话均经 `PairingService::authorize`：以本地 TrustStore
    为最终裁决（issued subject==peer 与 received issuer==peer 两个方向的有效 grant
    取并集）；`adjudicate_trust_scopes` 求请求 ∩ grant ∩ 本地策略交集，空交集即拒绝。
    被撤销/过期 grant 不参与裁决。
- [x] `M5-13` 实现撤销、仅轮换密码、轮换并撤销旧 generation grant 三种明确操作。
  - `revoke_grant`（单个撤销）；`rotate_password`（新 verifier + generation+1，既有
    grant 保持有效——ProfileStore 信任基准已从"当前 generation 等值"改为"未撤销且
    未过期"，`trust_grants_for_peer` 查询）；`rotate_password_and_revoke_grants`
    （额外撤销旧 generation 的全部 issued grant）。TUI 提供两个轮换命令。
- [x] `M5-14` 会话升级后才允许创建业务通道；失败、禁用或超时发送稳定 `AUTH_DENIED` 并关闭受限会话。
  - `open_business_channel`/`send_frame` 要求 authorized；错误密码/策略拒绝/限流/
    超时/禁用均以稳定 `pairing_denied`（或 pairing_rate_limited/timeout）关闭受限
    会话，拒绝结果帧携带稳定 StableStatus。未受信会话的业务帧第一起关闭违规通道、
    第二起关闭会话（wire 6.1）。

## ByteStream

- [x] `M5-15` 实现 `STREAM_OPEN/DATA/WINDOW_UPDATE/FIN/RESET` 和 stream ID/offset 校验。
  - `src/client/byte_stream.hpp/cpp`：OPEN 固定流 ID 与对端接收窗口；DATA 仅接受
    严格下一 offset（重复幂等、间隙/冲突 RESET）；WINDOW_UPDATE 仅接受单调
    consumed offset（陈旧忽略、超越已发偏移即 RESET）；FIN final offset 必须等于
    已收末尾；RESET 精确失败该流且幂等。
- [x] `M5-16` 实现接收字节与 frame 双重窗口；窗口耗尽时发送方停止产生 DATA，不只依赖 SCTP buffer。
  - 接收侧同时执行字节与帧窗口（超限 RESET resource_exhausted）；发送侧以对端
    credit（OPEN + WINDOW_UPDATE 授予）为闸，耗尽即停止产生 DATA；应用读取后按
    累计消费回报 WINDOW_UPDATE（≥窗口 1/4 或耗尽时回报）。
- [x] `M5-17` 实现 `async_read_some`、`async_write`、`shutdown_write` 和 `reset` 的 deadline/cancellation/partial completion 语义。
  - 读可短读、EOF 零字节无错；写完成携带已进入发送窗口的字节数，deadline 到期以
    partial 字节 + timeout 完成并从队列移除；`check_deadlines` 由服务活动驱动，
    时钟可注入；reset 一次失败整流（读写全部回执）。
- [x] `M5-18` 明确成功 write 只表示进入受控发送窗口，不表示对端应用读取；普通 stream 不跨重连自动恢复。
  - 写完成语义在实现与 TUI/测试注释中显式声明；ByteStreamService 析构与服务
    `fail_all` 使全部读写以错误收尾，流注册表清空；流对象不跨会话存续。
- [x] `M5-19` TUI 配对与信任视图支持请求 scope、输入一次性密码、查看/撤销 grant 和密码轮换。
  - `pair N`（隐藏输入目标密码，按 DEC-04 只读模板请求 scopes，observer 报告
    granted scopes / 稳定拒绝）；`trust N`（列 issued/received grant、generation、
    scopes、撤销状态）；`revoke N M`；`rotate-password` 与
    `rotate-password-revoke`（二次确认；本地初始化默认 pairing policy 安装同一
    只读模板 scopes）。M4 TUI 验收 harness（`drive_m4_tui_session.py`）现按
    M5 语义驱动：受限会话出现 → 输入对端密码 → grant → 双方 authenticated。
- [x] `M5-20` TUI Stream 视图支持文本/十六进制收发、半关闭、reset、窗口和背压状态。
  - `stream N` 进入流视图：`send <text>`/`sendhex <hex>`（完成即"进入受控发送
    窗口"）、`read`/`readhex`（含 EOF）、`window`（双向信用/缓冲/消费偏移）、
    `fin`/`reset`/`exit`；每次提示显示流状态、发送信用与接收缓冲。

## 测试与退出条件

- [x] pairing-only 越权、错误密码、重放 nonce、伪造 grant、过期/撤销 grant 和 endpoint scope 收窄全部默认拒绝。
  - `M5PeerSession.UntrustedPeersArePairingRestrictedByDefault`（业务帧/开通道默认拒绝）、
    `WrongPasswordClosesRestrictedSessionWithStableDenial`（AUTH_DENIED 关闭）、
    `M5PairingProtocol.AdmissionReplaysDuplicatesAndCapsAttempts`（同 ID 异 nonce 冲突
    即 protocol 错）、`M5TrustScopes`/`InitiatorSideAcceptsOnlyWellBoundedGrants`
    （伪造/越权 grant 拒绝）、`RevokedGrantNoLongerAuthorizesTheSession`（旧 grant
    不能恢复）、`PasswordPairingIssuesGrantAndUpgradesBothSides`（shell scope 被
    模板收窄剔除）。
- [x] 在每种队列满载下 control cancel/window/close 仍可发送；文件或事件流量不能饿死 control。
  - `ControlFramesFlowWhileBulkBacksUp`（64 帧 bulk 积压下 window update 前置发出）、
    `BulkIsNotStarvedUnderContinuousControlLoad`（反向无饥饿）、
    `heyaki_m5_scheduler` 基准（max deficit 0）。
- [x] frame/stream parser fuzz 覆盖截断、重复、乱序 offset、窗口溢出、未知必需 frame 和跨 session epoch 迟到数据。
  - 截断：decoder 任意切分边界测试 + libFuzzer 目标；重复：DATA 幂等与 pairing
    终态重放；乱序 offset/窗口溢出/未知 REQUIRED：随机化 64×6 敌意轮；迟到数据：
    terminal/reset 状态流帧忽略（wire 6.3）与 M4 会话 epoch 排斥（低 epoch hello
    忽略）复用。libFuzzer `heyaki_frame_parser_fuzzer` 增加
    `frame_stream_decoder`/`pairing_request_parser`/`trust_grant_parser` 目标。
- [x] 所有队列在持续过载测试中保持配置上限，RSS 无持续线性增长，drop/reject/timeout 与统计一致。
  - `PeerBudgetExhaustionAlwaysRejects`（peer 预算上限与统计）、
    `DropOldestAndKeepLatestPoliciesStayObservable`（drop 计数一致）、
    `RejectPolicyReturnsWouldBlockAndCapacityWaitFires`（would_block 与容量等待）、
    随机化测试每轮断言 open streams ≤ 上限且会话队列有界；ASAN 全量测试通过。
- [x] 已授权设备重连无需再次输入密码；被撤销设备持有旧 grant 也无法恢复权限。
  - `TrustedPeersAuthorizeWithoutPassword`（双端 TrustStore 有 grant 即直接授权，
    pairing_requests_sent==0）；`RevokedGrantNoLongerAuthorizesTheSession`。

## 实施记录

### 第 1 轮（2026-08-28）：全量交付

- 新增 `heyaki_core`：`frame_stream`（M5-01）、`trust_grant`（M5-11/12 规范化签名
  与 scope 裁决，`signing.cpp` 补 GrantId canonical 助手）、`pairing_protocol`
  （PAIRING_* 编解码 + 会话内 admission；`proto_codec.hpp` 内部共享 PB 编解码）。
- 新增 `heyaki_client`：`session_channels`（预算/策略/加权调度/容量等待，M5-02..06）、
  `pairing_service`（M5-09..13 服务层）、`byte_stream` + `byte_stream_facade`
  （M5-15..18 与公共 `heyaki::ByteStream` 门面，RULE-01 不泄漏内部类型）、
  `PeerSession` 重写（授权门控/受限状态机/配对流/AUTH_DENIED/业务帧分发/调度泵）、
  `Node` 集成（pair_peer/trust/revoke/rotate/open_byte_stream/授权快照/observer，
  会话建立与协议 1.2 重启会话均经 PairingService 裁决）。
- `ProfileStore`：信任基准从 generation 等值改为未撤销且未过期（DEC-04 默认：
  仅轮换不撤旧 grant）；新增 `trust_grants_for_peer`、
  `revoke_issued_trust_grants_below_generation`。
- `transport::ChannelKind` 新增 `stream`（标签 `heyaki.stream.v1`，无 wire 变更：
  帧数值表 1.2 后冻结，未新增帧类型）。
- TUI：`pair/trust/revoke/rotate-password[-revoke]/stream` 命令族与配对结果视图；
  本地初始化默认 pairing policy 安装 DEC-04 只读模板 scopes。
- 测试：`m5_framing_test`（core，8 用例）、`m5_channels_test`（7）、`m5_session_test`
  （PeerSession 配对/授权 6 + ByteStream 3 + 随机化鲁棒 1，17 用例）、
  `m5_pairing_service_test`（5，真实 ProfileStore + Argon2id）、
  `m5_scheduler_benchmark`；libFuzzer 解码器目标扩展。
- M3A/M3B/M4 既有 Node 级测试按"默认拒绝"新语义补种互信（`m5_support.hpp`：
  以冻结域签名的真实 grant 预置双端 TrustStore；仅验证连通性的场景不再要求配对，
  "发现不等于信任"断言保留未种子化的对照）。

### 第 3 轮（2026-08-28）：CI 修复（commit 2367322/054e28b/9f330ea/dbd86ab）

- 重启发送路径 UAF（asan+tsan，shutdown 矩阵）：`send_restart_frame` 同步
  fail 被取代会话时，close 观察者 retire 并 erase 持有 attempt 的记录，
  调用路径仍在解引用。PeerSession 公共入口在调用期间自持强引用；Node 的
  三个重启发送点先拷贝会话指针、发送后不再触碰 attempt。修复后 shutdown
  矩阵在 asan 与 tsan（setarch -R）反复运行零告警，restart e2e/M5 会话
  套件 tsan 干净。
- Release/clang -Werror 编译失败：`Frame` 指定初始化补全字段、
  `parse_stream_id` 复用于 RAW DATA 帧的 id 校验、M5 追加到
  `VerifiedPeerSessionConfig`/`PairingServiceConfig`/`TrustGrantRecord` 的
  函数与 optional 成员补默认成员初始化器（既有位置初始化调用点无需改动）、
  删除未用 lambda 捕获/参数/辅助函数、benchmark 符号转换；M5 pairing
  测试禁用 OS secret backend（glib 分配器在 tsan 下误报）并收紧目录权限。
- coturn 网络矩阵（M4 退出条件复验）：默认拒绝下两台矩阵节点停在
  pairing_restricted。`heyaki-m4-matrix-node` 新增 `seed-trust` 子命令
  （以双方设备身份签名方向性 grant 并写入两侧 TrustStore），矩阵脚本在
  init-profile 后预置互信；密码配对本身仍由单测覆盖。
- `M4RelaySignaling.TenantIsolationAndRateLimit` 计数竞态：relay 将快照
  发布合并到 handler 退出，错误帧可能先于计数刷出到达客户端。测试改为
  2 秒有界轮询后断言（既有 suite 模式）。

### 第 2 轮（2026-08-28）：收尾与验收

- `drive_m4_tui_session.py` 按 M5 语义重写验收路径：受限会话 → `pair N`（输入
  对端授权密码）→ granted scopes → 双方 authenticated（LAN/direct_host 不变），
  harness 通过。
- 修复实施中发现的缺陷：逻辑通道奇偶分配颠倒、PB 载荷 stream-id 解析偏移错误、
  OPEN 后初始发送信用缺失（响应方以 WINDOW_UPDATE 授予）、keep_latest 未在满载
  前清旧帧、WINDOW_UPDATE 回报被守卫条件抑制、scope-list canonical 编码与域规则
  不一致（varint → U16）。
- 全量 ctest（42+5 新测试目标）与 ASAN 构建通过；TUI/矩阵/延迟/重启端到端测试
  在种子互信下全绿。
