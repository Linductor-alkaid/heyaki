# M9-15 安全回归（2026-09-16）

> 范围：`M9-15` 执行安全回归——multicast 洪泛/伪造/重放、LAN TLS MITM/slowloris、
> 密码猜测/泄漏、grant/fingerprint/endpoint 伪造、降级、越权 method/topic、
> 路径穿越、relay/TURN 放大。本轮为 **测试与审计轮**：盘点八个攻击面的既有
> 覆盖，补齐真实缺口，未发现需要修复的生产缺陷（唯一的生产面发现是
> `encode_lan_presence` 拒绝序列化签名不符的 presence——这本身是纵深防御，
> 迫使伪造路径必须做字节手术，与真实攻击者行为一致）。

## 八面覆盖矩阵

每个攻击面 = 控制点 → 既有覆盖（本轮核对）→ 本轮新增。全部新增测试位于
CI 默认套件（无环境门控新增；m3a 的 LAN 测试沿用既有的"无多播接口即
SKIP"约定）。

### 1. multicast 洪泛/伪造/重放

控制点：签名验证 + DeviceId 从签名密钥派生 + boot nonce/sequence 重放缓存
+ 有界目录/速率/诊断状态。

| 场景 | 覆盖 |
| --- | --- |
| 有效签名洪泛（有界状态） | 既有 `M3aNodeTest.RejectsForgedMulticastFloodWithinBounds`（真组播 socket） |
| 编码层篡改/截断/未知字段 | 既有 `LanPresenceProtocolTest.RejectsTamperingUnknownFieldsAndTruncation` 等 |
| wire 级签名伪造 | **新增** `ForgedReplayedAndMismatchedPresenceRejectedOverWire`：对合法编码做字节手术（翻转签名尾字节）→ `presence_signature_invalid` |
| wire 级身份冒名 | 同上：覆写 32 字节 device_id 字段 → `presence_device_id_mismatch`（派生校验先于签名验证） |
| wire 级重放 | 同上：低序列重放 → `presence_sequence_replay`（注意：**字节级重复是幂等吸收**，低序列才是重放错误） |
| 目录重放/冲突/容量语义 | 既有 `EndpointDirectoryTest.*` 六例（unit） |

### 2. LAN TLS MITM / slowloris

控制点：LAN_HELLO 双指纹绑定 + 握手超时 + provisional 连接容量/速率限制。

| 场景 | 覆盖 |
| --- | --- |
| 证书替换/中继 hello | 既有 `RejectsRelayedHelloAndCertificateSubstitution`（真 TLS） |
| 编码层指纹/签名替换 | 既有 `LanHelloProtocolTest.RejectsCertificateAndSignatureReplacement` |
| 每源 provisional 限速 + 空闲超时 | 既有 `ProvisionalTlsIsPerSourceRateLimitedAndTimesOut` |
| **慢速部分握手（slowloris 形态）** | **新增** `SlowTrickledHandshakeTimesOutAndLegitimatePeerStillAuthenticates`：滴注 TLS 记录头 + 部分 ClientHello，两轮被握手死线回收（timed_out 递增、provisional 归零），随后真实受信 peer 在同一 listener 上照常认证 |
| **跨源全局容量帽** | **新增** `ProvisionalCapacityCapAppliesAcrossSources`：127.0.0.2/.3 占满 capacity=2 后，127.0.0.4 的第三连接被 `provisional_connection_capacity_full` 拒绝（非 Linux 平台无备用环回源时 SKIP） |

### 3. 密码猜测/泄漏

控制点：Argon2id 本地验证 + 每源失败表指数退避 + 无全局锁死 + 审计/日志
分级脱敏（`value_for_log`）。

| 场景 | 覆盖 |
| --- | --- |
| 错密码计数 + 退避门先于验证 | 既有 `WrongPasswordCountsFailuresAndBacksOff` |
| 策略交集授权 / 撤销 / 轮换 | 既有四例 |
| **指数递增 + 封顶** | **新增** `BackoffProgressionDoublesPerFailureAndClampsAtMax`：窗口 1000→2000→4000→4000（clamp），成功清零（fake clock 全表） |
| **跨源隔离（无全局锁死）** | **新增** `IndependentSourcePairsWhileAnotherSourceIsThrottled`：A 被限流的同时 B 立即配对成功 |
| **密码字面量泄漏猎杀** | **新增** `PasswordLiteralNeverReachesAuditOrProfileBytes`：猜测路径 + 接受路径的审计 detail 与 profile 根下全部文件字节均不含密码字面量；审计不含 "argon2"（verifier 只活在 DB） |
| 错误类分级脱敏 | 既有 `Security.SensitiveClassesAreAlwaysRedacted`（value_for_log 契约） |

relay 侧按协议不接触密码（pairing 是端到端），泄漏面不存在，不做重复测试。

### 4. grant / fingerprint / endpoint 伪造

控制点：canonical 签名对象 + 会话身份绑定 + 注册公钥验签。

| 场景 | 覆盖 |
| --- | --- |
| offer/answer 篡改、换绑重签、候选绑定 | 既有 `M4Coordinator.*` 四例 |
| 会话 hello 转录替换 | 既有 `M4SessionHello.RejectsSignatureAndTranscriptSubstitution` |
| relay 证书 pin 失配 / CA 验证 | 既有 `WrongPinFailsAuthentication` / `VerifyPeerWithoutTrustedCaFails`（真 WSS/TLS） |
| 记录层换钥签名 | 既有 `RecordRoundTripAndValidation`（public_key 翻位 → signature_verification_failed） |
| **第三方密钥 candidate** | **新增**（`CandidateBindingViolationsRejected` 扩展）：绑定字段全部照抄、以攻击者密钥签名 → 拒绝，不投递 |
| **伪造 TrustGrant 进接受侧** | **新增** `TamperedGrantSignatureIsRejectedByInitiatorAcceptor`：签名翻位 → authentication 拒绝，TrustStore 零持久化 |
| **endpoint 记录冒名（E2E）** | **新增** `EndpointPublishIsBoundToLoggedInSession`（真 relay/WSS）：A 会话签发 B endpoint 的有效签名记录 → `endpoint_record_session_mismatch`（会话绑定先于验签）；正控（自有 endpoint 发布 → ack）先行；目录只落地一条 |

### 5. 协议降级

控制点：签名版本/能力字段 + 精确 major 匹配 + required 位双重校验 + 认证后
不可回退。M9-12 已交付完整面（`m9_compat_test` 11 例：协商下调/交集、
越版 required 拒绝、1.2↔1.1 会话重启帧门控、relay login 钳制、LAN 版本
门）。本轮核对无新增缺口；"认证后再 hello 降级"由 hello 单次准入 +
`AdmitsOnceAndRejectsConflictingDuplicate`（M4 既有）覆盖。

### 6. 越权 method/topic

控制点：受限会话通道级 default-deny（`pairing_required`）+ 服务层 scope 匹配。

| 场景 | 覆盖 |
| --- | --- |
| 未配对会话整体隔离 | 既有 `UntrustedPeersArePairingRestrictedByDefault`（业务帧到不了 handler） |
| RPC/message/event/file/shell 各自 scope 越权 | 既有 `ScopeMissingAnswersPermissionDenied` 等五例 |
| **scope 匹配文法钉死** | **新增** `TrustScopeCoversPinsExactAndPrefixWildcardSemantics`：`prefix:*` 只覆盖 `prefix:x`（含更深层），不覆盖裸 `prefix`/`prefix:`；`:*`/`*`/空串不构成全局通配——这是全部服务授权判定的原语 |

### 7. 路径穿越

控制点：逻辑名文法 + 接收根映射 + 分量级 symlink 检查 + staging O_NOFOLLOW
+ 原子 rename。

| 场景 | 覆盖 |
| --- | --- |
| `..`/设备名（API 层与 manifest 编码层） | 既有 `UnsafeNamesRejectedBeforeAccept` |
| 目录分量 symlink | 既有 `SymlinkedRootComponentRejected` |
| **文法全表** | **新增** `SafeLogicalFileNameParsesAttackShapedNames`：绝对路径/反斜杠/NUL/控制字节/空段/尾点尾空格/COM1-9·LPT1-9·CON·PRN·AUX（任意大小写+扩展名）/512 字节与 32 段边界（含恰好达界的正值对照） |
| **终段 symlink** | **新增** `FinalPathComponentSymlinkIsReplacedNotFollowed`：预置终段 symlink 指向接收根外 → 提交 rename 替换链接本体、逃逸目标从未被创建、终路径为字节一致常规文件 |

shell 侧路径文法/防逃逸已由 M8 独立安全评审覆盖（P2-F1 修复 + 
`ExecutablePathGrammarPerPlatform`），不重复。

### 8. relay / TURN 放大

控制点：信令 1:1 定向投递 + 四 scope 限速（拒绝也记账）+ WSS 读上限 +
coturn 配置（no-multicast-peers/denied-peer-ip/quota/bps）。

| 场景 | 覆盖 |
| --- | --- |
| 离线目标无扇出 / 未知 kind 会话关闭 | 既有 `OfflineTargetReturnsEndpointOffline` / `RejectsUnknownKindAndPayloadPolicyViolations` |
| 跨租户拒绝 + 洪限速 | 既有 `TenantIsolationAndRateLimit` |
| 客户端侧 oversized 帧拒发 + 编码层上限 | 既有 `RejectsInvalidUrlsAndPayloads` / `RejectsMalformedAndUnboundedInput` |
| **服务端 oversized 帧（真 socket）** | **新增** `OversizedControlFrameIsRejectedAndServerStaysHealthy`：裸 beast WSS 客户端写入 16× `max_relay_wss_control_frame_bytes` 的二进制消息 → 服务端在 `read_message_max` 处丢弃会话、保持 running、新客户端照常登录 |
| **1:1 无放大比率** | **新增** `ForwardIsOneToOneWithoutFanoutOrReflection`：A→B 8 发 = B 恰收 8、第三方 C 与发送方 A 零接收、relay `signaling_forwarded` 恰好 +8 |
| coturn 反射面 | 配置契约既有（`heyaki_coturn_deployment_contract`：no-multicast-peers/denied-peer-ip/total-quota/user-quota/max-bps/bps-capacity 逐行钉死 + digest pin） |

## 已接受的残余（非本轮新增，记录于 threat-model）

- `/metrics` 端点对任何持有 CA 信任的 TCP 客户端应答（无客户端认证）——
  暴露类为 identifier/operational（threat-model §3），TLS 握手成本 +
  连接/每 IP 限速承担放大控制；产品级 scrape 认证留部署侧。
- coturn 反射行为由配置控制（contract 测试钉死），无行为级黑盒测试
  （需要向 denied 网段发 TURN 流量的专用客户端，收益低于成本）。
- LAN 稳定 ID 枚举、本地/relay/coturn DoS 与流量分析：v1 接受的残余
  （threat-model §7）。

## 测试资产索引

- 新 CTest：`heyaki_m9_security_regression`（labels unit;security;m9;regression）。
- 扩展文件：`tests/unit/{m3a_lan,m5_pairing_service,m4_signaling,
  m4_relay_signaling,m7_file}_test.cpp`（各文件新增 M9-15 标注的用例）。
- 本轮坑（供后续轮避免）：
  1. `encode_lan_presence` 先验证后编码——伪造 presence 不能经 codec 序列化，
     wire 级伪造必须对合法编码做字节手术（签名在 payload 末字段）。
  2. presence **字节级重复 = 幂等吸收**（无错误）；重放错误只在更低序列
     （或退役 boot nonce）时出现。
  3. `send_error` 恒 close-after-write：依赖"被拒后继续用同一控制连接"的
     测试必须把正控放在拒绝路径之前（signaling 运营错误走
     `send_signaling_error` 才不关连接）。
  4. `per_source_provisional_capacity` 必须小于等于
     `provisional_connection_capacity`（LAN 配置不变式，否则
     `invalid_lan_configuration`）。
  5. GCC 的 `std::filesystem` 无 `create_file_symlink`，用 `create_symlink`。
