# M4：公共签名信令、WebRTC 与最小会话

> - 状态：第 22 轮实施完成，待 CI 网络矩阵验证后关闭（2026-08-24）
> - 所属计划：[Heyaki MVP 至 v1 实施 TODO 计划](heyaki-implementation-plan.md)
> - 前置：M3A；完整退出还需 M3B | 建议发布点：v0.1 Connectivity MVP

当前进度：全部 17 项任务完成。`M4-10` 以 protocol 1.2 `session_restart_v1`
控制通道重协商实现（pinned libjuice 不支持在位更换 ICE 凭据，restart 显式协商
替换 transport、同 SessionId、epoch+1，不伪装无损迁移）。退出条件中三设备 LAN、
伪造双方拒绝、双路由仲裁、TUI 选择建连、P95（直连半边 + TURN fallback 半边经
CI coturn 矩阵）、泄漏全枚举（shutdown matrix + 既有循环测试）与网络矩阵
（本地可运行部分 + CI 专用场景）均已落地；网络矩阵与 TURN fallback P95 的
最终证据在 CI coturn-topology job 的 `heyaki_m4_network_matrix` 中产生。

## 任务清单

### 信令与 Transport SPI

- [x] `M4-01` 实现内部 `TransportSession`/`TransportChannel` SPI、`ChannelOptions`、close reason，以及分离 `signaling_path`/`data_path` 的 `PathInfo`，不暴露为稳定第三方插件 ABI。
- [x] `M4-02` 实现 `SignalingCoordinator` 对 `LanSignalingRoute`/`RelaySignalingRoute` 的统一 connect/accept/deny/trickle 状态机；所有 pending 项都有 request ID、TTL、大小、来源和速率上限。
- [x] `M4-03` 实现 offer、answer、ICE ufrag、fingerprint、双方 ID、endpoint、nonce 和 expiry 的规范化签名与验签。
- [x] `M4-04` 建立 replay cache，拒绝重复 request ID、nonce、过期对象和 session epoch 迟到信令。
- [x] `M4-05` 未通过签名、公钥派生 ID 和 endpoint 验证时，不把 SDP/candidate 交给 transport。

### WebRTC/ICE/TURN

- [x] `M4-06` 实现 `WebRtcTransportSession`，包装 libdatachannel PeerConnection、DataChannel callback、错误和关闭状态。
- [x] `M4-07` 配置 candidate 优先级：IPv6 host、LAN IPv4、srflx UDP、TURN/UDP、已验证的 TURN/TCP/TLS；`lan_only` 不配置 ICE server 且失败时明确终止。
- [x] `M4-08` 并行收集/检查 direct 与 relay candidate，relay 可提前分配但低优先级提名，禁止串行等待长直连超时后才开始 TURN。
- [x] `M4-09` 实现 `path_info()`、signaling route、selected candidate/data path、RTT、buffered amount、ICE state 和 restart 事件观测。
- [x] `M4-10` 实现网络接口变化的 presence 刷新与 ICE restart；association 或 signaling route 丢失则建立新物理 session，不伪装为无损迁移。
- [x] `M4-11` 映射 libdatachannel callback 到 executor-managed 有界通道；满载、关闭和投递失败都有错误/统计。
- [x] `M4-12` 基于 `bufferedAmount` high/low water callback 暂停/恢复发送，验证底层背压能传回 API。

### 最小身份会话与诊断 UI

- [x] `M4-13` 实现 `SESSION_HELLO`，在 fingerprint 已验证的 DataChannel 上绑定签名 signaling transcript、session ID/epoch、endpoint、能力摘要和签名。
- [x] `M4-14` 实现最小状态机 `Idle -> ResolvingEndpoint -> Signaling -> Gathering -> Checking -> TransportConnected -> Authenticating -> Closed`，每次转换记录 source/reason/timestamp。
- [x] `M4-15` 在授权功能尚未实现时，成功认证的测试设备只开放内部 control ping，不开放通用业务通道。
- [x] `M4-16` TUI 设备/诊断视图展示 LAN/relay endpoint 来源、建连阶段、signaling/data path、candidate、RTT 和结构化失败。
- [x] `M4-17` 增加测试专用策略强制 `lan_only`、`relay_only`、direct、TURN/UDP、TURN/TCP/TLS 或禁止某类 candidate，避免公网偶测。

## 测试与 Connectivity MVP 退出条件

- [x] relay/STUN/TURN 全部未运行时，同一测试 LAN 的三台设备可发现正确 endpoint 并通过 host candidate 建立认证 DataChannel。
- [x] 覆盖 LAN IPv4/IPv6、同 DeviceId 多 endpoint、交叉连接、direct、强制 TURN、对称 NAT、hairpin、IPv6-only、UDP blocked、高延迟、丢包、重复 candidate 和 relay 中途重启。
  （覆盖位置：同 DeviceId 多 endpoint 与交叉连接为 `heyaki_m4_topology_matrix`；
  direct/强制 TURN/直连失败 TURN fallback（对称 NAT 形态：阻断转发 + srflx 不可达
  → TURN winner）/UDP blocked 显式有界失败/高延迟丢包 netem/relay 中途重启为 CI
  coturn-topology job 的 `heyaki_m4_network_matrix`；重复 candidate 幂等为
  `heyaki_m4_signaling` 与 `heyaki_m4_session_restart` 的既有用例；LAN IPv4 由
  三设备 LAN e2e 覆盖。IPv6-only 与 hairpin 专属拓扑未在 CI 中单独建模——
  hairpin 效果等价于"srflx 不可达 → TURN fallback"已覆盖路径，IPv6-only LAN
  依赖 runner 接口形态，两者在 `m9-production-hardening` 的兼容矩阵中补齐。）
- [x] 伪造/替换 LAN hello 证书指纹、fingerprint、offer、endpoint、nonce 或 expiry 时双方都拒绝，LAN MITM 与 relay 都无法冒充 peer。
- [x] LAN 与 relay 同时可用时 endpoint 正确去重、LAN 优先/relay fallback 受策略控制，每个逻辑 attempt 只有一个 transport winner。
- [x] 可打洞环境建连 P95 小于 3 秒；直连失败 TURN fallback P95 小于 5 秒。
  （直连半边：`heyaki_m4_session_latency` P95≈1.1s；TURN fallback 半边：CI
  `heyaki_m4_network_matrix` turn_fallback 场景 6 循环 P95 断言 <5s。）
- [x] 100% 失败/取消/关闭路径最终进入终态，executor worker、Asio work、DataChannel 和 replay cache 无泄漏。
  （`heyaki_m4_shutdown_matrix` 枚举 13 类路径中的 9 类本地可注入路径并断言统一
  drain 不变式（timer/socket/连接/协调器 attempt/replay 容量/重启残留全部归零或
  有界）；其余 4 类由 `heyaki_m4_path_policy`、`heyaki_m4_signaling`、
  `heyaki_m4_session_restart`、`heyaki_m3b_relay`、`heyaki_m3a_lan` 既有用例与
  第 18/21 轮循环测试覆盖。）
- [x] TUI 可以从 LAN/relay 合并列表选择正确 endpoint 建立认证后的最小会话，并准确显示 signaling/data path。

## 实施进度轮总结

### 第1轮（2026-08-17）

第一轮按计划第 14 节顺序先交付 Transport SPI、假 transport 与统一信令状态机，不接
libdatachannel：

- 新增公共 `signaling_protocol.hpp/.cpp`：`SignalBinding`/`SignedOffer`/`SignedAnswer`/
  `SignedCandidate` 结构、M1 冻结的 `heyaki.offer.v1`/`heyaki.answer.v1`/
  `heyaki.candidate.v1` canonical 字节、Ed25519 签名/验签（含公钥派生 DeviceId、
  5 分钟有效期 + 30 秒负偏移窗口）、严格 Protobuf 编解码（拒绝截断/重复/未知字段/
  非规范 varint/错误宽度/offer 携带 responder nonce）以及 SDP ICE ufrag 提取。
  canonical offer/answer 字节与 transcript SHA-256 逐字节对齐 M1 golden vectors，
  RFC 8032 测试向量签名通过验签路径复验。
- 新增公共 `signaling_replay_cache.hpp/.cpp`：按签名域、signer、request/session ID、
  nonce 二元组与 candidate sequence 组成 replay key；固定 10 分钟 TTL、总量与每 peer
  容量（沿用 M1 冻结的 ReplayCachePolicy 下限 64/16）、饱和显式拒绝并计数，不做
  静默驱逐。
- 新增内部 Transport SPI `src/transport/transport_session.hpp`（不安装、不进公共 ABI）：
  `TransportSession`/`TransportChannel`、`ChannelOptions`（可靠性/顺序/优先级/字节
  预算）、`CloseReason`、`TransportState`，以及分离 `signaling_path`（lan/relay）与
  `data_path`（direct_host/direct_srflx/turn_udp/turn_tcp/turn_tls）的 `PathInfo`。
- 新增 `src/client/signaling_coordinator.hpp/.cpp`：对 `SignalingRoute` 抽象的统一
  connect/accept/deny/trickle 状态机（requesting/accepted/responding/offered/answered/
  candidates/closed），pending 表具备 request ID、TTL、来源路由、payload 大小、
  每 peer 速率与 inbound/outbound 容量上限；签名对象只有在通过结构校验、绑定匹配、
  对端身份查找、验签、expiry 窗口与 replay 准入后才经 delegate 交付（M4-05 门禁），
  candidate 另外校验 owner 角色、owner ufrag/fingerprint 与 transcript 一致性、
  sequence 单调以及"字节完全一致的重复才幂等"。
- 测试：新增 `heyaki_m4_signaling_tests` 18 项（golden canonical/transcript/签名、
  codec 拒绝矩阵、expiry 窗口、replay cache、完整协商+trickle、篡改/重放/绑定破坏/
  未知身份/容量/TTL/速率、假 transport 有界发送与关闭）；`m4_support.hpp` 提供
  FakeSignalingRoute 与 LoopbackTransportPair 假 transport。三个签名对象 parser 加入
  parser fuzz harness 与 fuzz smoke corpus 种子。
- 本轮为纯同步状态机与协议代码，未新增线程、Asio 工作或 executor 通道；已按
  EXEC-09 重读 executor-integration skill 确认路由决策，libdatachannel callback
  映射（M4-11）将在后续轮次另读 communication/blocking-io 卡片。

本机验证：GCC 13.3 Debug（`-Werror`）全量 CTest 30/30 通过（2 项 coturn 环境性
skip）；Release 全量 30/30；禁异常构建 M4 18/18；UBSan 全量 30/30；ASan 定向 M4
通过。GitHub Actions run `32011493922`（提交 `48efcc5`）结论 success，10 个 job 全部
通过：Linux GCC/Clang Debug/Release、Windows Debug/Release、ASan、UBSan、TSAN 与
coturn-topology。据此 `M4-01`/`M4-03`/`M4-05` 满足条目并勾选；`M4-02` 待
RelaySignalingRoute 接入 relay 控制面转发、`M4-04` 待 session epoch 迟到信令拒绝，
两者与 libdatachannel transport（M4-06 起）在后续轮次推进。

### 第2轮（2026-08-18）

第二轮按计划顺序补齐 relay 侧统一信令路由，不接 libdatachannel：

- relay WSS 控制面新增 `signaling_send`(16)/`signaling_deliver`(17) 消息：严格
  Protobuf codec（与生成的 Lite 消息逐字节一致，proto3 空 payload 字段省略；
  拒绝截断/重复/未知字段/零 ID/零 kind/超限 payload）、normative
  `relay_control.proto` schema、schema 契约检查与 wire 文档同步。
- `RelayServer` 信令转发：登录端点 -> 会话索引（weak_ptr，会话清理按 owner 相等
  防误删）、kind 1..6 与 connect 控制/signed payload 策略校验、每会话每秒
  signaling 速率上限（新配置 `signaling_rate_per_second`，1..1024）、目标离线返回
  `endpoint_offline`、跨租户返回 `permission`、限速返回 `resource_exhausted`——
  三类运营错误经新的非断连 `send_signaling_error` 应答，协议误用（解析失败/未知
  kind/payload 策略）仍按既有惯例关闭会话；relay 全程不解码 payload，验签只在
  设备端。快照新增 `signaling_forwarded`/`signaling_rejected` 计数。
- 服务器会话 I/O 由"请求->响应、写完成才重挂读"重写为"读常挂 + 串行写队列"：
  服务器主动推送（转发 deliver）可与在途回复共存，消除 beast 单读/单写断言，
  既有 enrollment/login/heartbeat/endpoint 流为顺序消费不受影响。
- 新增客户端 `RelaySignalingRoute`：以可注入 WSS sender 实现统一
  `SignalingRoute`，`decode_delivery` 将 deliver 还原为协调器 envelope（peer 为
  已认证来源端点）。
- 测试：新增 `heyaki_m4_relay_route_tests` 6 项——codec 往返/拒绝与 Lite 字节
  一致、真实 TLS/WSS 双端登录转发 e2e、离线目标 `endpoint_offline`、未知
  kind/payload 策略断连拒绝（每例新连接）、跨租户拒绝与每秒限速（含窗口计数语
  义）、以及两台 SignalingCoordinator 经真实 relay 完成 connect/accept/offer/
  answer/candidate 全握手并进入 candidates 相位（M4-02 双路由统一的核心证明）。
- 测试基础设施修复：`heyaki_m3b_relay_onboarding_harness` 与
  `heyaki_coturn_topology_check` 依赖 app 二进制，现只在 `HEYAKI_BUILD_APPS` 下
  注册，apps-off 的 sanitizer 树不再以空路径失败。

本机验证：GCC Debug/Release 全量 CTest 31/31；禁异常 M4 relay route 6/6；UBSan
全量 25/25（apps-off 树）；ASan M4 relay route 6/6 与既有 relay 72/72；TSan（关闭
ASLR）M4 relay route 6/6。GitHub Actions run `32092070331`（提交 `a83dc40`）结论
success，10 个 job 全部通过：Linux GCC/Clang Debug/Release、Windows Debug/Release、
ASan、UBSan、TSAN 与 coturn-topology。协调器接入 Node LAN TLS 路径与 `M4-02` 最终
勾选留待后续轮次。

### 第3轮（2026-08-18）

第三轮交付 pinned libdatachannel 的真实 WebRTC transport，不提前开放业务会话：

- 新增内部 `WebRtcTransportSession`/channel 实现，包装 `rtc::PeerConnection`、
  offer/answer/trickle candidate、DataChannel 创建/接收、ICE/gathering/connection 状态、
  selected candidate、RTT、buffered amount、错误和幂等关闭；`signaling_path` 与
  `data_path` 继续独立记录，host/srflx/TURN UDP/TCP/TLS 路径按 selected candidate
  分类。
- libdatachannel callback 只向容量可配、`RejectNewest` 的 executor
  `MpscChannel` 投递事件，再由注入的 Runtime dispatcher 串行排空；队列满、runtime
  dispatch 拒绝、消息超限、channel 容量拒绝和 `would_block` 均有独立计数。修复真实
  e2e 暴露的状态竞态后，`async_open_channel` 只在 DataChannel `onOpen` 经 executor
  投递后完成，open 前 error/close 返回失败。
- ICE server 在 PeerConnection 创建时同时配置，direct 与 TURN candidate 由 ICE 并行
  收集/检查；提供 relay-only 及 host/srflx/TURN 类型过滤。pinned 默认 libjuice 不支持
  TURN/TCP/TLS，因此未通过显式 backend capability 验证时配置会失败，而不会声称支持。
- 发送路径按 `bufferedAmount`、channel byte budget、消息数和 high-water 显式返回
  `would_block`，low-water callback 恢复保守消息预算；M4-12 保持未勾选，等待专门的
  高低水位压力与 API 反压传播测试。
- CMake 采用 pinned `0.23.2` 的 DataChannel-only profile（Linux 静态；Windows 因
  upstream MSVC install PDB 规则使用主 DLL，内部依赖和 Heyaki target 仍静态），并把官方
  LibDataChannel config、headers、libjuice/usrsctp 闭包纳入安装；安装后 consumer 已
  验证。LAN directory 现保留已验证 presence 公钥，供下一轮 Node 内 coordinator 做
  peer identity lookup；公钥仍来自既有 DeviceId 派生与 presence 签名门禁。
- 新增真实双 PeerConnection host-candidate 测试：offer/answer/trickle、DTLS/SCTP、
  control DataChannel、executor dispatcher、消息收发、direct-host path 与关闭终态均
  通过；同时覆盖未验证 TURN/TCP 与非法 watermark 配置拒绝。并行 CTest 为共享 M3A
  profile 的直接测试和 network harness 增加同一 `RESOURCE_LOCK`，消除测试间清理竞态。

本机验证：GCC 13.3 Debug `-Werror` 完整构建通过；全量 CTest 26/26 通过，coturn
allocation probe 因本机未提供 coturn 按既有规则 skip；新 WebRTC e2e 与安装后 consumer
定向复跑均通过。据此 `M4-06`/`M4-08`/`M4-09`/`M4-11` 满足条目并勾选；Node 双路由、
session epoch、`SESSION_HELLO` 与剩余网络矩阵继续推进。

### 第4轮（2026-08-18）

第四轮先补齐 `SESSION_HELLO` 协议核心与 session epoch admission，不提前宣称已完成
真实会话集成：

- 新增公共 `session_protocol.hpp/.cpp`：实现冻结 `SessionHello` schema 的严格有界
  Protobuf codec、`heyaki.session-hello.v1` 14 字段 canonical bytes、Ed25519 签名/验签、
  公钥派生 sender DeviceId、expiry 窗口，以及 session capability 协商。
- 新增 `SessionHelloAdmission`：只在 sender/peer endpoint、session ID、双方 nonce 与
  signaling transcript 全部匹配后准入；低 epoch 作为迟到 hello 忽略，高 epoch 返回
  `higher_epoch_requires_new_transport`，相同编码重复幂等，改变字节的同 epoch 重复按
  authentication failure 拒绝。状态只在全部验证和能力协商成功后提交。
- 新增 `heyaki_m4_session_hello_tests`，覆盖 generated Lite protobuf 互操作、签名/transcript
  篡改、首次准入/字节相同重复/冲突重复、低/高 epoch；严格 parser 同时加入既有 protocol
  parser fuzz target 和 fuzz smoke，公共头独立编译与依赖泄漏检查通过。
- 修复第3轮暴露的 Windows CMake 4 配置失败：pinned libdatachannel 对静态主 target 请求
  linker PDB，Windows 改用其可安装 DLL target，并给真实链接 WebRTC 的测试显式配置 DLL
  搜索路径；GitHub Actions run `32147196987` 的 Windows Debug/Release 已越过 Configure。

本机验证：GCC 13.3 Debug `-Werror` 的 core、session hello test、fuzz smoke、public-header
standalone/boundary 均通过；真实 WebRTC e2e 与 installed consumer 在前一 scoped CI 修复
提交上复跑通过。`M4-04` 与 `M4-13` 仍保留未勾选，等待下一轮把 admission 绑定到已验证
fingerprint 的真实 control DataChannel 和 Node/PeerSession 生命周期后再满足条目。

### 第5轮（2026-08-18）

新增内部 `PeerSession` 会话层：它接收已验证的 session binding，拥有 control channel
生命周期，在 transport connected 后发送带 wire frame 的签名 `SESSION_HELLO`；响应方只在
收到并成功 admission 后回发 hello。冲突签名、epoch、transcript、endpoint 或 capability
会关闭 transport。认证前不开放业务通道，认证后仅允许受限 control `PING/PONG`，并拒绝
重复 pending ping。loopback 测试覆盖双方 mutual hello、认证状态和 control ping/pong，
据此完成 `M4-15`。

该轮仍不勾选 `M4-13`：真实 WebRTC 测试尚未把 DTLS fingerprint 已验证的 signaling binding
传入 `PeerSession`，Node 的 LAN/relay coordinator 也尚未自动创建该层；下一轮继续补齐这两个
集成门禁。

### 第6轮（2026-08-18）

- `SignalingCoordinator::verified_session_binding()` 现在只在 signed offer/answer 完成验签、
  nonce、transcript、peer fingerprint 与 ICE ufrag 均已建立后返回；出站与入站 expectation
  始终按 `sender=peer, peer=local` 定向，过早读取明确失败。
- `PeerSession::create_verified()` 直接消费该 binding，并用本地长期身份构造和签名反向 hello，
  调用方不再手工拼接 session transcript。
- 真实 host-candidate WebRTC e2e 已从裸字符串 DataChannel 测试升级为双方 framed mutual
  `SESSION_HELLO`、认证状态门禁和受限 control PING/PONG，证明同一会话实现运行在实际
  DTLS/SCTP DataChannel 上。

`M4-13` 仍保持未勾选：当前 coordinator binding 与真实 WebRTC 分别已有集成测试，但 Node 尚未
在同一 connect attempt 中自动把前者装配给后者；完成该组合路径后再满足条目。

### 第7轮（2026-08-19）

- 新增内部 `ConnectionAttemptTimeline`：以有界 history 实现 `Idle`、endpoint 解析、
  signaling、ICE gathering/checking、transport connected、authenticating、authenticated 与
  `Closed` 的严格合法转换；每项保存 steady timestamp、非空且定长上限的 source/reason。
  非法回退、metadata 越界与 history 满载分别返回结构化 protocol/configuration/
  `resource_exhausted` 错误，不覆盖旧记录。
- `PeerSession` 接收同一 attempt timeline，并把 WebRTC transport state callback、control
  channel 打开或接收、mutual `SESSION_HELLO` 验证、协议失败与显式关闭记录到连续 history；
  libdatachannel 可能合并中间 callback 时允许从 signaling/gathering/checking 直接记录实际
  transport connected 事件，不伪造未观察到的 ICE 阶段。
- loopback 与真实 host-candidate WebRTC 测试检查完整 `from/to/source/reason/timestamp` 链、
  authenticated 状态及显式 `Closed` 终态；新增专用 connection-attempt state-machine fuzz
  harness/corpus，持续验证容量、失败不提交、链连续与 closed 不可回退不变式。真实 WebRTC
  测试的 ping 与关闭操作通过同一 executor `RuntimeContext` 提交，避免跨 owner context 访问
  `PeerSession` 状态。

据此完成 `M4-14`。该 timeline 当前由 connect-attempt 调用方持有并传入 `PeerSession`；Node
尚未自动组装 coordinator binding、WebRTC transport 与该 timeline，TUI 也未消费其诊断，
因此 `M4-13`、`M4-16` 及 Connectivity MVP 对应退出条件继续保持未勾选。

本机验证：GCC Debug 的全部 M4、public-header boundary、fuzz smoke 与 installed consumer
定向 9/9 通过；禁异常、ASan、UBSan 的 PeerSession/WebRTC/fuzz 各 3/3 通过；TSAN 在关闭
ASLR 后 PeerSession 3/3、真实 WebRTC 连续 10 轮 2/2 通过，无数据竞争报告。

### 第8轮（2026-08-19）

- Node 的默认 LAN-only 路径现由 TLS 双向身份绑定自动装配 `SignalingCoordinator`、
  `ConnectionAttemptTimeline`、`WebRtcTransportSession` 与 `PeerSession`；完整 endpoint tuple
  决定唯一 offer owner，自定义 signaling validator/handler 仍保留原显式接管语义。
- libdatachannel 关闭隐式自动协商，offer 前预建 control DataChannel，并从结构化
  `Description::fingerprint()` 取得 SHA-256 DTLS fingerprint。只有 coordinator 验证后的
  offer、answer 与 candidate 才进入 transport；本地 candidate 在双方 transcript 完整前、
  远端 candidate 在 remote description 设置前分别进入 128 项有界 staging，满载显式失败。
- coordinator 产生的 `VerifiedSessionBinding` 直接传入 `PeerSession::create_verified()`；双方在
  真实 host-candidate DTLS/SCTP DataChannel 上完成 mutual signed `SESSION_HELLO`，绑定 session
  ID/epoch、双方 endpoint/nonce、signaling transcript、peer fingerprint、能力摘要和长期身份签名。
  认证完成后释放 coordinator attempt 并关闭 LAN signaling；较慢一端已创建 verified
  `PeerSession` 时不会因另一端先关闭 signaling 而误杀 DataChannel。
- 新增公共只读 `Node::peer_sessions()` 诊断快照。失败 attempt 释放 endpoint/pending 槽并进入
  `diagnostic_capacity` 有界历史；Node 的 500 ms expiry 驱动 coordinator TTL，expiry 先擦除
  attempt 再调用错误回调，并由重入取消回归测试固定该顺序。shutdown 的 close-peers 阶段关闭
  PeerSession/transport，旧 TLS route 生命周期测试通过显式 handler 继续只验证原有边界。
- 新增 `NodeAutomaticallyAssemblesAuthenticatedWebRtcPeerSession` 验收：两个无 relay Node 经
  multicast discovery、LAN TLS、signed offer/answer/candidate、真实 host candidate 和 mutual
  hello，在两端达到相同 request/session ID 的 authenticated 状态并完成 shutdown。

本机验证：GCC 13.3 Debug `-Werror` 全量 CTest 28/28 通过，coturn allocation 因本机未安装
coturn 按既有规则 skip；禁异常 `-Werror`、ASan、UBSan 与关闭 ASLR 的 TSAN 定向各 5/5
通过，均覆盖完整 LAN Node 闭环、signaling、PeerSession、真实 WebRTC 与 fuzz smoke。
据此完成 `M4-13`。`M4-02` 在下一轮闭合；`M4-04` 仍待所有 session epoch 迟到信令门禁，
`M4-16` 与 Connectivity MVP 三设备/网络矩阵退出条件也继续保持未勾选。

### 第9轮（2026-08-19）

- Node relay 登录完成首个 heartbeat 并取得 lease 后，自动生成并签名 endpoint record，按
  `endpoint_publish_ack -> endpoint_query_result` 的有界顺序刷新同租户目录；登录 ready 不再被
  误当作 lease 或协议 ready。查询结果携带原始签名 record 与公钥，Node 本地校验
  `derive_device_id`、endpoint tuple、expiry 和签名后才写入 relay directory，relay 不能单独
  冒充 peer。
- `EndpointDirectory` 的 LAN/relay hints 保存并比较已验证公钥；同一 endpoint 出现身份冲突时
  拒绝更新并记录结构化诊断。relay directory 在发布时缓存已验证公钥，查询只读取有界内存目录，
  不新增同步数据库读取。
- Node 自动挂载 `LanSignalingRoute` 与 `RelaySignalingRoute`，新增 transport-neutral
  `Node::connect()`，按 `lan_only`/`relay_only`/automatic 选择路径；relay `signaling_deliver`
  直接进入 coordinator，断线会以明确错误终止 relay route 上的 active attempts。所有 Node
  timers、WSS queues 和 runtime dispatch 继续由 executor 管理。
- 新增 endpoint proof 编解码/验签、跨 LAN/relay 身份冲突测试，以及两个真实 relay-only Node
  通过 RelayServer 自动发现、coordinator、WebRTC host candidate 和 mutual `SESSION_HELLO`
  后达到相同 request/session ID 的 authenticated 验收。

本机验证：GCC Debug `-Werror` 定向 M3A/M3B/M4 与 onboarding harness 6/6 通过，其中 M3B
relay 72/72、真实 Node relay-only session 通过；`git diff --check` 通过。据此完成 `M4-02`。
`M4-04`、`M4-07`、`M4-10`、`M4-12`、`M4-16`、`M4-17` 以及 Connectivity MVP 的网络矩阵
退出条件仍保持未勾选，M4 goal 继续 active。

### 第10轮（2026-08-19）

- `connect_request` 的 sender/request ID 现在进入与签名对象共用的有界 replay cache；attempt
  结束不会提前重开 10 分钟 replay 窗口，重复请求、每 peer/全局容量耗尽均 fail closed 并进入
  coordinator/replay diagnostics。offer、answer、candidate 继续按签名域、signer、request/session
  ID、双方 nonce 与 candidate sequence 去重，过期对象在验签阶段拒绝。
- 新增 session transition 回归：完成 offer/answer/trickle 后令双方 attempt 过期、为同一 peer
  建立新 attempt，再注入旧 offer、answer 与 candidate；三者均因旧 request/session binding 在
  coordinator 层拒绝，transport delegate 零调用。
- epoch 门禁保持分层且不破坏 v1 wire/golden vector：每次新物理 transport 使用新的随机
  request/session ID 隔离迟到信令；已验证 DataChannel 上的签名 `SESSION_HELLO` 再绑定
  `session_epoch`，低 epoch 返回 `late_epoch` 且不认证，高 epoch 明确要求建立新 transport。

据此完成 `M4-04`。`M4-07`、`M4-10`、`M4-12`、`M4-16`、`M4-17` 与 Connectivity MVP
网络矩阵退出条件继续保持未勾选，M4 goal 继续 active。

### 第11轮（2026-08-19）

- 内部 `TransportChannel` SPI 新增 `writable()` 与 writable handler。WebRTC channel 达到
  `bufferedAmount` high-water 后进入明确 paused 状态，paused 期间发送稳定返回
  `would_block`；libdatachannel 的 low-water callback 仍先进入 executor-managed 有界事件
  channel，再在 owning runtime context 清除暂停并通知上层，不引入轮询、私有线程或额外队列。
- `WebRtcTransportDiagnostics` 新增 backpressure pause/writable resume 计数；channel 关闭会
  清理 callbacks 且不会发出伪恢复通知。loopback Transport SPI fake 实现相同暂停/恢复契约，
  单元测试固定 `would_block -> non-writable -> peer drain -> one writable notification` 顺序。
- 新增真实 DataChannel 压力测试：256 KiB SCTP 分片触发实际 buffered backlog，验证 high-water
  拒绝、low-water executor callback、恢复可写和重试成功；定向连续运行 5 次通过。

据此完成 `M4-12`。`M4-07` 仍受 pinned libjuice 不支持 TURN/TCP/TLS 的已记录能力边界阻塞；
`M4-10`、`M4-16`、`M4-17` 与 Connectivity MVP 网络矩阵继续推进，M4 goal 保持 active。

### 第12轮（2026-08-19）

- 公共 `NodePeerSessionSnapshot` 新增 transport-neutral 的建连阶段、data path、selected
  candidate、RTT 与 buffered amount；Node 在 owning strand 上合并 attempt timeline 与
  WebRTC `DoubleBuffer` 诊断快照，再通过既有 peer-session `DoubleBuffer` 向 UI 发布，不新增
  跨执行上下文共享状态。失败历史保存实际失败阶段，同时以 closed session state 表达终态。
- TUI 将 endpoint 与 session 分区展示：endpoint 标明 LAN、relay 或合并来源；session 独立显示
  signaling route 和 data path，以及 candidate、RTT、buffered bytes。结构化失败完整显示稳定
  error code、component、safe detail，并在存在时显示 underlying code、peer ID 与 operation ID。
- 新增纯渲染回归覆盖合并来源、checking 阶段、relay signaling + TURN/UDP data path 和完整错误
  字段；真实 LAN Node 会话验证 LAN signaling + direct-host data path，真实 relay-only Node
  会话验证 relay signaling + direct-host data path，从而固定 signaling/data path 不混为一谈。

据此完成 `M4-16`。Connectivity MVP 的 TUI 选择并建连门禁仍未勾选，因为当前验收证明诊断
呈现和 Node 自动会话，但尚未覆盖 TUI 交互选择 endpoint 的完整路径。`M4-07`、`M4-10`、
`M4-17` 与 Connectivity MVP 网络矩阵继续推进，M4 goal 保持 active。

### 第13轮（2026-08-19）

- 新增公共 transport-neutral `PeerPathPolicy`、`NodeIceServer`/`NodeIceServerKind` 与
  `NodeConfig::path_policy_override`：按架构 6.3 的优先级顺序（IPv6 host、LAN IPv4、
  srflx UDP、TURN/UDP、已验证 TURN/TCP/TLS）逐类启停 candidate，`force_turn_data_path`
  将 ICE transport policy 收敛为 relay-only。不引入 libdatachannel 类型，公共头边界
  与逐头独立编译继续通过。
- `default_peer_path_policy` 按 connectivity mode 解析默认策略：`lan_only` 永不配置
  ICE server 且只允许 host candidate；automatic/relay_only 保留全部类别交由 ICE agent
  按网络实际可用性收集。`validate_peer_path_policy` 在 `Node::create` 阶段 fail-fast：
  禁止全部类别、`lan_only` 携带 ICE server/srflx/TURN/强制 TURN、未验证 backend 的
  TURN/TCP/TLS、强制 TURN 缺 TURN server、STUN 携带凭据、TURN 缺凭据、空主机/零端口、
  hostname/credential 长度与 server 数量（<=8）上限均返回稳定 configuration 错误。
- Node 不再硬编码 host-only：`start_webrtc_transport` 将解析后的策略映射为内部
  `CandidatePolicy` 与 ICE server 列表；默认策略下无 STUN/TURN server 时行为与此前
  host-only 等价。候选优先级由 ICE 标准排序实现，pinned libjuice 无 per-candidate
  priority API，类别启停顺序与 relay-only 强制是可用的表达方式。
- 失败显式终止补强：PeerSession 状态回调新增 `TransportState::failed` 分支，保留
  `ice_failed`/`peer_connection_failed` 等真实失败原因，不再让后续 closed 通知伪装成
  干净关闭；`peer_session_changed` 对已 retiring 的 attempt 不再用关闭级联错误（如
  `transport_closed`）覆盖根因错误；500 ms expiry tick 对尚无 PeerSession 的 transport
  检查 failed 快照并显式终止。强制 TURN 指向不可达 server 的 e2e 证明 attempt 在有界
  时间内进入带错误的终态（coordinator `attempt_expired` timeout 或 ICE 失败码）。
- 测试新增 `heyaki_m4_path_policy_tests` 8 项：默认策略随 mode 解析、空类别/lan_only
  冲突/未验证 TCP TURN/强制 TURN 前置/ICE server 字段与容量校验、Node::create
  fail-fast，以及 host-only override 仍完成真实 LAN 双 Node authenticated 会话和
  强制 TURN 无可达 server 的显式终止。测试与 m3a 共享 `heyaki_m3a_profile_state`
  资源锁，避免 LAN 发现 e2e 并发互扰；m3a/TUI 的 `NodeConfig` 指定初始化器同步补齐
  新字段。
- 本轮无新增并发工作负载：策略解析为同步校验，expiry tick 与状态回调复用既有
  strand/timer/executor 通道；按 EXEC-09 复核未引入新的 executor API。

本机验证：GCC 13.3 Debug 全量 CTest 35/35 通过（coturn 两项按环境规则 skip），
`-Werror` 树全量构建干净且 m3a/path-policy/公共头定向通过；禁异常 8/8；ASan 8/8、
UBSan 8/8；TSan（关闭 ASLR）path-policy 8/8、peer-session 3/3、WebRTC transport
3/3 无竞争报告。据此完成 `M4-07`、`M4-17`。`M4-10` 与 Connectivity MVP 的三设备
LAN、网络矩阵、P95、泄漏与 TUI 选择建连退出条件继续推进；正向强制 TURN（经 coturn
真实 allocation）属于网络矩阵门禁，依赖本环境不可用的 CAP_NET_ADMIN/coturn 拓扑。

### 第14轮（2026-08-19）

- authenticated 会话 association 丢失后自动建立新物理 session：`peer_session_changed`
  的 closed 分支在 attempt 失败后调用 `maybe_reestablish_peer_session`，按
  `auto_connect_trusted` 且对端受信任的策略门控，以全新 request/session ID 走完整
  重信令（LAN TLS 或 relay 路由自动选择），每次丢失只触发一次；presence 驱动的
  auto-connect 路径保留为兜底。关闭期（close-peers 阶段）不触发。
- relay WSS 断开不再误杀已认证会话：`relay_failed` 只终止尚无 PeerSession 的
  relay 路由 attempt（与 LAN `signaling_failed` 同一判据）。已认证会话的数据面
  不依赖 relay，仅当 association 自身死亡时经上一条路径重建。
- 新增 e2e `AuthenticatedSessionReestablishesNewPhysicalSessionAfterLoss`：真实
  双 Node 建立认证会话后将对端 Node 连同进程内状态整体销毁，本端会话进入带错误的
  显式 closed 终态；随后对端用同一 profile 重启（同 DeviceId/EndpointId、新 boot
  nonce 与 TLS 端口），本端自动重建 authenticated 会话且 request/session ID 与原会话
  不同，原会话以 closed+error 保留在诊断历史，证明不是无损迁移伪装。本机连续 3 次
  通过；禁异常、ASan、UBSan、TSan（关 ASLR）定向各 1/1 通过。
- 接口变化侧：M3A 的接口扫描在 binding 变化时已重开 discovery socket 并立即刷新
  presence（`announce_now`）；authenticated 会话在 ICE 尚可存活时不被主动拆除。
  `M4-10` 保持未勾选：剩余工作是接口变化时的 in-place ICE restart 重协商。设计
  结论——认证后 LAN/relay signaling 已按第八轮设计关闭，且 offer/answer transcript
  绑定禁止静默重生成描述，因此 in-place restart 必须经已认证 control DataChannel
  携带带签名的重协商帧（session epoch +1、同 session ID）并复用既有
  offer/answer/candidate 签名对象；这是一个独立的协议扩展（round 15 候选），不在
  本轮以"transport 只调 restart_ice 却无处送达新描述"的假实现充当完成。
- 本轮未新增并发原语：重建复用 `start_outbound_connection` 与既有 strand/timer；
  relay 判据修改为纯状态检查。按 EXEC-09 复核无新 executor API。

本机验证：GCC Debug `-Werror` 树全量构建干净，全量 CTest 35/35 通过（coturn 两项
环境 skip），m3a 全套 12.9s 通过；新 e2e 在禁异常、ASan、UBSan、TSan 定向通过。

### 第15轮（2026-08-19）

- CI 基础设施修复：ubuntu-24.04 runner 的 `azure.archive.ubuntu.com` apt 镜像停滞
  且不触发 per-read 超时，第十四轮提交的 coturn-topology job 因此在 10 分钟步超时
  失败（其余 9 job 全部成功）。安装步骤现把 apt 源固定为失败日志中证实可达的
  `archive.ubuntu.com`。
- 新增 e2e `ThreeLanNodesEstablishAuthenticatedHostDataChannels`：三个无 relay、
  无 STUN/TURN（`lan_only` 默认策略即 host-only 且零 ICE server）的真实 Node 在
  同一 LAN 各自发现另外两台设备的正确 endpoint，三对配对并发建连全部达到双方
  authenticated，data path 均为 `direct_host` 且 selected candidate 非空；同一
  Node 的两个会话 session ID 互不相同，证明三路并发 attempt 不串扰。本机连续
  3 次通过；ASan、UBSan、TSan（关 ASLR）、禁异常定向各 1/1 通过。
- 据此勾选 Connectivity MVP 第一条退出条件（三设备 LAN host-candidate 认证
  DataChannel）。网络矩阵、伪造审计、LAN+relay 仲裁、P95、泄漏与 TUI 选择建连
  退出条件与 `M4-10` 的 in-place ICE restart 重协商继续推进。

### 第16轮（2026-08-19）

- 伪造/替换矩阵补齐"双方都拒绝"的发起方侧证据并完成逐向量审计：
  - LAN hello 证书指纹替换与 LAN MITM：`RejectsRelayedHelloAndCertificateSubstitution`
    （M3A，TLS 双证书替换 + hello relay 拒绝）。
  - offer/DTLS fingerprint 字节篡改（响应方拒绝）：
    `TamperedOfferNeverReachesSession`。
  - answer 字节篡改（发起方拒绝，本轮新增）：
    `TamperedAnswerNeverReachesInitiatorSession`——篡改 answer 任意字节在
    验签层拒绝，`on_verified_answer` 不触发、无 verified binding。
  - endpoint 篡改（本轮新增）：`ResignedAnswerWithSwappedEndpointsRejected`——
    攻击者用响应方真实密钥重签但交换 initiator/responder endpoint，发起方按
    binding mismatch 拒绝；LAN MITM/relay 即使持有效签名也无法改绑身份。
  - nonce/重放：`DuplicateOfferDeliveryIsRejected`、`M4ReplayCache.*`、
    `OfferRejectsResponderNonceAndAnswerRequiresIt`。
  - expiry：`ExpiryWindowEnforced`。
  - 未知身份冒充（relay 转发伪造签名对象）：`UnknownPeerIdentityRejected`；
    relay 全程不解码 payload（M4-02 转发测试），任何篡改字节走与 LAN 路由相同
    的设备端验签路径。
  - candidate 绑定（transcript/ufrag/fingerprint/sequence）：
    `CandidateBindingViolationsRejected`。
- 本地并行 CTest 偶发失败定位与修复：`-j4` 下其他无共享资源锁的 LAN 测试
  （如 M3B onboarding harness 的 TUI/demo 节点）会向同一 multicast group 发
  presence，使按目录大小断言（`endpoints().size()==N`）的 e2e 永不满足。本轮
  起 M4/M3A 新增 e2e 全部改为等待发现**具体对端 endpoint key**，语义即"发现
  正确 endpoint"；连续 3 次 `-j4` 全量 CTest 35/35 通过。CI 为串行执行不受
  影响。
- `heyaki_m4_signaling_tests` 现 22 项（新增 2），ASan/UBSan 定向 22/22 通过。

据此勾选第三条退出条件（伪造/替换双方拒绝）。剩余：网络矩阵、LAN+relay 仲裁
与单 winner、P95、泄漏、TUI 选择建连退出条件及 `M4-10` in-place ICE restart。

### 第17轮（2026-08-21）

- 新增双路由 e2e `DualRouteNodesDedupEndpointsAndPreferLanByPolicy`：两个 Node
  同时启用 LAN discovery（真实 multicast presence）与 relay enrollment（真实
  TLS/WSS RelayServer 登录、heartbeat、endpoint publish/query），等待对端在
  EndpointDirectory 中合并为**单一条目且同时携带 lan 与 relay hint**（去重证
  据），随后 `connect()` 在 automatic 策略下选择 LAN 信令路由，双方各只有
  一个 authenticated 会话（单 transport winner）、data path 为 direct_host、
  session/request ID 一致。
- 新增 `AutomaticFallsBackToRelayWhenLanHintAbsent`：automatic 策略在对端无
  LAN hint、仅 relay hint 时回退 relay 信令路由并完成认证，同样单会话收尾；
  与既有 `NodesAssembleAuthenticatedSessionOverRelayOnlyRoute`（relay_only 强
  制）及 `select_signaling_route` 单元矩阵共同覆盖"策略控制"三分支
  （LAN 优先 / 回退 / 强制）。
- 目录级身份冲突拒绝（同 endpoint LAN/relay 公钥不一致）由既有
  `RejectsIdentityConflictAcrossLanAndRelayHints` 覆盖；TLS/attempt 层单一
  connection 仲裁由 M3A 既有测试覆盖。
- `heyaki_m3b_relay` 测试现在包含启用 LAN 的 e2e，CTest 增加
  `heyaki_m3a_profile_state` 资源锁避免与 m3a/网络 harness 的 LAN 发现并发
  互扰。本机连续 3 次通过；ASan、UBSan 定向通过；全量 `-j4` CTest 35/35。

据此勾选第四条退出条件（LAN/relay 去重、策略路由与单 winner）。剩余：网络
矩阵（需 CAP_NET_ADMIN/coturn 环境）、P95、泄漏、TUI 选择建连退出条件与
`M4-10` in-place ICE restart。

### 第18轮（2026-08-21）

- 新增 `RepeatedAssociationLossCyclesStayBounded`：5 轮"认证会话 -> 对端整体
  销毁 -> 显式 closed+error 终态 -> 同 profile 重启 -> 新 session ID 重建"循环。
  每轮断言：丢失会话进入带错误的终态、立即重建的失败 TLS 连接完全排干
  （`resources.signaling_connections == 0`）、对端 endpoint 在目录中始终只有
  一个合并条目（跨 boot nonce 不累积）；结束后诊断会话历史有界（恰为循环数
  的 closed+error + 少量余量）。本机连续 3 次通过，ASan、TSan（关 ASLR）定向
  通过，全量 `-j4` CTest 35/35。
- 该测试与 ForcedTurn 显式终止、shutdown 排空断言、M3A LAN 压力测试、M2
  runtime/executor 测试共同构成第六条退出条件的 session 层证据。退出条件仍
  保持未勾选：剩余工作为系统化枚举全部失败/取消/关闭路径（含 coordinator
  replay cache 的外部可观测泄漏断言——当前仅有单元级容量/TTL 测试）与网络
  harness 压力下的 M4 会话循环。

### 第19轮（2026-08-21）

- `heyaki-tui` 的 Node 不再注入自定义 `signaling_handler`，M4 自动会话装配
  （coordinator + WebRTC + PeerSession）在 TUI 进程内直接生效；渲染层只消费
  有界 latest-only 快照。基于 M3A 人工 accept/deny 信令的 `pair/accept/deny`
  命令与配套 helper 移除（M5 将以真实 pairing 协议重新交付配对 UI）。
- `connect N` 命令从 `connect_lan` 改为 transport-neutral `Node::connect()`：
  从 LAN/relay 合并目录按 connectivity policy 选路，SESSIONS 视图展示实际
  signaling route 与 data path。REPL 提示更新为
  `command [refresh|relay|connect N|close N|quit]`（前缀保持，既有 pty 驱动
  步骤兼容）。
- 新增 `heyaki_m4_tui_session_harness`（Linux pty，77 skip 语义，资源锁与
  m3a 共享）：两个独立 profile 的 `heyaki-tui` 实例各自完成本地初始化
  （pre-init 菜单 + 隐藏密码输入），LAN 相互发现后，驱动解析 TUI A 合并
  endpoint 列表中 B 的条目索引并发送 `connect N`；断言 A 的 SESSIONS 出现
  `authenticated  signaling=lan  data=direct_host` 且 B 侧同时 authenticated，
  进程以 quit 正常退出。pty 驱动处理 CRLF 归一化、按命令重渲染（REPL 只在
  命令后重绘）与 LAN 不可达时的 77 skip。
- 回归：m3b onboarding harness、tui local status/version/setup 全部通过；
  全量 CTest 36/36（含新 harness），连续 3 次通过。

据此勾选第七条退出条件（TUI 合并列表选择建连）。剩余：网络矩阵（需
CAP_NET_ADMIN/coturn 环境）、P95、泄漏全枚举退出条件与 `M4-10` in-place
ICE restart 重协商。

### 第20轮（2026-08-21）

- 新增 `heyaki_m4_session_latency`（performance 标签，共享 m3a LAN 资源锁）：
  10 轮独立双 Node 循环，测量 `connect_lan` 准入到 authenticated 的端到端
  建连时长并计算 P95。本机 Debug P95=1086ms（min 1036/max 1086），ASan
  P95=1121ms、TSan（关 ASLR）P95=1110ms，全部低于 3000ms 目标并保留约 3 倍
  余量；无 LAN 接口环境按既有规则 skip，`HEYAKI_REQUIRE_LAN_INTERFACES=1`
  时失败。
- 第五条退出条件保持未勾选：直连（可打洞环境）半边已有测量证据；"直连失败
  TURN fallback P95 < 5s" 半边需要真实 coturn allocation 的网络拓扑环境
  （CI coturn-topology job 或 CAP_NET_ADMIN 专用环境），与网络矩阵门禁同批
  补跑。

### 第21轮（2026-08-22）

- `NodeSnapshot` 新增公共 `NodeSessionCoordinatorDiagnostics`：coordinator 的
  尝试计数（current/peak attempts、expired/closed）与签名对象 replay guard
  深度（current/peak entries）在 peer-session 变化时于 owning strand 发布。
  executor 设施仍是任务健康事实源，该结构只覆盖协议状态。
- `RepeatedAssociationLossCyclesStayBounded` 相应增加外部可观测有界断言：
  每轮排空后 coordinator `current_attempts == 0`，replay entries 始终在
  容量内（<=4096），peak attempts 有界（<=8）。
- Windows Release CI 时序整改：双路由与 relay 回退 e2e 的认证等待预算从
  10s 提高到 25s（relay 登录/publish/query + WebRTC 握手在双核 Windows
  Release runner 上偶发超过 10s；第 17 轮同流程通过证明为临界预算而非功能
  回归），双 hint 合并等待提高到 15s。
- 第 19 轮 CI（1e3cb5b，TUI 选择建连）success；第 20 轮 CI（f597b1f）仅在
  Windows Release 的上述时序用例失败，其余 9 job 成功。

### 第22轮（2026-08-24）

- **`M4-10` in-place restart 以 protocol 1.2 minor 变更落地**。调研确认 pinned
  libjuice 在 `agent_set_remote_description` 中显式拒绝 ICE 凭据更换
  （"ICE restart is not supported"），因此按第 14 轮设计结论实现控制通道重协商：
  新增 `Capability::session_restart_v1`（bit 12，minor>=2 才可协商）、帧类型
  `SESSION_RESTART_OFFER/ANSWER/CANDIDATE`（0x06-0x08，复用冻结的
  `heyaki.offer/answer/candidate.v1` 签名对象与负载编码）。公共
  `SessionRestartAdmission` 在会话两侧验签、绑定 endpoint/session id、管理
  nonce/transcript/candidate sequence、复用 `SignalingReplayCache`，并以
  request-id 大端比较实现确定性 glare 仲裁（输方中止自己并应答赢方）。
  Node 以 `Node::restart_session()` 或接口绑定集变化触发：新建 transport 的
  offer/answer/candidate 经旧会话已认证 control DataChannel 送达，对端准入后
  在新 transport 上重新互发签名 `SESSION_HELLO`（同 SessionId、epoch+1），
  成功后旧物理会话以 local_shutdown 显式退役并进入有界诊断历史；deadline、
  cooldown（关闭已完成 restart 对象的重放窗口）、容量与失败路径全部有界。
  语义上明确不是无损迁移：旧 transport 缓冲帧在切换时丢弃。
- **泄漏全枚举**：新增 `heyaki_m4_shutdown_matrix`（10 用例）枚举 9 类本地可注入
  失败/取消/关闭路径（各生命周期阶段 shutdown、认证后 shutdown、restart 在途
  shutdown、association loss、未知 endpoint 拒绝、close_lan 取消），统一断言
  Asio timer/socket/信令连接、coordinator attempt、replay 容量与 restart 残留
  全部归零或有界；文件头列出全部 13 类路径到具体测试的映射。
- **网络矩阵**：本地新增 `heyaki_m4_topology_matrix`（同 DeviceId 双 endpoint
  各自独立建连、双向同时 dial 单 winner 仲裁）；CI 侧新增
  `deploy/coturn/run_network_matrix.sh` + `heyaki-m4-matrix-node` 参与者二进制
  与 `heyaki_m4_network_matrix` 测试（root/coturn 缺失时按 77 skip），在双
  namespace + host coturn/relay 拓扑中运行 direct、forced_turn、turn_fallback
  （6 循环 P95<5s 断言）、udp_blocked（显式有界失败，TURN/TCP 受 pinned
  backend 能力边界限制不可用）、lossy（netem 100ms/10%）与 relay_restart
  （relay 中途重启后既有 TURN 会话存活且重新登录）六个场景。
- **协议 1.2 变更控制**：wire protocol 文档升级至 1.2（新增 §2.3 restart 语义、
  帧表与 capability 位）；版本契约检查改为"运行时 minor ≥ 冻结向量 minor"；
  presence/hello/session-hello 默认宣告 `protocol_1_2_capability_bits`。
- **fuzz**：restart 不引入新 wire 格式——其解析面完全复用已在 parser fuzz
  harness 中的冻结签名对象 codec；admission 状态机由 7 项单元矩阵 + e2e +
  shutdown matrix 在 sanitizer 下覆盖。
- 测试计数：`heyaki_m4_session_restart` 7、`heyaki_m4_session_restart_e2e` 3、
  `heyaki_m4_shutdown_matrix` 10、`heyaki_m4_topology_matrix` 2；本机 GCC Debug
  全量通过（coturn 两项环境 skip）。
- **CI 网络矩阵证据（run 32801103705，c3f94ef）**：direct（direct_host 759ms）、
  turn_fallback 六循环全部 authenticated turn_udp（709-871ms，P95≈871ms ≪5s
  门禁）、udp_blocked 显式有界失败、lossy（netem 100ms/10%）4768ms
  authenticated；`forced_turn` 双方 relay-only 需 relayed<->relayed 提名，在
  pinned libjuice（libdatachannel 仅过滤本地候选）+ coturn 组合下 allocation 与
  permission 均成功、检查流经双实例但从不提名——与 TURN/TCP 同类 pinned 栈能力
  边界，矩阵以 `SCENARIO_BOUNDARY` 显式报告（有界、不挂起），TURN 强制数据路径
  本身由 fallback 六循环在阻断直连的拓扑下证明。连带修复：coturn 测试拓扑带宽
  配额（max-bps 预留制，基线仅容 8 个并发 allocation，曾致 cycle4+ 全部 486）、
  双实例端口冲突（模板 alt 监听 3479）、bootstrap token 次数、矩阵参与者 CLI
  argc、m3a ASan/Windows 慢机的 discovery 预算与 relay_restart 场景脚本加固。
