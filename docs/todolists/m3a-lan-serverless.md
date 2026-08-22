# M3A：LAN Discovery、TLS 本地信令与本地 Onboarding

> - 状态：已完成，2026-08-16 关闭
> - 所属计划：[Heyaki MVP 至 v1 实施 TODO 计划](heyaki-implementation-plan.md)
> - 前置：M2 | 建议发布点：Serverless control-plane alpha

M3A 与 M3B 都依赖 M2，可并行实施。M3A 是 serverless Connectivity MVP 的前置；M3B 扩展
广域 presence、NAT fallback 和集中运维。两条路径必须收敛到同一 `EndpointDirectory`、
`SignalingRoute` 与签名信令状态机，禁止各自复制会话和授权逻辑。

## 协议 1.1 LAN 扩展与配置

- [x] `M3A-01` 以协议 1.1 可选能力冻结 `lan_discovery_v1`/`lan_signaling_v1` capability；同一提交更新 CMake/build info、wire 文档、schema 和 golden vectors。
- [x] `M3A-02` 新增 discovery schema，并冻结无冲突的 IPv4/IPv6 multicast group、UDP port、datagram envelope/max wire size；定义有界 `LanPresence` 的设备公钥/ID、endpoint、boot nonce、sequence、relative lease、TLS port、能力和签名。
- [x] `M3A-03` 新增 `LAN_HELLO` schema 与 `lan_presence`/`lan_hello` canonical signing domain；hello 绑定双方身份/endpoint/nonce/boot nonce 及本端和对端 TLS 证书指纹。
- [x] `M3A-04` 实现 1.0/1.1 协商与 N-1/N 测试；1.0 peer 不得因未知可选能力失败，1.1 peer 不得向 1.0 peer 假定 LAN 支持。
- [x] `M3A-05` 为 Node/ProfileStore 增加 `automatic/lan_only/relay_only`、LAN enabled、discoverability、`auto_connect_trusted`、接口偏好、容量与 deadline 配置；非法或零控制容量启动失败。
- [x] `M3A-06` 明确本地初始化独立于 relay enrollment：profile 创建身份、endpoint、verifier 和 pairing policy 后即可进入 LAN-only readiness。

## Multicast discovery 与 endpoint directory

- [x] `M3A-07` 使用现有 executor-managed Asio runtime 在每个允许接口加入 IPv4 管理域和 IPv6 link-local multicast group，hop limit 固定为 1，不创建第二 worker/线程/poll loop。
- [x] `M3A-08` 实现带 jitter 的签名 presence announce/browse、monotonic lease、boot/sequence replay 检查和接口加入/离开/休眠恢复；单 datagram 不超过无分片配置上限。
- [x] `M3A-09` 在分配/缓存前验证 Protobuf 长度、版本、公钥派生 DeviceId、签名、endpoint、lease 和 sequence；未知自签身份保持 untrusted。
- [x] `M3A-10` 实现有界 `EndpointDirectory`，按完整 `(DeviceId, EndpointId)` 合并 LAN/relay 来源和 TTL；LAN hint 过期不撤销 TrustGrant 或删除 relay presence。
- [x] `M3A-11` 对目录、每接口、每源地址、未知身份、公告速率和诊断历史设置硬上限；满载保留已信任控制容量并显式拒绝。
- [x] `M3A-12` presence 不广播 display name、tenant、service manifest、scope、credential 或其他接口拓扑；日志按 identifier retention policy 处理完整 ID。

## TLS 本地信令与 TUI

- [x] `M3A-13` 复用项目冻结的 OpenSSL 系列，以 Asio TLS 1.3/TCP 实现 boot-scoped certificate、动态监听端口、client/acceptor、握手 deadline 和有界 provisional connection。
- [x] `M3A-14` TLS 建立后只允许限长 `LAN_HELLO`；验证签名、公钥派生 ID、role、双方 nonce、boot nonce、版本和双方证书指纹后才进入 `AuthenticatedSignaling`。
- [x] `M3A-15` 实现内部 `DiscoveryProvider`、`EndpointDirectory`、`SignalingRoute` 和 `LanSignalingRoute`，只转发通过校验的 connect/accept/deny 与现有 signed offer/answer/candidate。
- [x] `M3A-16` 实现 LAN 优先、relay fallback preference、单逻辑 attempt/transport winner、自动连接 offer owner 和手工交叉连接的确定性仲裁。
- [x] `M3A-17` 关闭时在 `stop_producers`/`close_peers` hook 中依次停止公告/lease/timer、关闭 multicast socket/TLS listener/pending signaling，再释放 directory/route；所有 wait 有预算和终态。
- [x] `M3A-18` TUI 本机/LAN 视图展示 profile 初始化、接口 readiness、发现来源、untrusted/trusted endpoint、signaling/data path、配对入口和结构化失败，不把“已发现”显示成“已授权”。

## 测试与退出条件

- [x] golden vectors、Protobuf parser 和状态机 fuzz 覆盖 LAN presence/hello 的截断、超大、未知字段、签名冲突、boot/sequence replay 和 capacity-full。
- [x] 安全测试覆盖 multicast 洪泛/伪造、TLS slowloris/洪泛、每 IP 限速、证书指纹替换、双 TLS MITM/hello relay、版本降级和未认证 SDP/candidate。
- [x] Linux/Windows 可在 relay/STUN/TURN 全部未运行时双向发现；IPv4-only、IPv6 link-local、双栈、多网卡、接口切换和同 DeviceId 多 endpoint 均有稳定结果。
- [x] multicast blocked、Windows firewall/public network、AP isolation 模拟进入可解释失败，不挂起、不声称 LAN ready。
- [x] 发现/过期/交叉连接/取消/关闭压力下，socket、TLS、timer、operation、directory/replay cache 和 executor worker 无泄漏或无界增长。

## 验收记录

### 协议 change-control 验收记录（2026-08-15）

构建版本与公共协议版本升级为 1.1，冻结
`lan_discovery_v1`/`lan_signaling_v1` bits、`HYLD` v1 envelope、IPv4 `239.192.72.89`、IPv6
`ff12::4845:5941:4b49`、UDP `49189`、hop limit `1` 和 1200-byte datagram 上限；新增 Lite
`LanPresence`/`LanHello` schemas、两个 canonical signing domain 和经 Ed25519 独立验证的 golden
vectors。协议、来源一致性、Protobuf Lite、公共头及 fuzz smoke 针对性测试 5/5 通过；M1 1.0
golden vector 保留为 N-1 基线，1.1/1.0 协商不会泄漏 LAN capability。replay、capacity 和网络状态机
覆盖属于 M3A-07 之后的退出条件，仍保持未勾选。

### 本机实现验收记录（2026-08-16）

Profile schema v3、独立本地初始化、双栈逐接口
multicast、签名 presence 与有界 directory、boot-scoped TLS 1.3、三消息 `LAN_HELLO`、有界 LAN
signaling frame、确定性连接仲裁、executor-managed callback/lifecycle 和本机/LAN TUI 已接通。
Debug 全量构建及 CTest 22/22、ASan 定向 5/5、UBSan 定向 4/4 通过；TSAN 二进制完成构建，
但当前 Linux 宿主以 `ThreadSanitizer: unexpected memory mapping` 被测试包装器明确标记为不支持。
本机测试覆盖双 Node 无 relay 发现、TLS 身份绑定、认证前 signed signaling 拒绝、validator 拒绝、
同源 provisional TLS 限速与握手超时、trusted auto-connect、重复连接仲裁和有预算关闭。以下
网络、安全、跨平台和压力矩阵的后续补强与剩余门禁记录如下。

### 网络与安全矩阵补强记录（2026-08-16）

新增 LAN directory replay/capacity 状态机 fuzz
target 与 corpus seed，状态机本体由 libFuzzer target 直接编译以保留 coverage instrumentation；
本机缺少 Clang/libFuzzer，真实短跑等待远端 Clang Debug CI。Linux user/network namespace harness
现强制执行 IPv4-only、IPv6 link-local、双栈四接口、接口 down/up 刷新及 nftables 阻断
multicast 场景，覆盖无 relay 的发现、TLS/信令、同 DeviceId 多 endpoint、12 轮连接关闭及有预算
失败。安全测试补充伪造 multicast 洪泛容量约束、hello relay 与 TLS 双证书指纹替换拒绝；既有
测试继续覆盖 TLS provisional connection 容量、每源限速、握手超时、版本降级和认证前 signed
signaling 拒绝。GCC Debug 全量 CTest 22/22、强制 network harness、ASan 定向 3/3、UBSan
定向 3/3 通过；TSAN 目标构建通过，但宿主仍因 `ThreadSanitizer: unexpected memory mapping`
明确 skip。Windows Debug/Release、Windows firewall/public network、AP isolation 与长期外部压力
尚无本轮证据，因此对应退出条件继续保持未勾选。

### 跨平台 CI 确认（2026-08-16）

代码提交
`a967d73f23ae46285a46e4be0ac2cfc30b428414` 对应 GitHub Actions run `31902837405`
结论为 success，9 个 job 全部通过：Linux GCC/Clang Debug/Release、Windows Debug/Release、
ASan、UBSan 和 TSAN。Linux 四个构建组合均强制运行真实 network namespace harness；Clang
Debug 额外执行 `heyaki_lan_state_fuzzer` 100 次 smoke。Windows Debug/Release 在
`HEYAKI_REQUIRE_LAN_INTERFACES=1` 下完成全量 CTest，确认无 relay 的双向发现、TLS 本地信令和
同 DeviceId 多 endpoint 测试不能以无接口 skip 冒充成功。远端整改同时确认 GitHub Hosted
Runner 使用 passwordless root network namespace 时仍执行相同 IPv4-only、IPv6 link-local、
双栈多接口、接口切换与 multicast blocked 场景；MSVC `/WX`、OpenSSL 测试 include 和 TUI
Windows 宏配置均已通过。由此 fuzz 与 Linux/Windows 发现退出条件完成；Windows firewall/public
network、AP isolation 及长期外部压力仍需专用环境，不在本次记录中宣称通过。

### 最终退出验收（2026-08-16）

代码提交
`510f696675b65ed847da128de78e084e6f3eb728` 对应 GitHub Actions run `31907250422`
结论为 success，Linux GCC/Clang Debug/Release、Windows Debug/Release、ASan、UBSan 和 TSAN 共
9 个 job 全部通过。Linux GCC Debug 在强制 network namespace harness 下完成 22/22 CTest、
multicast blocked 与 AP isolation 故障模拟，并以 64 轮 x 3 epoch 执行发现、过期、交叉连接、
取消、关闭和 Node 重建压力。Windows Debug/Release 均完成 23 项 CTest；专用 harness 将活动网络
切换为 Public profile，临时安装 UDP 49189 入站/出站阻断规则并验证可解释失败，随后恢复 profile
和规则，压力参数为 16 轮 x 2 epoch。ASan、UBSan、TSAN 均在强制 sanitizer runtime 下以 32 轮
x 3 epoch 完成全量测试与 fuzz smoke；资源快照和关闭报告确认 socket、TLS listener、timer、
signaling operation/callback、通信队列、directory/replay cache 与 executor worker 保持配置上限，
最终资源计数归零。至此 M3A 两项剩余退出条件完成。
