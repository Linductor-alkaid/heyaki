# Heyaki 局域网无服务器连接设计

> 状态：v1 设计基线，wire protocol 1.1 扩展待 M3A 冻结
> 日期：2026-08-15
> 适用范围：Linux/Windows 设备端、`heyaki-tui`、局域网发现、本地信令与 WebRTC 直连
> 上位设计：[Heyaki 设备通信基础设施设计](heyaki-architecture.md)

## 1. 目标与边界

Heyaki 在没有 `heyaki-relay`、STUN 或 TURN 的情况下，应能在同一局域网内发现其他 Heyaki
endpoint，完成相互认证的 WebRTC 信令，并使用 host ICE candidate 建立 DataChannel。消息、
RPC、事件、文件、Shell、配对和 TrustGrant 继续运行在现有 `PeerSession` 与服务协议之上。

本文中的“无服务器”表示不依赖中心化网络服务。每个 Node 仍会临时监听本地信令端口，但它
不是需要单独部署或运维的服务端组件。

v1 的明确边界：

- 只保证同一二层 multicast domain 内的自主发现，不保证跨 VLAN、路由子网或被隔离的访客
  Wi-Fi；
- 不绕过操作系统防火墙、AP client isolation 或企业网络策略；
- 无 relay 时没有 TURN fallback，host candidate 失败必须返回明确终态；
- 不把局域网内所有设备自动组成全连接 mesh；发现自动进行，连接按信任与策略按需建立；
- 不新增业务 transport，数据面仍为 `WebRtcTransportSession`；
- 不把发现公告、源 IP 或 TLS 建连成功当作设备授权证明。

## 2. 设计决策

| 主题 | v1 决策 | 原因 |
| --- | --- | --- |
| 发现协议 | Heyaki 自有的有界 UDP multicast + Protobuf | 无系统 daemon 依赖，可复用现有 parser/fuzz 基线并接入 Asio |
| 地址范围 | IPv4 管理域 multicast 与 IPv6 link-local multicast，hop limit 为 1 | 明确限定本地链路，不意外形成跨网段发现协议 |
| 本地信令 | Boost.Asio TLS 1.3/TCP，复用项目统一 OpenSSL 系列 | 保护 SDP、candidate 和设备元数据免于被动监听 |
| 信令认证 | Ed25519 签名的 `LAN_HELLO` 绑定双方 TLS 证书指纹与 nonce | 自签名 TLS 证书不承担设备身份或授权职责 |
| 数据面 | 无 ICE server 的 libdatachannel host candidate | 复用既有 DTLS/SCTP/DataChannel 与上层协议 |
| 自动连接 | 仅对已信任且策略允许的 peer 自动连接 | 避免未知设备触发业务通道和平方级 session 增长 |
| 可见性 | 启用 LAN 模式时广播完整 `DeviceId`/`EndpointId`，不广播名称和服务清单 | 支持签名校验与去重；接受局域网身份可枚举的残余风险 |
| mDNS/DNS-SD | 保留 `DiscoveryProvider` 扩展点，v1 不交付 | 避免 Linux/Windows 系统 API、daemon 和生命周期差异阻塞主路径 |

LAN 模式必须可按 profile/Node 关闭。Windows public network profile、系统防火墙拒绝或接口
不支持 multicast 时，Node 应报告受影响接口和稳定失败原因，不能声称已经可发现。

## 3. 组件与数据流

```text
Node
  -> DiscoveryCoordinator
       -> MulticastDiscoveryProvider
       -> EndpointDirectory
  -> SignalingCoordinator
       -> LanSignalingRoute
       -> RelaySignalingRoute
  -> PeerSession
       -> WebRtcTransportSession
```

内部契约建议为：

- `DiscoveryProvider`：启动/停止公告与浏览，输出有 TTL 的未授权 endpoint hint；
- `EndpointDirectory`：按完整 `(DeviceId, EndpointId)` 合并 LAN/relay 来源、记录来源 TTL 与
  验证状态，不提升授权；
- `SignalingRoute`：承载 connect request、accept/deny、offer、answer 和 trickle candidate；
- `SignalingCoordinator`：执行路由选择、交叉连接仲裁、replay 检查和逻辑 attempt 生命周期；
- `TransportSession`：只消费通过身份、绑定和状态机校验的信令对象。

这些接口属于内部 SPI，不构成 v1 第三方插件 ABI。业务公共 API 只观察 endpoint、session、
连接策略和结构化状态。

## 4. 局域网发现

### 4.1 Presence 公告

计划新增 `proto/heyaki/discovery/v1/discovery.proto`。`LanPresence` 至少包含：

```text
protocol major/minor, supported/required capabilities,
DeviceId, identity public key, EndpointId,
boot nonce, monotonically increasing announcement sequence,
TLS signaling port, relative lease, signature
```

协议 1.1 评审必须同时冻结 IPv4/IPv6 multicast group、UDP port、datagram magic/type 和最大
wire size，检查与常见 discovery 协议/端口的冲突，并为防火墙和抓包诊断提供稳定配置说明。
普通 profile 不得改成不同 group 后仍声称具备默认互操作性；测试可使用显式隔离配置。

签名使用计划中的 `heyaki.lan-presence.v1` domain。接收方必须先检查 datagram、字段和
Protobuf 上限，再验证公钥派生的 `DeviceId`、签名、版本、lease、boot nonce 和 sequence。
UDP 源地址作为本次可达地址 hint，不进入设备身份，也不覆盖签名对象中的 endpoint。

公告不得包含：

- display name、tenant、service manifest 或授权 scope；
- relay enrollment、TrustGrant、配对密码/verifier；
- 私网拓扑、其他接口地址或业务 payload。

单个 datagram 必须低于配置的无分片上限。公告周期加入随机 jitter；接收方从收到公告时
启动本地 monotonic lease，不以设备 wall clock 判断在线状态。相同 boot nonce 下 sequence
倒退、签名字节冲突或过期公告都被拒绝并计数。

### 4.2 接口与缓存

Node 在每个允许的非 loopback multicast 接口上分别加入 IPv4/IPv6 group。接口加入、离开、
地址变化或休眠恢复触发受控的 socket 更新和 presence 重发，不创建新的线程或事件循环。

`EndpointDirectory` 必须有全局、每接口和每源地址容量。满载时拒绝新的未知 endpoint，保留
已信任 peer 和控制容量，并暴露 reject/expiry/duplicate/conflict 统计。来源消失只表示当前
LAN hint 过期，不撤销 TrustGrant，也不删除 relay presence。

发现签名只能证明“该公告由其携带的私钥对应身份生成”，不能证明该身份受信任。恶意局域网
设备仍可批量生成新身份，因此所有未知 endpoint 都保持 untrusted。

## 5. TLS 本地信令

### 5.1 TLS 与身份绑定

每个 Node 启动时生成 boot-scoped TLS key/certificate，监听动态或配置端口。TLS 使用项目统一
冻结的 OpenSSL 系列。证书不需要公共 CA，不持久化为 Heyaki 身份，也不进入 TrustStore。

TLS 握手完成后，连接处于 `ProvisionalTls`，只能交换严格限长的 `LAN_HELLO`。双方的签名
hello 必须绑定：

```text
role, sender/peer DeviceId and EndpointId,
sender identity public key,
initiator/responder nonce,
sender TLS certificate fingerprint,
observed peer TLS certificate fingerprint,
boot nonce, protocol/capabilities, relative expiry
```

双方都必须验证签名、公钥派生 ID、role、nonce、两个证书指纹、版本和 expiry。任一不匹配都
关闭 TLS 连接，且不得把后续 SDP/candidate 交给 libdatachannel。只有完成该校验后，状态才进入
`AuthenticatedSignaling`。

绑定本端与对端两个证书指纹是主动 MITM 防护的一部分：中间人可以终止两个自签名 TLS 会话，
但不能修改真实设备签名的证书绑定。签名验证前不得发送授权密码、TrustGrant 或业务数据。

### 5.2 信令复用

身份绑定完成后，LAN route 复用协议 1.0 已定义的 `SignedOffer`、`SignedAnswer` 和
`SignedCandidate`，不另建一套 SDP 语义。现有规范化签名、双方 ID/endpoint、request/session
ID、nonce、expiry、DTLS fingerprint、ICE ufrag 和 signaling transcript 规则保持不变。

本地 TLS 连接只承载当前连接 attempt 的控制消息。DataChannel 完成 `SESSION_HELLO` 并验证
实际 signaling transcript 后，或 attempt 进入失败/取消终态后，LAN signaling 连接应及时关闭。

## 6. WebRTC 与路径选择

纯 LAN 模式不给 libdatachannel 配置 STUN/TURN server，只收集可用接口的 IPv6/IPv4 host
candidate。候选仍由签名信令交换，DTLS fingerprint 仍按现有规则验证。

`PathInfo` 必须把两个维度分开：

```text
signaling_path = lan | relay
data_path      = direct_host | direct_srflx | turn_udp | turn_tcp | turn_tls
```

经 relay 信令建立的会话也可能使用 LAN host candidate；经 LAN 信令发起的会话在 relay/TURN
可用时也不应被错误标记为“LAN 数据路径”。业务服务不得按这些路径分支授权或协议语义。

自动策略默认为：

1. 已验证 LAN presence 存在时优先尝试 LAN signaling；
2. relay 同时可用时可在有界 preference delay 后启动 fallback，但一个逻辑 attempt 只允许一个
   transport winner；
3. LAN-only 模式失败后返回明确错误，不暗中等待不存在的 relay；
4. `relay_only`、`lan_only` 和测试强制 candidate 策略必须可配置；
5. 路由切换建立新物理 session，不伪装为原连接无损迁移。

## 7. 配对、信任与多设备策略

“已登记身份”不能继续等同于“已登录 relay”。进入 pairing channel 的前置条件改为：来源已在
当前 DataChannel 上完成长期公钥身份与 signaling transcript 验证。该身份可经 LAN 或 relay
路径到达，但匿名 UDP/TLS 来源永远不能直接提交配对密码。

未知设备只进入 `PairingRestricted`；已存在有效 TrustGrant 的设备才可根据 scope 进入
`Authorized/Active`。授权密码仍只在 DTLS DataChannel 中发送，本地 TLS 信令层不得承载密码。

发现默认不创建全连接 mesh：

- 未知设备只进入可发现列表，需用户或明确 pairing policy 发起连接；
- 已信任设备仅在 `auto_connect_trusted`、目标服务需求和 peer 容量均允许时自动连接；
- 自动连接交叉发起时，以完整 `(DeviceId, EndpointId)` tuple 的确定性顺序选择 offer owner；
- 手工交叉连接或重试产生重复 attempt 时，以规范化 attempt key 选择唯一 winner；
- 每设备 active/pending peer 数、每源 IP provisional TLS 数和全局连接数均有硬上限。

同一 `DeviceId` 的多个进程分别广播自己的稳定 `EndpointId`。目录按 endpoint 路由，TrustStore
默认仍按 device 授权；endpoint/service policy 可以进一步收窄权限。

## 8. Executor 与生命周期

UDP multicast socket、接口变化处理、TLS acceptor/client、握手 deadline、lease timer 和本地
信令读写全部使用进程现有 Boost.Asio `io_context`。该 `io_context::run()` 继续由 executor
注册的 `BlockingIoWorker` 承载，不新增 `std::thread`、独立 poll loop 或第三方后台 worker。

所有外部/第三方 callback 只做有界校验和投递。逐条发现/信令事件使用
`executor::comm::MpscChannel`，低频 endpoint/session 快照使用 `DoubleBuffer`，可覆盖计数或
进度使用 `LatestMailbox`。channel admission 不是协议完成；connect operation 以最终 session
状态或显式错误为完成事实源。

Node 关闭时按以下顺序收敛：

1. 停止新的发现、配对和连接 admission；
2. 取消公告、lease、接口刷新、route preference 和重试 timer；
3. 关闭 multicast sockets 与 TLS acceptor，不再产生 provisional connection；
4. 取消并关闭 pending LAN signaling，投递最终 close/error；
5. 关闭 PeerSession/transport，并按既有顺序处理 relay 注销；
6. 关闭 callback channel，等待 Node 自有 operation 有界收敛；
7. 释放 Asio work guard，由 Blocking I/O worker 的 `wakeup()` 解除等待并 join；
8. 最后刷新 ProfileStore，由进程 owner 关闭 executor。

worker `started/ready` 只表示执行线程已建立，不表示 multicast group 已加入、TLS listener 可用或
已发现 peer。LAN readiness 必须由应用状态与 socket/listener 结果单独表示。

## 9. 可观测性与资源限制

LAN 路径至少暴露：

- 每接口 multicast join/leave/failure 和最近公告时间；
- presence accepted/rejected/expired/duplicate/conflict、目录当前/峰值容量；
- provisional TLS accepted/rejected/timeout、每 IP 限速和握手失败分类；
- `LAN_HELLO` 签名、ID、nonce、证书指纹、版本和 replay 拒绝；
- signaling route、route fallback/winner、重复 attempt 仲裁；
- host candidate、selected pair、建连阶段耗时和最终失败原因；
- executor worker status、comm stats、operation timeout/cancel 和关闭阶段。

v1 复用现有稳定 `ErrorCode`，不因新增 route 立即扩展公共 enum：接口/listener 配置失败映射为
`configuration` 或 `transport`，非法 presence/hello 映射为 `protocol`/`authentication`，目录或
连接容量满映射为 `resource_exhausted`，LAN-only 查无目标映射为
`peer_offline`/`endpoint_offline`，握手和信令失败映射为 `signaling`，deadline/cancel 保持
`timeout`/`cancelled`。`component` 与 `safe_detail` 区分 discovery、LAN TLS 和 route 阶段。

所有容量、deadline、announcement interval、lease、jitter、route preference 和自动连接上限集中
进入 `Limits`/Node 配置，并在启动时校验。不得用无界 map 保存发现设备或用静默丢包维持表面
可用性。

## 10. 协议兼容与变更控制

当前已冻结和实现检查的 wire protocol 仍为 1.0。LAN 能力不得仅通过文档约定直接进入 1.0。
M3A 必须作为协议 1.1 的可选扩展完成：

- capability bit 与 major/minor 协商；
- IPv4/IPv6 multicast group、UDP port、datagram envelope 与最大 wire size；
- discovery schema、LAN hello/schema 与签名 canonical field 表；
- `lan_presence`、`lan_hello` golden vectors；
- parser/state-machine/replay fuzz；
- N-1/N 行为：1.0 peer 忽略未知可选能力，1.1 peer 不对 1.0 peer 假定 LAN 支持；
- CMake 版本、build info、协议文档、schemas 和 golden vectors 同一变更提交。

在这组门禁完成前，本文是实现设计，不是可互操作 wire 规范；
[Heyaki Wire Protocol v1](heyaki-wire-protocol.md) 继续是协议 1.0 的规范来源。

## 11. 安全与测试门禁

安全测试必须覆盖伪造/自签新身份公告、公告重放和冲突 sequence、超大/截断 Protobuf、multicast
洪泛、TLS slowloris、每 IP 连接洪泛、证书指纹替换、hello relay/MITM、offer/candidate 替换、
pairing 猜测和目录/replay cache 满载。局域网中的被动观察者能够看到 presence 中的稳定 ID、
时序和源地址；这是 v1 明确接受的残余元数据风险。

网络验收至少包含：

- Linux/Windows 双向发现和建连；
- IPv4-only、IPv6 link-local、双栈、多网卡和接口切换；
- 同一 LAN 三设备、同 DeviceId 多 EndpointId、同时启动和交叉连接；
- relay/coturn 完全未运行时通过 host candidate 建立认证 DataChannel；
- multicast 被阻止、Windows firewall 拒绝、AP isolation 模拟时快速进入可解释失败；
- LAN 与 relay 同时可用时 endpoint 去重、LAN 优先、relay fallback 和单 transport winner；
- 关闭任意阶段时 socket、TLS、timer、worker、operation 和 replay/endpoint cache 无泄漏；
- sanitizer、TSAN、fuzz 与长时间反复发现/过期/重连保持资源有界。

LAN Connectivity MVP（M4）的退出条件是：三台设备在没有 relay/STUN/TURN 的同一测试网段中
可发现正确 endpoint、建立通过签名与 transcript 认证的 DataChannel，并只开放内部 control
ping；任何伪造、重放、满载、取消或关闭路径都必须进入可观测终态。未知/已信任 peer 分别
进入 `PairingRestricted` 与 `Authorized` 的完整门禁在 M5 pairing/TrustGrant 实现后验收。
