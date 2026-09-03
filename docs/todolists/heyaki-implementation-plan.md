# Heyaki MVP 至 v1 实施 TODO 计划

> - 状态：M3B 已关闭；M4 已关闭（17/17 任务与全部退出条件完成：第 23 轮修复
>   executor/relay 时序变化放大的三个既有竞态后，CI 网络矩阵以 MATRIX_OK 收官，
>   2026-08-27）；M5 已关闭（20/20 任务与全部退出条件完成：默认拒绝授权、密码
>   配对/TrustGrant、加权通道调度与 ByteStream 交付，M3A/M3B/M4 Node 级测试按新
>   语义补种互信，TUI 配对/信任/Stream 视图落地，两轮实施记录见
>   [M5 阶段文件](m5-authorization-bytestream.md)，2026-08-28）；
>   M6 已关闭（21/21 任务与全部退出条件完成：MessageEnvelope 消息服务
>   （best_effort/peer_acked、有界 TTL 去重、message.send scope）、unary RPC
>   （registry/deadline/协作取消/at-most-once 结果缓存/outcome_unknown/
>   streaming→unimplemented）、Node 公共 API、TUI 消息与 RPC 视图、语义示例、
>   35 项服务单测 + TUI/矩阵端到端，实施记录见
>   [M6 阶段文件](m6-message-rpc.md)，2026-08-29）；
>   2026-08-27 计划修订：新增 M10 Gateway 代理服务里程碑（设计见
>   [Gateway 代理服务设计](../design/gateway-service.md)）；
>   2026-08-29 计划修订：依赖可移植性分析完成后新增 M11 Android（NDK）适配里程碑
>   （见 [M11 阶段文件](m11-android-port.md)）
> - 日期：2026-08-29
> - 设计依据：[Heyaki 设备通信基础设施设计](../design/heyaki-architecture.md)、[局域网无服务器连接设计](../design/lan-serverless-connectivity.md)
> - 计划范围：设备端 C++20 库、`heyaki-relay`、coturn 集成、`heyaki-tui`、测试与生产交付

本文是总计划的概览与索引：保留交付边界、里程碑依赖和通用门禁；各阶段的任务清单
（`M*-NN` 条目）、测试与退出条件以及逐轮实施/验收记录拆分在本目录下的独立阶段文件
（见第 3 节索引）。M0 已建立顶层构建、源码与测试骨架、三平台 CI、依赖锁定和供应链
基线；后续里程碑在此工程基线上按退出条件推进。

勾选规则：只有代码、测试、必要文档和本阶段验收同时完成后，任务才可从 `[ ]` 改为
`[x]`。因环境限制无法执行的验证保持未勾选，并在条目后记录环境、负责人和补跑条件。

---

## 1. 交付边界与实施原则

### 1.1 首版边界

- [ ] `SCOPE-01` 确认 v1 数据面只交付 `libdatachannel` WebRTC DataChannel 后端；QUIC 仅保留内部 SPI 扩展点。
- [ ] `SCOPE-02` 确认 relay 只负责登记、登录、租约、在线查询、信令和短期 TURN credential，不接收业务职责。
- [ ] `SCOPE-03` 确认部署 relay 的 MVP 使用单 region、单控制实例、SQLite 和一个 coturn 实例；LAN-only 运行不要求这些组件，不提前引入 Redis/NATS/PostgreSQL。
- [ ] `SCOPE-04` 确认 v1 不包含离线消息、持久事件、目录同步、多跳转发、无损路径迁移、detached Shell 和本机 agent。
- [ ] `SCOPE-05` 将 Linux x86_64 作为 MVP 开发基线，将 Linux/Windows x64 双平台作为 v1 发布门禁。
- [ ] `SCOPE-06` 将 Remote Shell 设为默认关闭的独立安全里程碑；Shell 未完成不得阻塞消息、RPC、事件和文件版本交付。
- [ ] `SCOPE-07` v1 支持同一二层 multicast domain 内无 relay/STUN/TURN 的自主发现、认证信令和 WebRTC host-candidate 直连。
- [ ] `SCOPE-08` LAN 与 relay 是可组合的 discovery/signaling route；v1 数据面仍只有 `libdatachannel`，不新增 LAN 专用业务 transport。
- [ ] `SCOPE-09` LAN serverless 不承诺跨 VLAN、访客 Wi-Fi client isolation、阻止 multicast/入站连接的网络；这些场景使用 relay 或明确失败。
- [ ] `SCOPE-10` v1.0 不包含 Gateway 代理服务；gateway 以 M10（v1.x）交付，且只以显式授权的 L4 字节流代理形态存在，复用 ByteStream 与 TrustGrant，不新增帧类型。L3/TUN 网关、UDP 转发与 Heyaki 会话多跳转发不属于本计划。

### 1.2 不可破坏的架构约束

- [ ] `RULE-01` 公共业务 API 只依赖 `PeerSession`/`Channel` 等 transport-neutral 契约，不暴露 libdatachannel 类型。
- [ ] `RULE-02` 设备身份始终使用完整 `DeviceId`；`ShortDeviceId` 只用于显示，不进入协议比较、主键或 ACL。
- [ ] `RULE-03` transport connected 与 authorized 分开建模；`PairingRestricted` 状态不得创建任何业务通道。
- [ ] `RULE-04` 所有队列、窗口、缓存、并发 operation 和诊断历史都有容量上限，不以无界缓存掩盖背压。
- [ ] `RULE-05` 可靠、确认、持久化、幂等和自动重试分别定义，禁止把 DataChannel 可靠传输描述为业务已处理。
- [ ] `RULE-06` relay、TURN 日志和存储中不得出现授权密码、Argon2id verifier、TrustStore 或业务明文。
- [ ] `RULE-07` 未经单独批准不得修改 pinned executor；若发现能力缺口，按仓库 `AGENTS.md` 的五项要求先报告并等待决策。
- [ ] `RULE-08` discovery/presence、源 IP、TLS 建连和 relay 在线状态都只是 endpoint hint，不得提升 TrustStore 或业务授权状态。
- [ ] `RULE-09` `PathInfo` 分离 `signaling_path` 与 `data_path`；业务 API 不按 LAN/relay/TURN 路径改变协议和授权语义。
- [ ] `RULE-10` 自动发现不等于全连接 mesh；只对已信任且策略允许的 peer 自动建连，并对 active/pending peer 设置硬上限。

### 1.3 Executor 并发边界

- [ ] `EXEC-01` 每个进程明确唯一 executor owner；owner 在任何工作提交前初始化配置，并负责最终 drain/shutdown，其他组件只借用。
- [ ] `EXEC-02` Heyaki 自有的 Asio `io_context::run()` 等长期循环通过 pinned executor 的 Blocking I/O worker/facade 管理，不自行创建线程。
- [ ] `EXEC-03` libdatachannel 等第三方回调只做有界校验和投递；业务 handler、文件哈希和其他 Heyaki 工作不得直接在第三方线程执行。
- [ ] `EXEC-04` 跨执行上下文按语义使用 `executor::comm`：逐条 FIFO 用 `MpscChannel`，最新状态用 `LatestMailbox`，一致快照用 `DoubleBuffer`，本地多订阅者事件用 `Topic`，启动阶段用 `PhaseGate`。
- [ ] `EXEC-05` 不引入 `std::thread`、`std::jthread`、`std::async`、自建线程池、detached worker、ad-hoc 队列或共享可变状态加条件变量的替代实现。
- [ ] `EXEC-06` 每个普通任务保存并观察 future；提交成功只表示 admission，任务结果和异常以 future 为准。
- [ ] `EXEC-07` 不把 executor 的 queued soft timeout 当作运行中任务取消；每个网络和业务 operation 另行实现 deadline 与协作取消。
- [ ] `EXEC-08` executor failure status/event、worker status 和 `executor::comm` stats 是任务健康的事实源；Heyaki 指标只补充协议和业务状态，不建立平行任务监控系统。
- [ ] `EXEC-09` 每次实现新的并发工作负载前，重新按 pinned `executor-integration` skill 路由并读取对应的唯一 capability card，记录所选 API、容量和关闭语义。
- [ ] `EXEC-10` LAN multicast socket、TLS acceptor/client、接口刷新和 timer 全部复用 executor Blocking I/O worker 承载的现有 Asio runtime，不创建第二 worker、裸线程或独立 poll loop。
- [ ] `EXEC-11` LAN 关闭先停公告/lease/route producer，再关闭 multicast socket、TLS listener 和 pending signaling；worker `ready` 不得冒充 LAN readiness。

---

## 2. 里程碑、依赖与发布点

| 里程碑 | 目标 | 前置 | 建议发布点 |
| --- | --- | --- | --- |
| M0 | 仓库、构建、CI 与决策基线 | 无 | 内部工程基线 |
| M1 | 协议、安全和公共类型冻结 | M0 | 协议评审基线 |
| M2 | Executor/Asio runtime、ProfileStore 与身份 | M1 | 本地库 alpha |
| M3A | LAN discovery、TLS 本地信令与 local-only onboarding | M2 | Serverless control-plane alpha |
| M3B | Relay 登记、自动登录、租约与 TUI onboarding | M2 | Relay control-plane alpha |
| M4 | 公共签名信令、WebRTC、ICE/TURN 和最小会话 | M3A；完整退出还需 M3B | v0.1 Connectivity MVP |
| M5 | 配对、TrustGrant、通道调度和 ByteStream | M4 | 会话安全 beta |
| M6 | 消息、unary RPC 与对应 TUI | M5 | v0.2 Service MVP |
| M7 | 远程事件、文件传输与对应 TUI | M6 | v0.3 Data beta |
| M8 | Remote Shell 与安全终端 UI | M7 | v0.4 Shell beta |
| M9 | 生产加固、跨平台、兼容性与发布 | M8 | v1.0 |
| M10 | Gateway 代理服务（受限 L4 网关） | M5 | v1.1 Gateway beta |
| M11 | Android（NDK）库适配与 CI | M9 | v1.2 Android alpha |

Serverless 关键路径为 `M0 -> M1 -> M2 -> M3A -> M4 -> M5 -> M6 -> M7 -> M8 -> M9`；
relay 路径 `M2 -> M3B -> M4` 可与 M3A 并行，但 M4 完整退出要求 LAN 与 relay/TURN 两组门禁
都通过。TUI 不作为最后一次性补做的界面工程，而是在 M3A、M3B、M4、M6、M7、M8 中按公共
API 逐步交付，以持续充当端到端验收客户端。M10 依赖 M5 的 ByteStream 与 TrustGrant
scope，可与 M7/M8 并行实施，但 gateway 不进入 v1.0 发布门禁，作为 v1.x 能力交付。

### 2.1 产品决策默认值

以下项目需要产品确认；为避免阻塞技术验证，在未得到相反结论时使用括号中的暂定默认值：

- [ ] `DEC-01` 目标平台与设备等级（MVP Linux x86_64；v1 增加 Windows x64；受限嵌入式延后）。
- [ ] `DEC-02` 严格 HTTP 代理/完全禁 UDP 是否为 v1 硬要求（TURN/TCP/TLS 是 v1；认证 HTTP 代理延后）。
- [ ] `DEC-03` 容量基线：每设备 peer、并发 RPC、订阅者、文件大小和吞吐目标（M0 用配置化保守值，M9 压测后冻结）。
- [ ] `DEC-04` 默认 pairing policy 与密码轮换行为（默认只读/文件模板不含 Shell；轮换不自动撤销既有 grant）。
- [ ] `DEC-05` relay 产品形态（MVP 单租户自部署；多租户公网服务延后）。
- [ ] `DEC-06` Shell 用途（只支持人工维护；无人值守操作使用窄 RPC/job service）。
- [ ] `DEC-07` 移动网络切换目标（v1 不承诺无损会话迁移）。
- [ ] `DEC-08` ProfileStore 所有权（默认 per-user；系统服务必须显式指定 system profile）。
- [ ] `DEC-09` service manifest 暴露粒度（同租户内只发布连接选择必需的最小能力摘要）。
- [ ] `DEC-10` LAN serverless 范围（默认仅同一二层 multicast domain；跨 VLAN 使用 relay/显式 hint）。
- [ ] `DEC-11` 发现协议（默认有界 Heyaki UDP multicast；mDNS/DNS-SD 延后）。
- [ ] `DEC-12` LAN 可见性与自动连接（启用时暴露完整 DeviceId/EndpointId、不广播名称/manifest；仅自动连接已信任 peer）。
- [ ] `DEC-13` Gateway 代理默认值（默认关闭、不入标准 pairing 模板；首版仅 TCP；默认 profile 仅允许 B 直连网段，公网出口显式开启；TURN 数据路径上 gateway 流量默认允许但独立计量，可配置限速或禁止；gateway 与 shell 同时授权要求显式确认）。
- [ ] `DEC-14` Android 产品形态（v1.x 只交付 C++20 核心库的 NDK 交叉编译与 JNI 集成边界，不包含完整 Android 应用/UI；TUI、fuzzer、coturn 部署组件不移植；Android 上的 profile 存储位置与 secret backend 等价物须在 M11 立项时单独确认）。

---

## 3. 阶段任务文件索引

各阶段的任务清单、测试与退出条件以及实施进度轮总结在下列文件中维护，本节只保留
状态概要。通用门禁（第 13-15 节）节号与拆分前的单文件计划保持一致，历史记录中的
“计划第 N 节”引用仍然有效。

| 里程碑 | 文件 | 状态 | 概要 |
| --- | --- | --- | --- |
| M0 | [m0-engineering-baseline.md](m0-engineering-baseline.md) | 已完成 | 仓库骨架、三平台 CI、依赖锁定与供应链基线；17 项任务与全部退出条件于 2026-08-14 完成。 |
| M1 | [m1-protocol-security.md](m1-protocol-security.md) | 已完成 | 公共强类型、wire protocol、canonical signing、threat model 与 fuzz 基线；2026-08-15 正式准入 M2。 |
| M2 | [m2-runtime-identity.md](m2-runtime-identity.md) | 已完成 | executor/Asio runtime、身份与密码材料、ProfileStore/TrustStore；2026-08-15 正式准入 M3A/M3B。 |
| M3A | [m3a-lan-serverless.md](m3a-lan-serverless.md) | 已完成 | LAN multicast discovery、TLS 本地信令与 local-only onboarding；2026-08-16 最终退出验收通过。 |
| M3B | [m3b-relay-control-plane.md](m3b-relay-control-plane.md) | 已完成 | relay 登记/登录/租约/信令转发、TURN credential 与 TUI onboarding；15 轮记录，2026-08-16 关闭。 |
| M4 | [m4-connectivity-mvp.md](m4-connectivity-mvp.md) | 已完成 | 公共签名信令、WebRTC/ICE/TURN 与最小认证会话；17/17 任务完成、退出条件全部达成；第 23 轮修复三个被时序变化放大的既有竞态后，CI run 33094431955 全绿、`heyaki_m4_network_matrix` MATRIX_OK（turn_fallback P95 2203ms），2026-08-27 关闭。 |
| M5 | [m5-authorization-bytestream.md](m5-authorization-bytestream.md) | 已完成 | 会话授权（pairing/TrustGrant）、通道调度与 ByteStream；20/20 任务与全部退出条件完成，两轮实施记录见阶段文件，2026-08-28 关闭。 |
| M6 | [m6-message-rpc.md](m6-message-rpc.md) | 已完成 | 消息（best_effort/peer_acked、TTL 去重、scope）、unary RPC（deadline/取消/at-most-once/outcome_unknown）与 TUI/示例；21/21 任务与退出条件于 2026-08-29 完成。 |
| M7 | [m7-event-file-transfer.md](m7-event-file-transfer.md) | 已完成 | 远程事件与文件传输。 |
| M8 | [m8-remote-shell.md](m8-remote-shell.md) | 已完成 | Remote Shell 与安全终端 UI（独立安全里程碑，默认关闭）。2026-09-03 交付：ShellProfile/scope 授权、全帧协议、executor PTY worker（POSIX/ConPTY + 升级阶梯 + 速率/时限/背压上限）、内容无关审计、安全 VT 渲染器、Node API 与 TUI 视图；交付时 45 项 M8 测试 + fuzz 目标绿，本机全仓 51 项绿 + m8 ASan 绿，CI 全矩阵（含 Windows ConPTY 生命周期）10/10 绿。2026-09-04 安全评审签字（[报告](../security/m8-remote-shell-security-review.md)，无 P0/P1，F2 已修）后生产启用解禁，限 POSIX；Windows 待路径校验修复，默认保持禁用。 |
| M9 | [m9-production-hardening.md](m9-production-hardening.md) | 未开始 | 生产加固、跨平台、兼容性与 v1 发布。 |
| M10 | [m10-gateway-proxy.md](m10-gateway-proxy.md) | 未开始 | 受限 L4 Gateway 代理：protocol 1.3 变更单、授权/profile、B 侧网关服务、A 侧 API 与可选 SOCKS5 前端。 |
| M11 | [m11-android-port.md](m11-android-port.md) | 未开始 | Android（NDK）适配：依赖交叉编译、平台层验证、JNI 集成边界与 NDK CI；v1.x 交付，不阻塞 v1.0。 |

---

## 13. 每阶段通用 Definition of Done

每个实现 PR/阶段必须同时满足以下项目，不因主路径“已经跑通”而省略：

- [ ] `DOD-01` 需求可追溯到本计划 ID 和总设计章节；偏离设计时先提交设计决策记录。
- [ ] `DOD-02` 公共 API、wire schema、错误码、默认限制和兼容性影响已评审并记录。
- [ ] `DOD-03` 并发工作已声明 executor owner、提交/worker API、communication component、capacity、backpressure、future/status owner 和 shutdown 顺序。
- [ ] `DOD-04` admission rejection、执行失败、timeout/cancel、drop/overwrite、重连和关闭状态可由返回值及 executor 设施观察。
- [ ] `DOD-05` 单元、协议、集成和相应故障测试随代码提交；测试自身不创建裸线程或私有执行循环。
- [ ] `DOD-06` 新 parser/状态机加入 fuzz corpus；新密钥、密码、路径和远程输入边界加入安全测试。
- [ ] `DOD-07` Linux/Windows 差异被封装在平台层，至少完成目标平台编译；平台未验证项保持未完成。
- [ ] `DOD-08` ASAN/UBSAN 通过；涉及跨上下文状态、关闭或多进程存储时增加 TSAN/故障注入。
- [ ] `DOD-09` 日志与指标无 secret/payload 泄漏；高频指标、最近事件和 replay/dedup cache 均有容量。
- [ ] `DOD-10` 文档、示例、TUI 行为和实现一致；示例使用公共 API 且纳入编译/smoke test。
- [ ] `DOD-11` 关闭测试证明生产者先停、在途工作有界收敛、依赖对象最后销毁，无 detached 工作或后台泄漏。
- [ ] `DOD-12` 评审者可以从测试输出回答“接收了吗、完成了吗、失败在哪里、丢了多少、能否取消、何时释放”。
- [ ] `DOD-13` 新 discovery/signaling route 证明“发现不授权”、来源合并/过期/仲裁有界、signaling/data path 分离，并覆盖 LAN-only 与 fallback。

---

## 14. 建议拆分与合并顺序

1. 先合入 M0 构建/CI 骨架和 M1 公共类型，不在同一 PR 中引入 WebRTC 或 UI。
2. M1 的 wire protocol、签名 canonicalization 和 threat model 先评审，再生成业务实现。
3. M2 分为 runtime、identity、ProfileStore 三组 PR；runtime shutdown 测试先于任何长生命周期网络工作。
4. M3A 先完成协议 1.1 change control，再交付 multicast discovery/endpoint directory，最后交付 TLS LAN route 与 TUI；不得先写未冻结的 wire bytes。
5. M3B 与 M3A 并行时先交付 relay enrollment/login 服务端，再交付客户端和 TUI；两者共用 endpoint/signaling 契约。
6. M4 先合 Transport SPI/假 transport 与双 route 测试，再接 libdatachannel、host-only LAN、coturn 与组合网络矩阵。
7. M5 先完成 framing/调度，再完成 pairing/TrustGrant，最后开放 ByteStream；未授权状态始终默认关闭。
8. M6 的消息与 RPC 可分 PR，但共同复用会话、ACL、deadline、取消和 executor dispatch。
9. M7 先事件、再 ByteStream 上的文件协议和安全落盘；恢复协议通过故障注入后再开放 TUI push/pull。
10. M8 的 OS Shell backend、协议、VT UI 和安全评审分别提交；安全门禁未通过不启用生产配置。
11. M9 只做加固、兼容、测量和交付，不在发布冲刺中加入 QUIC、跨 region、mDNS provider 或业务 Broker。
12. M10 先冻结 protocol 1.3 变更单与 golden vectors（不新增帧类型），再实现 B 侧网关服务与授权准入，最后交付 A 侧流 API、SOCKS5 前端与 TUI Gateway 视图；v1.0 发布不被 M10 阻塞。
13. M11 先完成 NDK 依赖交叉编译基线与 CI job，再验证平台层（文件锁、接口枚举、组播、dlopen backend），最后交付 JNI 集成层与最小 Android 集成示例；不移植 TUI、fuzzer 与 coturn 拓扑。

每个里程碑建议以可回滚提交序列合入。若某阶段需要修改已冻结的身份、签名或 wire major，
应暂停下游功能开发，先完成兼容性影响评审和 golden vector 更新。

---

## 15. 延后项与触发条件

- [ ] `POST-01` ICE + QUIC backend：只有 M9 数据证明 SCTP 吞吐、延迟隔离或迁移能力不达标时立项。
- [ ] `POST-02` WSS 密文帧 transport：仅在目标平台无法通过已验证 TURN/TCP/TLS 建立 DataChannel 且企业网络是硬要求时立项。
- [ ] `POST-03` 多 region/横向 relay：只有单实例容量与可用性目标明确后，再设计 presence 共享和 sticky routing。
- [ ] `POST-04` 外部事件 Broker/gateway：只有点对点 fan-out 达到冻结上限且产品需要大规模广播时立项。
- [ ] `POST-05` 本机 agent/IPC：只有 secret backend 无法安全支持同 profile 多进程，或需要不可信应用隔离时立项。
- [ ] `POST-06` 目录同步、增量去重、稀疏文件和多文件事务：单文件恢复协议稳定并有真实需求后立项。
- [ ] `POST-07` detached Shell：只有终止策略、重连授权、持久审计和资源回收有单独安全设计后立项。
- [ ] `POST-08` relay 离线 PAKE：只有产品明确要求目标设备离线时预验证密码，并接受扩大 relay 信任边界后立项。
- [ ] `POST-09` mDNS/DNS-SD discovery provider：只有需要系统生态互操作或 multicast 私有协议受部署约束时立项；仍须服从 executor 生命周期和同一安全边界。
- [ ] `POST-10` 隐私增强 LAN discovery：只有稳定 DeviceId/EndpointId 枚举不可接受时，设计配对窗口、旋转 hint 或已信任 peer 定向发现，不能以未认证名称替代身份。
- [ ] `POST-11` L3 受限子网网关（TUN + NAT/受控放行）：只有 M10 的 L4 代理形态经真实使用证明不满足透明性/协议覆盖需求时立项；须先修订架构 §2.2 非目标条目（三层虚拟网络/透明 IP 路由），仿 M8 模式作为独立安全里程碑（默认关闭、特权部署、专项安全评审）。
- [ ] `POST-12` Gateway UDP 转发（SOCKS5 UDP ASSOCIATE 或数据报流）：只有 TCP-only 的 M10 交付后出现明确 UDP 需求（如 QUIC、内网 UDP 服务）时立项；须定义数据报语义、无序通道选择与防放大策略。
