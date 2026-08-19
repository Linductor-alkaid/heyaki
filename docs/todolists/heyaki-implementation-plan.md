# Heyaki MVP 至 v1 实施 TODO 计划

> - 状态：M3B 已关闭；M4 活动中（已推进至第十五轮：三设备 LAN host-candidate
>   认证会话退出条件已达成；in-place ICE restart、网络矩阵与 TUI 选择建连继续）
> - 日期：2026-08-19
> - 设计依据：[Heyaki 设备通信基础设施设计](../design/heyaki-architecture.md)、[局域网无服务器连接设计](../design/lan-serverless-connectivity.md)
> - 计划范围：设备端 C++20 库、`heyaki-relay`、coturn 集成、`heyaki-tui`、测试与生产交付

本文把总设计拆成可以按依赖顺序实施、独立验收和回归的任务。M0 已建立顶层构建、源码与
测试骨架、三平台 CI、依赖锁定和供应链基线；后续里程碑在此工程基线上按退出条件推进。

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

Serverless 关键路径为 `M0 -> M1 -> M2 -> M3A -> M4 -> M5 -> M6 -> M7 -> M8 -> M9`；
relay 路径 `M2 -> M3B -> M4` 可与 M3A 并行，但 M4 完整退出要求 LAN 与 relay/TURN 两组门禁
都通过。TUI 不作为最后一次性补做的界面工程，而是在 M3A、M3B、M4、M6、M7、M8 中按公共
API 逐步交付，以持续充当端到端验收客户端。

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

---

## 3. M0：仓库、构建与质量基线

### 3.1 仓库骨架

- [x] `M0-01` 新增顶层 `CMakeLists.txt`、`CMakePresets.json` 和 C++20 编译基线，提供 Debug/Release/ASAN/UBSAN/TSAN 预设。
- [x] `M0-02` 建立设计规定的目录：`include/heyaki/`、`src/`、`proto/`、`apps/relay/`、`apps/tui/`、`tests/{unit,integration,network}`。
- [x] `M0-03` 建立 targets：`heyaki::core`、`heyaki::profile`、`heyaki::client`、`heyaki::services`、`heyaki::transport_webrtc`、`heyaki-relay`、`heyaki-tui`。
- [x] `M0-04` 用 CMake target 约束依赖方向，加入“公共头不可包含 libdatachannel/FTXUI 私有类型”的编译测试。
- [x] `M0-05` 统一 warning、`clang-format`、`clang-tidy`、include-what-you-use（若环境可用）与禁止异常配置的项目选项。
- [x] `M0-06` 为生成的 Protobuf 文件、测试临时 profile、credential 和 fuzz corpus 明确构建目录及清理规则，防止机密进入源码树。

### 3.2 依赖与供应链

- [x] `M0-07` 运行 `scripts/fetch_third_party.sh --check --all`，补齐当前未抓取的 `googletest` 与可选 `zstd` 验证路径。
- [x] `M0-08` 为 Boost、TLS backend 和 coturn 确定可复现版本策略；不能只依赖开发机上未记录的系统版本。
- [x] `M0-09` 验证 libdatachannel v0.23.2 的 ICE backend、TURN/TCP/TLS、证书库和 Windows 构建组合，形成兼容矩阵。
- [x] `M0-10` 对所有 pinned 依赖生成许可证清单和 SBOM；确认静态/动态链接与发布包合规。
- [x] `M0-11` 给依赖升级建立单独流程：更新 ref/commit、验证 moved tag、运行全量协议/网络回归并记录版本差异。

### 3.3 CI 与测试入口

- [x] `M0-12` 建立 Linux GCC/Clang 与 Windows MSVC 构建矩阵，至少执行 configure、build、unit test 和安装后 consumer compile test。
- [x] `M0-13` 建立 ASAN/UBSAN 常规任务、TSAN 专项任务和 fuzz smoke 任务；宿主不支持时记录目标机补跑门禁。
- [x] `M0-14` 建立测试标签：`unit`、`protocol`、`integration`、`network`、`security`、`fuzz`、`performance`、`tui`、`windows`。
- [x] `M0-15` 建立测试证书、bootstrap token、relay database 和 profile fixture 生成器；fixture 只能包含测试密钥。
- [x] `M0-16` 建立 network namespace + nftables/netem harness 的 Linux-only 入口，并在无权限环境明确 skip 原因。
- [x] `M0-17` 建立版本、构建 commit、协议版本和 feature flags 的可查询接口，供 relay、TUI 和诊断输出复用。

### M0 测试与退出条件

- [x] 空实现 targets 在 Linux GCC/Clang 和 Windows MSVC 上可构建、安装并由外部最小 consumer 引用。
- [x] runtime、test、optional 三组 dependency pin 均可离线校验，依赖缺失时 configure 给出可操作错误。
- [x] 单元、集成、网络、fuzz 和 sanitizer 命令均有稳定入口，CI 不以“无测试可运行”冒充成功。
- [x] 产品决策 `DEC-01` 至 `DEC-09` 已确认，或明确记录暂定默认值、负责人和最迟冻结里程碑。

M0 验证记录（2026-08-14）：本机 GCC 13.3 的 Debug、Release、UBSAN、禁异常、可选依赖及 pinned libdatachannel 最小静态 DataChannel profile 构建通过，安装后 consumer 通过；ASAN 因宿主 ptrace 限制、TSAN 因宿主地址映射限制而明确 skip。GitHub Actions 在 commit `72c55d7` 上完成 Linux GCC/Clang、Windows MSVC、ASAN、UBSAN、TSAN 和 fuzz smoke 矩阵，configure、build、CTest、安装后 consumer 以及三平台 pinned libdatachannel 构建全部通过，CI 不允许 sanitizer runtime skip。Linux network harness 在缺少 `CAP_NET_ADMIN` 的环境明确 skip。供应链生成器覆盖 9 个直接 pin、5 个 libdatachannel submodule、许可证文件存在性与 SPDX 父子关系，相关 CI 清单测试通过；当前安装/链接闭包见 [M0 链接与许可证审计](../supply-chain/m0-linkage-license-audit.md)。默认 libjuice 明确不支持 TURN/TCP/TLS，该负向能力结论与后续 libnice/coturn 门禁见 [兼容矩阵](../compatibility/libdatachannel-v0.23.2.md)。产品默认值、owner 与冻结点见 [M0 产品决策默认值](../decisions/m0-product-defaults.md)。据此 `M0-01` 至 `M0-17` 及全部 M0 退出条件完成，正式准入 M1。

---

## 4. M1：协议、安全与公共契约基线

### 4.1 公共类型和限制

- [x] `M1-01` 定义 `DeviceId`、`EndpointId`、`SessionId`、`OperationId`、`MessageId`、`RequestId` 和 `TransferId` 的强类型与文本/二进制编码。
- [x] `M1-02` 实现 `DeviceId = SHA-256(public_key)` 与 `hy1_` base32 文本格式，覆盖非法字符、长度和大小写规则。
- [x] `M1-03` 定义稳定 `ErrorCode`、`Error` 和 `Result<T>`，覆盖架构第 13.1 节全部类别，禁止调用方依赖错误字符串分支。
- [x] `M1-04` 定义 monotonic deadline、wall-clock metadata 和相对时限的使用规则，不在协议正确性上假设设备时钟同步。
- [x] `M1-05` 建立集中 `Limits` 配置和安全最小/最大值，覆盖 frame、message、RPC、队列、窗口、文件、配对、endpoint manifest 和诊断缓冲。
- [x] `M1-06` 定义 operation 生命周期 `pending/success/error/cancelled/outcome_unknown`，并为跨重连状态增加 session epoch。

### 4.2 Wire protocol

- [x] `M1-07` 新增 `docs/design/heyaki-wire-protocol.md`，冻结 framing 字段、varint、字节序、最大长度、未知帧和关闭规则。
- [x] `M1-08` 按协议域拆分 versioned Protobuf Lite schema：enrollment、signaling、session、pairing、message、RPC、event、stream、file、shell。
- [x] `M1-09` 定义 major/minor 和 capability bits 协商；未知可选字段可跳过，未知必需能力必须明确拒绝。
- [x] `M1-10` 定义规范化签名对象：enrollment、endpoint record、service manifest、offer/answer/candidate、`SESSION_HELLO`、TrustGrant。
- [x] `M1-11` 为签名对象明确 domain separator、字段顺序、长度编码、nonce、expiry 和双方身份绑定，禁止直接签名不稳定 JSON/Protobuf 序列化结果。
- [x] `M1-12` 生成并提交跨语言可复验的 golden vectors：ID 派生、规范化字节、签名、frame 和 Protobuf envelope。
- [x] `M1-13` 定义每个业务协议的状态机、重复帧、乱序帧、迟到帧、超大帧和局部通道失败行为。

### 4.3 Threat model 与安全门禁

- [x] `M1-14` 新增 `docs/security/threat-model.md`，覆盖恶意设备、被控制 relay、密码猜测、ProfileStore 窃取、重放、降级、资源耗尽、路径穿越、恶意 VT 和供应链。
- [x] `M1-15` 定义密钥、token、密码、verifier 和 payload 的日志分类与脱敏测试；结构化字段只允许安全上下文。
- [x] `M1-16` 定义 replay cache 的 key、TTL、容量和满载策略；容量耗尽必须可观测且默认拒绝高风险请求。
- [x] `M1-17` 定义密码强度、Argon2id 参数版本/校准范围、安全 buffer 清理和 password generation 规则。
- [x] `M1-18` 评审 TLS/DTLS 信任边界和签名 signaling transcript 绑定，证明 relay 替换 fingerprint、ICE generation 或 offer/answer 时会在设备侧失败。
- [x] `M1-19` 建立 parser/state-machine fuzz targets，初始 corpus 包含 golden vectors、截断、重复、边界长度和未知字段。

### M1 测试与退出条件

- [x] 所有公共强类型、错误码、限制默认值和序列化边界有单元测试及公开头独立编译测试。
- [x] golden vectors 在 Linux/Windows、Debug/Release 上得到相同字节；协议文档与 schema 版本一致。
- [x] 所有 parser 在分配 payload 前检查长度，fuzz smoke 无 crash、越界、超限分配或无限循环。
- [x] threat model、安全默认值和 wire protocol 通过独立评审后再进入 M2；后续不兼容修改必须显式提升协议 major。

M1 本地验证记录（2026-08-15）：首轮协议/安全评审的七项问题已完成整改。Linux GCC 13.3 的
Debug、Release、`-Werror` 和禁异常构建均通过；各配置的 16 项 CTest 为 15 pass、1 network
skip。UBSAN 的 15 项 CTest 为 14 pass、1 network skip。ASAN 构建通过，但相关运行时测试
因宿主 ptrace/LeakSanitizer 限制按既定规则明确 skip，network harness 同样因缺少
`CAP_NET_ADMIN` skip。公开头逐头独立编译，安装后 consumer、schema/文档版本检查、golden
bytes、frame parser、operation 状态机、pinned `protoc` 生成的 Protobuf Lite conformance
test 和 fuzz smoke 均通过。新增 generated Protobuf parser 的第三个 libFuzzer target；当前
宿主没有 Clang/libFuzzer。GitHub Actions 在基线 commit `0567800` 上完成 Linux GCC/Clang、
Windows MSVC Debug、ASAN、UBSAN、TSAN 和两个真实 libFuzzer target 各 100 次短跑；本次整改
已将 Windows 扩展为 Debug/Release 矩阵并增加第三个 target，但更新后的远端 CI 尚未执行。
该 CI 与独立协议/安全复审均完成前，保持对应退出条件未勾选，不准入 M2。

M1 独立评审整改记录（2026-08-15）：未知可选 capability 现按 v1 已知掩码忽略，任一未知
必需 bit 明确拒绝；tenant 和 application ID 的规范化签名字段要求非空且通过严格 UTF-8
校验；`FILE_CHUNK` 的 256 KiB 限制只计算 60 字节 raw header 后的数据，并覆盖精确边界。
Protobuf fuzz target 现遍历 11 个 schema 文件中的全部 42 个消息类型，state-machine target
覆盖 enrollment、signaling、session/pairing、message、RPC、event、stream、file 和 shell，
并保留 operation 生命周期检查。Linux CI 已扩展为 GCC/Clang × Debug/Release，libFuzzer
仍在 Clang Debug 执行；Windows pinned Protobuf、Abseil 与 Heyaki 目标统一使用 MSVC 动态
runtime，保留 Debug/Release 矩阵。全新本地 GCC Debug/Release、`-Werror` 构建均通过，
各 16 项 CTest 为 15 pass、1 network 权限 skip；UBSAN 协议/安全/fuzz 标签 11 项全部通过。
更新后的 Windows Debug/Release 仍须远端执行确认，因此跨平台退出条件继续保持未勾选。

M1 准入复审与 Windows CI 整改记录（2026-08-15）：复审逐项核对公共类型、错误不可变性、
版本/能力协商、规范化签名字段、信令 transcript 绑定、frame parser、全部 42 个 Protobuf
Lite 消息及九个协议域状态模型，未发现新的协议或安全阻断问题。Windows Debug/Release 的
`protoc.exe` 链接失败源于同一构建图中 Abseil 按 MSVC 默认 C++14、Protobuf 按 C++17
编译，导致 Abseil drop-in `string_view` ABI 不一致。修复提交 `2a5340f` 将所有 in-tree
target 统一为必需的 C++20，并在配置期验证 `absl_cord`、Protobuf runtime、`libprotoc`、
`protoc` 的语言标准及动态 MSVC runtime 一致。全新 GCC 13.3 Debug、Release、禁异常和
UBSAN `-Werror` 构建均通过，四套各 16 项 CTest 全部通过；依赖锁离线校验通过。本机无
Clang，且当前环境没有 GitHub 推送凭据，因此修复提交尚待推送并由更新后的 Linux/Windows、
sanitizer 与 libFuzzer CI 验证；在远端结果完成前，跨平台退出条件保持未勾选且不准入 M2。

M1 跨平台退出确认（2026-08-15）：提交 `5ffdca1bb43b7a9427b2096ac997728be2f392d6`
对应 GitHub Actions run `31848814394` 已完成且结论为 success。该 run 的 9 个 check runs
全部成功：Linux GCC/Clang Debug/Release、Windows Debug/Release、ASAN、UBSAN 和 TSAN；
Clang Debug 同时执行并通过 `heyaki_frame_parser_fuzzer`、`heyaki_protocol_state_fuzzer`
及 `heyaki_protobuf_parser_fuzzer` 各 100 次 smoke。Windows Debug/Release 的 pinned
Protobuf、Abseil、Heyaki 构建、CTest 和 pinned libdatachannel baseline 均通过，golden
vectors 的跨平台 Debug/Release 字节一致性退出条件完成，M1 正式准入 M2。

---

## 5. M2：Runtime、身份与 ProfileStore

### 5.1 Executor/Asio 集成

- [x] `M2-01` 新增 `docs/design/concurrency-and-shutdown.md`，逐项列出 runtime owner、执行上下文、通信组件、容量、完成边界和关闭顺序。
- [x] `M2-02` 实现进程级 runtime 装配：初始化 executor、注册 Blocking I/O worker、启动 Asio、安装 failure/comm 诊断桥接。
- [x] `M2-03` 为 Node 与 relay 分别明确 executor 所有权模式；库默认借用调用方配置的 executor，独立 app 在进程边界拥有 executor。
- [x] `M2-04` 用 Asio strand 串行化 Node/PeerSession 状态；外部 callback 通过有界 `MpscChannel` 进入，不跨线程共享可变 session state。
- [x] `M2-05` 为低频状态快照选择 `DoubleBuffer`，为可覆盖指标选择 `LatestMailbox`；记录 sequence、overwrite、stale 和 lag。
- [x] `M2-06` 为 executor 提交封装 operation ID 和安全上下文，但不复制其 task health 统计；任务异常仍由 future/failure event 观察。
- [x] `M2-07` 实现固定关闭序列：停止 admission -> 停止生产者/重连定时器 -> 取消服务 -> 关闭 peer -> 注销 relay -> 停 Asio -> 有界等待任务/worker -> 刷新持久状态 -> owner shutdown executor。
- [x] `M2-08` 明确借用 executor 的 Node 只 drain 自己的 operation，不得关闭共享 executor；拥有者销毁依赖数据必须晚于任务收敛。
- [x] `M2-09` 所有 drain 和 shutdown 等待都有预算、超时状态与后续动作，不能依赖无限等待或 sleep 判断完成。

### 5.2 身份与密码材料

- [x] `M2-10` 使用 libsodium 初始化安全随机、Ed25519、SHA-256、Argon2id 和常量时间比较；禁止自研密码原语。
- [x] `M2-11` 实现首次身份创建、已有身份加载、公私钥匹配检查和 `DeviceId` 派生验证。
- [x] `M2-12` 抽象 OS secret backend：Windows DPAPI/credential facilities、Linux 可用 key store；文件回退必须加密并检查权限。
- [x] `M2-13` 实现授权密码 verifier 创建、验证、参数校准、格式版本升级和敏感临时 buffer 清理。
- [x] `M2-14` 定义密钥不可用、secret backend 降级、权限过宽和损坏材料的稳定错误，禁止静默生成新身份覆盖旧档案。

### 5.3 ProfileStore 与 TrustStore

- [x] `M2-15` 冻结 ProfileStore SQLite schema：identity handle、relay enrollment、password verifier、TrustStore、grant、endpoint record、file resume、preferences。
- [x] `M2-16` 实现 `open_default()`、显式 profile 打开、创建、重命名和枚举；不存在时返回 `not_registered`，不隐式创建另一个身份。
- [x] `M2-17` 实现 schema version、向前迁移、事务回滚、损坏检测和可恢复备份；每个 migration 有 fixture 测试。
- [x] `M2-18` 实现同一 OS 主体的多进程文件锁/SQLite busy 策略、临时文件、flush 和原子替换；锁超时返回 `profile_locked`。
- [x] `M2-19` 按 `application_id` 创建并持久化随机 `EndpointId`，验证同 profile 多应用得到同 `DeviceId`、不同 endpoint。
- [x] `M2-20` 实现 TrustGrant/TrustStore 的写入、查询、撤销、过期和 password generation 索引，目标本地状态始终为最终裁决。
- [x] `M2-21` 对 profile 导出、删除和 relay 吊销建立不同 API；删除操作在 TUI 中不得把本地删除伪装成远端吊销。

### M2 测试与退出条件

- [x] executor overload、提交拒绝、任务异常、callback 异常、关闭期间提交和 drain timeout 均可通过既定事实源观察。
- [x] ASAN/TSAN 覆盖 callback bridge、Node 状态转换、并发 profile 打开和 shutdown，无悬空 buffer 或数据竞争。
- [x] 进程在每个 ProfileStore 事务点被强制终止后，重启得到旧版本或完整新版本，不出现半写状态。
- [x] 私钥不可用、profile 权限过宽、schema 过新、锁超时和磁盘满均返回稳定错误且不破坏原数据。
- [x] M2 demo 能创建 profile、重启后保持相同 `DeviceId`，两个 application ID 获得稳定且不同的 `EndpointId`。

M2 本地验证记录（2026-08-15）：Linux GCC 13.3 的 Debug `-Werror`、禁异常和 ASAN 全量
构建均通过 20 项 CTest，包含安装后 consumer、当时 15 个直接依赖 pin 的供应链检查、profile
崩溃恢复和 shutdown 测试。TSAN 目标成功构建；对测试进程关闭 ASLR 后，runtime 8 项全部
通过，无 D-Bus 环境下 profile 19 项通过、2 项显式 Secret Service 集成测试按设计 skip，覆盖
callback bridge、Node 状态转换、并发 profile 打开和 shutdown。demo 连续打开同一 profile 后
保持相同 `DeviceId`，两个 application ID 的 `EndpointId` 各自稳定且彼此不同。

runtime 使用容量为 64 的有界 shutdown hook 通道，按 producer、service、peer、relay、
persistence 五阶段依次发起非阻塞停止并以 shared future 和阶段级 monotonic 预算确认完成；
hook 容量拒绝、启动失败、完成超时、固定顺序及 persistence 晚于 Asio worker 停止均有单元
测试。Linux secret backend 动态加载稳定 `libsecret-1.so.0`，以受权限保护的随机 `store.id`
隔离 Secret Service 命名空间；服务不可用时只在策略允许下使用 XChaCha20-Poly1305 加密文件
回退，已有后端不会静默切换。profile 导出会在目标后端重存私钥并更新 SQLite handle，本地
删除会先清理 OS key store；正常 Secret Service 与无 D-Bus 回退两种路径均已测试。14 个显式
事务边界均有 `_Exit` 崩溃注入，Linux `RLIMIT_FSIZE` 真实 I/O 耗尽验证了 SQLite 回滚和稳定
`storage/sqlite_statement_failed`。4 个 executor task 通过容量为 4 的 `MpscChannel` 和
`PhaseGate` 同时打开强制文件后端的同一 profile，均得到原 `DeviceId`；Debug、禁异常和 ASAN
均覆盖该路径。启用本机 Secret Service 时，系统 `libsecret`/GLib 的 `gdbus` 后台线程会产生
第三方 TSAN 报告；正常 Secret Service 路径已由 Debug 和 ASAN 覆盖，M2 自有并发路径则在无
D-Bus 文件回退环境下通过 TSAN。Windows vendored SQLite 生成逻辑已有 Linux 可执行的 CMake
脚本测试，覆盖 Win32/x64/ARM/ARM64 到 Visual Studio 开发环境参数的映射，以及带空格路径下
通过 PowerShell 导入 `Microsoft.VisualStudio.DevShell.dll`、执行 `Enter-VsDevShell` 和
`nmake /f ... "TOP=..." sqlite3.c sqlite3.h`；全新 Linux amalgamation 生成和编译通过。

M2 跨平台验收记录（2026-08-15）：最终提交 `168a6216` 的
[GitHub Actions 运行 31874698030](https://github.com/Linductor-alkaid/heyaki/actions/runs/31874698030)
以 `completed/success` 结束。Windows MSVC Debug/Release 均完成当前 17 个直接依赖 pin 的校验、SQLite
amalgamation 生成、Heyaki 与 pinned libdatachannel 构建及全量 CTest；Linux GCC/Clang 的
Debug/Release 四组合与 ASAN、UBSAN、TSAN 三项也全部通过，共 9/9 job 成功。Windows 验证
过程中发现的 libsodium 静态消费定义/平台源集、Boost.System 所需 WinAPI/Predef 头文件闭包
和 runtime 完成指标发布顺序均已修复并回归。至此 `M2-01` 至 `M2-21` 及全部 M2 退出条件
均有本地与远端证据，正式准入 M3A/M3B。

---

## 6. M3：LAN 与 Relay 控制路径

M3A 与 M3B 都依赖 M2，可并行实施。M3A 是 serverless Connectivity MVP 的前置；M3B 扩展
广域 presence、NAT fallback 和集中运维。两条路径必须收敛到同一 `EndpointDirectory`、
`SignalingRoute` 与签名信令状态机，禁止各自复制会话和授权逻辑。

### 6.1 M3A：协议 1.1 LAN 扩展与配置

- [x] `M3A-01` 以协议 1.1 可选能力冻结 `lan_discovery_v1`/`lan_signaling_v1` capability；同一提交更新 CMake/build info、wire 文档、schema 和 golden vectors。
- [x] `M3A-02` 新增 discovery schema，并冻结无冲突的 IPv4/IPv6 multicast group、UDP port、datagram envelope/max wire size；定义有界 `LanPresence` 的设备公钥/ID、endpoint、boot nonce、sequence、relative lease、TLS port、能力和签名。
- [x] `M3A-03` 新增 `LAN_HELLO` schema 与 `lan_presence`/`lan_hello` canonical signing domain；hello 绑定双方身份/endpoint/nonce/boot nonce 及本端和对端 TLS 证书指纹。
- [x] `M3A-04` 实现 1.0/1.1 协商与 N-1/N 测试；1.0 peer 不得因未知可选能力失败，1.1 peer 不得向 1.0 peer 假定 LAN 支持。
- [x] `M3A-05` 为 Node/ProfileStore 增加 `automatic/lan_only/relay_only`、LAN enabled、discoverability、`auto_connect_trusted`、接口偏好、容量与 deadline 配置；非法或零控制容量启动失败。
- [x] `M3A-06` 明确本地初始化独立于 relay enrollment：profile 创建身份、endpoint、verifier 和 pairing policy 后即可进入 LAN-only readiness。

M3A 协议 change-control 验收记录（2026-08-15）：构建版本与公共协议版本升级为 1.1，冻结
`lan_discovery_v1`/`lan_signaling_v1` bits、`HYLD` v1 envelope、IPv4 `239.192.72.89`、IPv6
`ff12::4845:5941:4b49`、UDP `49189`、hop limit `1` 和 1200-byte datagram 上限；新增 Lite
`LanPresence`/`LanHello` schemas、两个 canonical signing domain 和经 Ed25519 独立验证的 golden
vectors。协议、来源一致性、Protobuf Lite、公共头及 fuzz smoke 针对性测试 5/5 通过；M1 1.0
golden vector 保留为 N-1 基线，1.1/1.0 协商不会泄漏 LAN capability。replay、capacity 和网络状态机
覆盖属于 M3A-07 之后的退出条件，仍保持未勾选。

### 6.2 M3A：Multicast discovery 与 endpoint directory

- [x] `M3A-07` 使用现有 executor-managed Asio runtime 在每个允许接口加入 IPv4 管理域和 IPv6 link-local multicast group，hop limit 固定为 1，不创建第二 worker/线程/poll loop。
- [x] `M3A-08` 实现带 jitter 的签名 presence announce/browse、monotonic lease、boot/sequence replay 检查和接口加入/离开/休眠恢复；单 datagram 不超过无分片配置上限。
- [x] `M3A-09` 在分配/缓存前验证 Protobuf 长度、版本、公钥派生 DeviceId、签名、endpoint、lease 和 sequence；未知自签身份保持 untrusted。
- [x] `M3A-10` 实现有界 `EndpointDirectory`，按完整 `(DeviceId, EndpointId)` 合并 LAN/relay 来源和 TTL；LAN hint 过期不撤销 TrustGrant 或删除 relay presence。
- [x] `M3A-11` 对目录、每接口、每源地址、未知身份、公告速率和诊断历史设置硬上限；满载保留已信任控制容量并显式拒绝。
- [x] `M3A-12` presence 不广播 display name、tenant、service manifest、scope、credential 或其他接口拓扑；日志按 identifier retention policy 处理完整 ID。

### 6.3 M3A：TLS 本地信令与 TUI

- [x] `M3A-13` 复用项目冻结的 OpenSSL 系列，以 Asio TLS 1.3/TCP 实现 boot-scoped certificate、动态监听端口、client/acceptor、握手 deadline 和有界 provisional connection。
- [x] `M3A-14` TLS 建立后只允许限长 `LAN_HELLO`；验证签名、公钥派生 ID、role、双方 nonce、boot nonce、版本和双方证书指纹后才进入 `AuthenticatedSignaling`。
- [x] `M3A-15` 实现内部 `DiscoveryProvider`、`EndpointDirectory`、`SignalingRoute` 和 `LanSignalingRoute`，只转发通过校验的 connect/accept/deny 与现有 signed offer/answer/candidate。
- [x] `M3A-16` 实现 LAN 优先、relay fallback preference、单逻辑 attempt/transport winner、自动连接 offer owner 和手工交叉连接的确定性仲裁。
- [x] `M3A-17` 关闭时在 `stop_producers`/`close_peers` hook 中依次停止公告/lease/timer、关闭 multicast socket/TLS listener/pending signaling，再释放 directory/route；所有 wait 有预算和终态。
- [x] `M3A-18` TUI 本机/LAN 视图展示 profile 初始化、接口 readiness、发现来源、untrusted/trusted endpoint、signaling/data path、配对入口和结构化失败，不把“已发现”显示成“已授权”。

M3A 本机实现验收记录（2026-08-16）：Profile schema v3、独立本地初始化、双栈逐接口
multicast、签名 presence 与有界 directory、boot-scoped TLS 1.3、三消息 `LAN_HELLO`、有界 LAN
signaling frame、确定性连接仲裁、executor-managed callback/lifecycle 和本机/LAN TUI 已接通。
Debug 全量构建及 CTest 22/22、ASan 定向 5/5、UBSan 定向 4/4 通过；TSAN 二进制完成构建，
但当前 Linux 宿主以 `ThreadSanitizer: unexpected memory mapping` 被测试包装器明确标记为不支持。
本机测试覆盖双 Node 无 relay 发现、TLS 身份绑定、认证前 signed signaling 拒绝、validator 拒绝、
同源 provisional TLS 限速与握手超时、trusted auto-connect、重复连接仲裁和有预算关闭。以下
网络、安全、跨平台和压力矩阵的后续补强与剩余门禁记录如下。

### M3A 测试与退出条件

- [x] golden vectors、Protobuf parser 和状态机 fuzz 覆盖 LAN presence/hello 的截断、超大、未知字段、签名冲突、boot/sequence replay 和 capacity-full。
- [x] 安全测试覆盖 multicast 洪泛/伪造、TLS slowloris/洪泛、每 IP 限速、证书指纹替换、双 TLS MITM/hello relay、版本降级和未认证 SDP/candidate。
- [x] Linux/Windows 可在 relay/STUN/TURN 全部未运行时双向发现；IPv4-only、IPv6 link-local、双栈、多网卡、接口切换和同 DeviceId 多 endpoint 均有稳定结果。
- [x] multicast blocked、Windows firewall/public network、AP isolation 模拟进入可解释失败，不挂起、不声称 LAN ready。
- [x] 发现/过期/交叉连接/取消/关闭压力下，socket、TLS、timer、operation、directory/replay cache 和 executor worker 无泄漏或无界增长。

M3A 网络与安全矩阵补强记录（2026-08-16）：新增 LAN directory replay/capacity 状态机 fuzz
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

M3A 跨平台 CI 确认（2026-08-16）：代码提交
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

M3A 最终退出验收（2026-08-16）：代码提交
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

### 6.4 M3B：Relay 控制面

- [x] `M3B-01` 实现 `heyaki-relay` TLS 1.3/WSS 服务骨架、健康检查、配置加载和有界 graceful shutdown。
- [x] `M3B-02` 实现 SQLite 表 `devices`、`bootstrap_tokens`、`device_audit` 及迁移；在线 presence 和 pending signaling 仅保存在有界 TTL 内存结构。
- [x] `M3B-03` 实现 bootstrap token 哈希、tenant 绑定、过期、使用次数和竞争消费事务。
- [x] `M3B-04` 实现 enrollment challenge-response，验证公钥派生 `DeviceId`、签名、token、`EndpointId` 和最小 capability。
- [x] `M3B-05` 实现设备吊销、enrollment generation 与审计；吊销后拒绝新登录，现有连接行为由配置明确。
- [x] `M3B-06` 实现自动登录 challenge-response，不要求 bootstrap token 或授权密码，但每次校验随机 challenge、generation 和状态。
- [x] `M3B-07` 实现 `(DeviceId, EndpointId)` 租约、心跳、到期、同设备多 endpoint 和同租户在线查询。
- [x] `M3B-08` 对 endpoint record/service manifest 验证设备签名、大小和字段上限，只暴露租户策略允许的最小信息。
- [x] `M3B-09` 为 enrollment/login/query/heartbeat 设置连接、请求、tenant 和 IP 级速率限制及明确拒绝指标。

### M3B 实施进度（2026-08-16）

M3B 已开始推进。入口冻结了 `heyaki-relay` 的 WSS 依赖门禁：Boost.Beast 1.88.0 及其
18 个新增模块 closure 已加入 `dependencies.lock`/`licenses.lock` 并完成离线 `--check`；
依赖政策与供应链审计文档已同步。`M3B-01` 的服务骨架已落地为 `heyaki_relay` target：
TLS 1.3-only Asio acceptor、Beast WebSocket 握手、`/health` 路径、每连接握手 deadline、
有界连接容量与满容量拒绝、配置加载/严格校验、SIGINT/SIGTERM 请求停止，以及由
executor-managed Runtime 承载的固定关闭 hook。新增 5 项 GCC 本地单元/集成测试，覆盖
配置文件解析/非法值、WSS health 端到端、握手 deadline、容量上限与有预算关闭。

本轮本机验证：GCC Debug 全量 CTest 25/25 通过（新增 `heyaki_m3b_relay` 与
`heyaki_relay_version`），GCC `-Werror`/禁异常构建通过，ASan/UBSan 定向 relay 测试各 1/1 通过；
SIGINT 驱动的 app 启动/监听/优雅退出已手工验证。Windows、完整 sanitizer 矩阵、长期压力
和 relay 协议栈尚未验证，因此 `M3B-01` 保持未勾选，M3B 继续为活动里程碑。

### M3B 实施进度（2026-08-16，第2轮）

第二轮完成 M3B-02/M3B-03 的服务端数据基座：

- 新增 `relay_database.hpp/.cpp`：relay SQLite schema v2（v1 建 `devices`、
  `bootstrap_tokens`、`device_audit` 与 `schema_migrations`，v2 增加 tenant/status、tenant/expiry、
  device/time 索引），独立 application_id，quick_check、迁移历史校验、v1→v2 事务迁移和
  `schema_too_new`/application_id 错误分类。
- bootstrap token 只保存 SHA-256 哈希；token 限制为 16..256 字节可打印非空白文本，
  tenant 严格 UTF-8；创建校验过期与 1..1000000 次使用上限。消费在 `BEGIN IMMEDIATE`
  事务中完成哈希查找、tenant/过期/剩余次数校验、原子扣减和审计写入，失败回滚且不产生审计。
- 新增有界 `RelayTtlTable<Key, Value>`（容量、TTL、upsert/refresh、lazy expiry、显式 expire、
  snapshot 与 diagnostics），作为后续在线 presence 和 pending signaling 的唯一内存形态。
- `RelayServerConfig` 增加 `database_file`（配置键 `database_file`，CLI `--database`）；
  `RelayServer` 启动时打开/迁移数据库并把 schema/计数发布到快照。

验证：relay 测试可执行文件现含 15 项测试（新增 token 哈希边界、建库/重开、v1 迁移、
错误头、过期/耗尽/tenant 拒绝、重复消费、raw token 不落盘、双连接并发消费唯一胜者、
TTL 表容量/刷新/过期/擦除），GCC Debug 全量 CTest 25/25，`-Werror`/禁异常构建通过，
ASan/UBSan 定向 relay 测试各 1/1。因 Windows、完整 M3B 验收和 enrollment 协议流尚未完成，
`M3B-02`/`M3B-03` 继续保持未勾选。

### M3B 实施进度（2026-08-16，第3轮）

第三轮推进 M3B-04，并落地 M3B-05 的设备表操作：

- 新增 `relay_enrollment.hpp/.cpp`：`EnrollmentChallenge`/`EnrollmentRequest` 的
  Protobuf 1.1 编码/严格解析、随机 challenge 创建、`heyaki.enrollment.v1` canonical
  signing，以及验证链（公钥派生 `DeviceId`、challenge nonce/过期、请求过期、1.1 capability
  negotiation、Ed25519 签名）。解析器拒绝截断、重复字段、未知字段和非规范 varint。
- 新增 `relay_enrollment_service.hpp/.cpp`：有界 challenge 表（复用 `RelayTtlTable`）、
  单次 challenge 消费、签名验证后竞争消费 bootstrap token、写入/审计 `devices`，
  并返回 enrollment generation 与 token 剩余次数；错误分为 validation/token/database 指标。
- `RelayDatabase` 增加 `enroll_device`（幂等同 generation 重试、拒绝旧 generation/identity
  冲突）、`device` 查询、`revoke_device`（generation 必须更新且审计）。
- 测试新增 challenge round-trip/边界、签名请求 round-trip、身份/challenge/过期/签名篡改、
  未知 required capability、parser 拒绝、设备 enrollment/重试/吊销/重登记，以及 service 的
  token 多设备流程与容量拒绝。relay 测试可执行文件现含 23 项测试。

本机验证：GCC Debug 全量 CTest 25/25，`-Werror`/禁异常构建通过，ASan/UBSan 定向 relay
测试各 1/1。GitHub Actions run `31925713758` 结论 success：Linux GCC/Clang Debug/Release、
Windows Debug/Release、ASan/UBSan/TSAN 全部通过。CI 整改包含空 optional 读取修复、
relay SQLite 改用 DELETE journal、MSVC `/bigobj`，以及把既有 Node begin 调度到 strand 消除
TSAN 竞争。WSS 控制消息尚未接入这些 service，完整 M3B 验收未完成，因此
`M3B-04`/`M3B-05` 保持未勾选。

### M3B 实施进度（2026-08-16，第4轮）

第四轮推进 M3B-06 自动登录 challenge-response：

- 冻结 `heyaki.relay-login.v1` signing domain：12 个 canonical 字段在 enrollment 基础上
  增加 enrollment generation；wire 文档签名域表已同步，signing 单元测试覆盖 shape/UTF-8。
- 新增 `relay_login.hpp/.cpp`：`RelayLoginChallenge`/`RelayLoginRequest` 的 Protobuf 编码与
  严格解析、canonical signing，以及验证链（公钥派生 `DeviceId`、challenge nonce/过期、
  请求过期、capability negotiation、Ed25519 签名、数据库 device 公钥/tenant 匹配、状态与
  enrollment generation）。
- 新增 `relay_login_service.hpp/.cpp`：有界单次 challenge 表；authenticate 不再要求
  bootstrap token 或授权密码，成功写 `device_login` audit，拒绝尝试写 `device_login_rejected`；
  diagnostics 区分 unknown challenge、validation、device 与 audit 失败。
- 测试新增 login challenge/request round-trip、成功认证与审计、错误 generation/tenant/
  已吊销设备/错误签名，以及 parser 拒绝重复、未知、截断字段。relay 测试现含 27 项。

本机验证：GCC Debug 全量 CTest 25/25，Release relay 27/27，`-Werror`/禁异常构建通过，
ASan/UBSan 定向 relay 测试通过，TSAN（关闭 ASLR）relay 27/27。GitHub Actions run
`31927188575` 结论 success：Linux GCC/Clang Debug/Release、Windows Debug/Release、
ASan/UBSan/TSAN 全部通过。WSS 控制消息尚未接入，完整 M3B 验收未完成，因此
`M3B-06` 保持未勾选。

### M3B 实施进度（2026-08-16，第5轮）

第五轮推进 M3B-07 在线租约表：

- 新增 `relay_lease_table.hpp/.cpp`：以完整 `(DeviceId, EndpointId)` 为 key 的有界内存
  租约表；heartbeat 支持插入/刷新、generation 单调递增、默认 45 秒 lease、最大 lease 上限
  与 tenant 绑定；同一 `DeviceId` 可挂多个 `EndpointId`，同一 tenant 可查询全部在线 endpoint。
- 硬上限与拒绝分类：总容量、每设备 endpoint 容量、每租户设备容量；tenant 冲突、非法 key/
  tenant、超长 lease 均返回稳定错误。过期、remove、remove_device 会同步清理设备/租户索引。
- 在线查询接口：`online`、`online_device`、`online_tenant`，均按当前 steady clock 过滤过期项；
  diagnostics 覆盖 accepted/refreshed/expired/removed/各类 capacity rejection 与峰值。
- 测试新增 4 项：插入/刷新与多 endpoint/tenant 查询、过期与索引清理、三类容量拒绝、
  tenant 冲突与非法配置。relay 测试现含 31 项。

本机验证：GCC Debug 全量 CTest 25/25，Release relay 31/31，`-Werror`/禁异常构建通过，
ASan/UBSan 定向 relay 测试通过，TSAN（关闭 ASLR）relay 31/31。GitHub Actions run
`31928348709` 结论 success：Linux GCC/Clang Debug/Release、Windows Debug/Release、
ASan/UBSan/TSAN 全部通过。WSS heartbeat 消息尚未接入，完整 M3B 验收未完成，因此
`M3B-07` 保持未勾选。

### M3B 实施进度（2026-08-16，第6轮）

第六轮推进 M3B-08 endpoint record 与 service manifest：

- 新增 `relay_endpoint.hpp/.cpp`：`RelayEndpointRecord`/`RelayServiceManifest` 的
  Protobuf 编码与严格解析、`heyaki.endpoint-record.v1`/`heyaki.service-manifest.v1`
  canonical signing，以及基于数据库设备公钥/状态的验签（吊销设备拒绝）。
- 大小与字段上限：单消息 16 KiB、application_id 1..255 字节严格 UTF-8、generation/hash/expiry
  非零、endpoint 非零；parser 拒绝重复、未知、截断、超长和非规范 varint。
- manifest 可与 endpoint record 绑定校验（同 endpoint 且 manifest hash 一致）。
- 新增 `RelayTenantExposurePolicy`/`RelayEndpointPublication`：只输出租户策略允许的字段；
  默认最小策略仅暴露完整 endpoint 与 expiry，不暴露 application_id、generation、manifest hash。
- 测试新增 4 项：record round-trip/吊销/签名、manifest round-trip/绑定/签名、租户最小/全量
  暴露、parser 拒绝。relay 测试现含 35 项。

本机验证：GCC Debug 全量 CTest 25/25，Release relay 35/35，`-Werror`/禁异常构建通过，
ASan/UBSan 定向 relay 测试通过，TSAN（关闭 ASLR）relay 35/35。GitHub Actions run
`31929776482` 结论 success：Linux GCC/Clang Debug/Release、Windows Debug/Release、
ASan/UBSan/TSAN 全部通过。WSS endpoint 注册/查询消息尚未接入，完整 M3B 验收未完成，
因此 `M3B-08` 保持未勾选。

### M3B 实施进度（2026-08-16，第7轮）

第七轮推进 M3B-09 速率限制：

- 新增 `relay_rate_limiter.hpp/.cpp`：四个独立 token bucket 维度——
  connection（按连接 ID）、request（全局）、tenant（按租户）、ip（按来源 IP）。
  每维度有 capacity/window/max_keys，默认 policy 覆盖 16/s、256/s、64/s、32/s。
- 每个 bucket 使用整数 micro-token 精确补水和消耗；key 表有硬上限，新 key 在满载时
  先按 entry TTL 清理，仍满则拒绝并计 `capacity_rejected`；普通超限返回
  `resource_exhausted/rate_limit_exceeded`。diagnostics 记录 allowed/rejected/
  capacity_rejected/current/peak。
- `RelayServerConfig` 增加 `rate_limits`，`RelayServer` 启动时创建 limiter 并把四个维度
  指标发布到快照，供后续 WSS handler 统一调用。
- 测试新增 4 项：四维度 token 限制、key 表容量拒绝、idle prune、非法 policy/key。
  relay 测试现含 39 项。

本机验证：GCC Debug 全量 CTest 25/25，Release relay 39/39，`-Werror`/禁异常构建通过，
ASan/UBSan 定向 relay 测试通过，TSAN（关闭 ASLR）relay 39/39。GitHub Actions run
`31931389055` 结论 success：Linux GCC/Clang Debug/Release、Windows Debug/Release、
ASan/UBSan/TSAN 全部通过。WSS 控制消息尚未接入，完整 M3B 验收未完成，因此
`M3B-09` 保持未勾选。

### M3B 实施进度（2026-08-16，第8轮）

第八轮推进 M3B-10/M3B-11 TURN credential 与 coturn 部署基线：

- 新增 `relay_turn_credentials.hpp/.cpp`：TURN REST API HMAC-SHA1/base64 实现，
  使用 coturn 官方 known vector 验证；username 格式
  `<expiry_unix_seconds>:<tenant>:<DeviceId>`，password 只在 credential 对象中返回。
- 密钥轮换：最多 4 个 secret generation，新签发使用最新 generation，旧 generation 在
  其 TTL 内继续验证；替换/淘汰采用有界向量与 `sodium_memzero` 清理旧 secret。
- 服务端校验：过期、篡改、缺 secret、非法 tenant/secret 均返回稳定错误；diagnostics
  记录 issued/validated/validation_rejected/active generations。
- 新增 `deploy/coturn/`：README 固定 `coturn/coturn:4.10.0-debian` 与 immutable digest
  `sha256:f4c2af06c3c535c4f49d64e14d484104e7e4fcc98c4cb83d6e1544f64d1e6158`；
  `turnserver.conf` 启用 `use-auth-secret`、TLS 5349、受限 peer 网段、端口范围/配额；
  `docker-compose.yml` 使用 digest 拉取且不提交真实 secret；env example 通过环境变量注入。
- 新增 CTest `heyaki_coturn_deployment_contract` 检查 pin、config 关键项与“不提交真实
  static-auth-secret”。
- 测试新增 5 项 TURN credential 测试。relay 测试现含 44 项，全量 CTest 26/26。

本机验证：GCC Debug 全量 CTest 26/26，Release relay 44/44，`-Werror`/禁异常构建通过，
ASan/UBSan 定向 relay 测试通过，TSAN（关闭 ASLR）relay 44/44。GitHub Actions run
`31932919521` 结论 success：Linux GCC/Clang Debug/Release、Windows Debug/Release、
ASan/UBSan/TSAN 全部通过。尚未在真实 coturn 实例上做 allocation 端到端验证，因此
`M3B-10`/`M3B-11` 保持未勾选。

### M3B 实施进度（2026-08-16，第9轮）

第九轮推进 M3B-12/M3B-13 coturn 资源策略与本地拓扑：

- `turnserver.conf` 增加 `external-ip`、每会话 2 Mbit/s、服务器 16 Mbit/s 容量、
  3600 秒最大 allocation lifetime；已有 total/user quota、49160-49200 端口范围、
  私网/链路本地/环回 peer 拒绝与 TLS 证书配置。
- README 记录资源策略、TURN credential 契约和 `run_topology.sh` 使用方法。
- 新增 `deploy/coturn/run_topology.sh`：两个隔离 client namespace、两个 host bridge、
  iptables 阻断 client 间转发、host coturn 与 `heyaki-relay` 分别启动、从两个 namespace
  验证 STUN 与 relay WSS TCP 可达性、检查隔离后自动清理。coturn 保持独立进程，不嵌入 relay。
- 新增 CTest `heyaki_coturn_topology_check`：环境缺少 root/namespace/coturn 时按 77 skip；
  具备环境时验证脚本与二进制可用性。部署 contract 同步检查新配置项和拓扑脚本关键行为。
- 全量 CTest 现为 27 项；本机网络 harness 与 coturn topology 按环境限制 skip，其余全通过。
  GitHub Actions run `31933990848` 结论 success：Linux GCC/Clang Debug/Release、
  Windows Debug/Release、ASan/UBSan/TSAN 全部通过。尚未在具备 CAP_NET_ADMIN 且安装
  coturn 的专用环境执行完整拓扑，因此 `M3B-12`/`M3B-13` 保持未勾选。

### 6.5 M3B：TURN credential 与部署

- [x] `M3B-10` 固定 coturn 配置与容器/包版本，启用 TURN REST API 风格 HMAC 临时 credential。
- [x] `M3B-11` credential 用户名绑定到期时间、设备和租户；密钥支持轮换，日志不得记录完整 credential。
- [x] `M3B-12` 配置 allocation、带宽、并发、relay 端口范围、禁止内网管理 peer 地址、TLS certificate 和 advertised address。
- [x] `M3B-13` 建立本地一键测试拓扑：relay + coturn + 两个隔离 client namespace，不把 coturn 嵌入 relay 进程。

### M3B 实施进度（2026-08-16，第10轮）

第十轮推进 M3B-14 设备端 WSS client：

- 新增 `src/client/relay_wss_client.hpp/.cpp`：executor-managed Beast/Asio WSS client。
  TLS peer/hostname 验证、可选 CA file、可选 32 字节证书 pin、连接/握手/关闭 deadline。
- 安全错误分类：DNS/连接失败 -> `relay_unavailable`，TLS 验证/pin 失败 -> `authentication`，
  超时 -> `timeout`，取消 -> `cancelled`，WebSocket/transport 错误保持稳定分类。
- 有界通信：接收与发送均使用 `executor::comm::MpscChannel`，满载显式拒绝；
  发送串行化于 strand，关闭时 close channels。连接状态通过 `DoubleBuffer` 发布。
- 测试新增 4 项：TLS pin 匹配 + health 接收、错误 pin、无信任 CA 的 peer 验证失败、
  非法 URL/空或超大 payload。relay 测试现含 48 项。

本机验证：GCC Debug 全量 CTest 27/27（2 项环境 skip），Release relay 48/48，
`-Werror`/禁异常构建通过，ASan/UBSan 定向 relay 测试通过，TSAN（关闭 ASLR）relay 48/48。
GitHub Actions run `31937069733` 结论 success：Linux GCC/Clang Debug/Release、
Windows Debug/Release、ASan/UBSan/TSAN 全部通过。enrollment/login 协议尚未通过该 client
跑端到端，因此 `M3B-14` 保持未勾选。

### M3B 实施进度（2026-08-16，第11轮）

第十一轮推进 M3B-15/M3B-16 的客户端 enrollment 持久化语义：

- `ProfileStore` 新增 `put_relay_enrollment`、`relay_enrollment`、
  `relay_enrollments`：原子 upsert/查询 relay URL、pin、tenant、generation、
  auto_connect、revoked；校验 URL scheme、32 字节 pin、非空 tenant 与 generation。
- 新增公共 `relay_enrollment_client.hpp/.cpp`：`enroll_relay_profile` 只使用已有本地
  identity/endpoint，不隐式创建 profile；通过可注入 exchange 完成 challenge/request 流程，
  成功后才写 ProfileStore；exchange 失败不落盘；结果不匹配或持久化失败时调用 rollback，
  rollback 失败返回 `outcome_unknown`。
- 测试新增 profile 3 项（写入/查询/重开、吊销 generation、非法记录）与 client 4 项
  （成功持久化、exchange 失败不持久化、mismatch rollback、未初始化 profile 不隐式创建）。
  relay 测试现含 52 项，profile 测试增加 3 项。

本机验证：GCC Debug 全量 CTest 27/27（2 项环境 skip），Release relay 52/52，
`-Werror`/禁异常构建通过，ASan/UBSan/TSAN 均覆盖 relay 与新增 profile 测试。
GitHub Actions run `31938772323` 结论 success：Linux GCC/Clang Debug/Release、
Windows Debug/Release、ASan/UBSan/TSAN 全部通过。真实 WSS exchange 尚未接入
（exchange 为可注入 transport），因此 `M3B-15`/`M3B-16` 保持未勾选。

### 6.6 M3B：客户端 enrollment 与 TUI

- [x] `M3B-14` 实现设备端 WSS client、证书/主机名校验、可选 relay pin 和安全错误分类。
- [x] `M3B-15` 实现可选 relay enrollment API：只使用现有本地身份/endpoint，提交成功 record 后原子写 ProfileStore，不重新生成身份或 verifier。
- [x] `M3B-16` 只有 enrollment 持久化成功才报告完成；失败时撤销或标记服务端半完成 enrollment 以便安全重试。
- [x] `M3B-17` 实现自动登录、15 秒默认心跳、3 次丢失离线和带 jitter 的有界指数退避；安全错误停止自动重试，relay 失败不关闭 LAN readiness。
- [x] `M3B-18` TUI onboarding 将“创建本地身份”和“连接 Relay”分成明确步骤，密码控件隐藏内容且不进入 history/log。
- [x] `M3B-19` TUI Relay 视图展示 enrollment、租约、重连、endpoint 来源和需要人工处理的状态；本机/LAN 视图在 relay 不可用时仍可操作。
- [x] `M3B-20` TUI renderer 只消费有界 `UiEvent` 通道；高频状态使用 latest-only 聚合，关闭时先取消 operation 再释放 profile。

### M3B 实施进度（2026-08-16，第12轮）

第十二轮把 enrollment 从独立 service 接入真实 TLS/WSS 控制路径：

- 新增公共 `relay_wss_control.hpp/.cpp`，冻结 `/control` 二进制 envelope、64 KiB 总上限、
  enrollment challenge/request/result 与结构化 `control_error`，并同步 normative enrollment
  v1 Protobuf schema；parser 拒绝未知 type、长度不符、非规范 Protobuf、非法 UTF-8、未知错误码
  和不安全 detail。
- `RelayServer` 以 TLS certificate SHA-256 派生非零 relay ID，新增严格两步 enrollment session；
  challenge 绑定发起 WSS session，签名/身份/capability 校验、bootstrap token 竞争消费、
  device/audit 事务和结果响应现已通过同一连接闭环。错误只返回稳定 code/safe token，
  不回显 token 或数据库内容。
- `/control` 的所有 session 复用 executor 托管 Asio runtime 的 relay strand，SQLite、challenge
  TTL 表、限流器和 server snapshot 不跨 strand 并发访问；未新增线程、锁或私有执行循环。
  每个消息在解析前计入 connection/global request/IP 限流，合法 enrollment 再以 tenant 的
  SHA-256 派生键计 tenant 限流，避免 UTF-8 tenant 受限流 key 文本格式影响。
- server snapshot 新增 control session、challenge、完成与拒绝计数；WSS client 默认发送 binary。
  新增控制 envelope 单元测试和真实 TLS/WSS enrollment 集成测试，覆盖成功登记、证书 pin 与
  relay ID 绑定、四维限流计数、签名篡改结构化拒绝，以及失败时 device/audit 不变。

本机验证：GCC Debug `-Werror` 全量 CTest 27/27（coturn 拓扑 1 项环境 skip），relay 58/58；
禁异常 `heyaki-relay` 与公开头独立编译通过，ASan/UBSan/TSAN 定向 relay 测试各 1/1 通过。
本轮完成后，`M3B-01`～`M3B-04` 与 `M3B-14` 已满足条目并勾选。自动登录、
heartbeat/lease、endpoint publish/query 和真实 ProfileStore enrollment exchange 仍未接入
`/control`，因此 `M3B-05`～`M3B-09` 与 `M3B-15`～`M3B-20` 继续保持未勾选；真实 coturn
allocation 和隔离拓扑尚未完成，`M3B-10`～`M3B-13` 同样保持未勾选。
GitHub Actions run `31944662316` 结论 success：Linux GCC/Clang Debug/Release、
Windows Debug/Release、ASan/UBSan/TSAN 全部通过。

### M3B 实施进度（2026-08-16，第13轮）

第十三轮把自动登录、租约、endpoint directory 与客户端 onboarding 闭环接入 `/control`：

- `relay_wss_control` 增加 `login_challenge/login_request/login_result`、
  `heartbeat/heartbeat_ack`、`endpoint_publish/endpoint_publish_ack`、
  `endpoint_query/endpoint_query_result`，并新增 normative
  `proto/heyaki/relay/v1/relay_control.proto`；编码器与生成的 Protobuf Lite 消息逐字节一致，
  parser 拒绝重复/未知/截断/非规范字段。
- `RelayServer` 增加 login service、lease table 与有界 endpoint directory 的 WSS 状态机：
  challenge 会话绑定、登录 tenant/generation/吊销校验、45 秒默认租约、heartbeat 刷新、
  同设备多 endpoint、同租户查询、默认最小 exposure policy、记录签名与 manifest 绑定、
  connection 关闭时清理 lease/record；`close_revoked_sessions` 配置决定已登录会话在吊销后
  是否被下一次控制消息关闭。快照补齐 login/lease/endpoint 计数与诊断。
- enrollment/login/endpoint 协议 codec 移入 `heyaki_client`，`enroll_relay_profile` 在没有注入
  exchange 时使用真实 TLS/WSS 路径完成 challenge/request/result；服务端对同租户同身份
  enrollment 幂等，持久化失败后的安全重试不再要求剩余 token。
- `Node` 从 `ProfileStore` 的 auto-connect enrollment 或 `relay_override` 启动自动登录：
  复用同一 executor-managed Asio runtime 的 strand 与三个定时器，实现 15 秒默认心跳、3 次丢失
  离线、带 jitter 的有界指数退避、安全错误停止重试；relay 失败只更新 relay 状态，不关闭
  LAN readiness。`RelayWssClient` 增加非阻塞 `start_connect`/`try_receive`，不新增线程或
  私有执行循环。
- `heyaki-tui` 把 `relay` 作为本地初始化后的独立 onboarding 步骤；bootstrap token 继续使用
  隐藏输入并立即擦除。状态/交互视图显示 `RELAY` 状态、url、tenant、generation、lease、
  heartbeat/missed、reconnect 与 backoff；LAN 视图在 relay 不可用时保持可操作。UI 仍只消费
  有界 `UiEvent` channel，relay 高频状态经 `DoubleBuffer` latest-only 聚合。

验证：GCC Debug `-Werror` 全量 CTest 27/27；`heyaki_m3b_relay` 70/70，新增 WSS 登录/心跳/
endpoint publish/query、吊销会话关闭、真实 ProfileStore enrollment + 幂等重试、Node 自动登录
与 profile 重启自动登录、同设备多 endpoint 查询及 control payload golden-byte 测试。
`_GLIBCXX_DEBUG` 与定向 TSAN（关闭 ASLR）70/70 通过，修复了 WSS 异步 handler 生命周期和
owned runtime 关闭线程归属问题。GitHub Actions run `31957570954` 结论 success：
Linux GCC/Clang Debug/Release、Windows Debug/Release、ASan/UBSan/TSAN 全部通过。
本轮完成后 `M3B-05`～`M3B-09` 与 `M3B-15`～`M3B-20` 满足条目并勾选；真实 coturn allocation
和隔离拓扑仍受当前环境无 root/coturn 限制，`M3B-10`～`M3B-13` 与对应退出条件保持未勾选。

### M3B 实施进度（2026-08-16，第15轮）

第十五轮补齐 M3B 测试退出条件：

- 新增 `heyaki-m3b-relay-demo`：初始化/复用本地 profile、写入 relay bootstrap token，
  并以库应用身份自动登录持有 Node；同一 profile 可同时承载 TUI 与 demo 两个 endpoint。
- 新增 `tests/network/run_m3b_relay_onboarding_harness.sh` 与 Python pty driver：
  在既有本地 profile 上通过 `heyaki-tui` 完成真实 relay enrollment；随后不输入凭据重启
  TUI `--status` 与独立库 demo，验证两者自动登录、`DeviceId` 相同且 `EndpointId` 不同。
  TUI `--status` 对 relay ready 做最多 3 秒有界等待。
- harness 使用无 root Python TCP 代理抓取真实 WSS 字节流，并扫描 relay DB、relay 日志与
  WSS 抓包，确认不出现授权密码明文、Argon2id verifier 或私钥。
- `heyaki_m3b_relay` 新增 relay 重启后 Node 自动重连测试，以及真实 WSS enrollment P95
  测量（本地 P95 约 17ms，阈值 2000ms）；测试现为 72/72。
- 本机 GCC Debug `-Werror` 全量 CTest 29/29（2 项环境 skip）；`HEYAKI_COTURN_ROOT`
  指向 pinned 4.10.0 rootfs 时 allocation probe 通过。
- GitHub Actions run `31961219500` 结论 success：Linux GCC/Clang Debug/Release、
  Windows Debug/Release、ASan/UBSan/TSAN 全部通过；新增 `coturn-topology` job 输出
  `TOPOLOGY_OK`，Linux/Windows 测试均运行 M3B onboarding harness。
- M3B 测试退出条件全部勾选，里程碑关闭。

### M3B 实施进度（2026-08-16，第14轮）

第十四轮用 pinned coturn 4.10.0 镜像完成真实 TURN REST allocation 验收：

- 修复 `deploy/coturn/turnserver.conf` 与 pinned `coturn/coturn:4.10.0-debian@sha256:f4c2...`
  的兼容性：删除 4.10.0 已不支持的 `no-loopback-peers`，保留显式
  `denied-peer-ip=127.0.0.0-127.255.255.255` 与 coturn 默认 loopback peer 拒绝语义。
- 新增 `deploy/coturn/run_allocation_probe.sh`：无需 root，使用与部署相同的
  `turnserver.conf` 模板生成临时证书/配置，启动真实 coturn，按
  `<expiry>:<tenant>:<DeviceId>` username 完成 TURN REST allocation 并确认 relayed data
  admission；同时扫描 coturn 日志确认不出现 `static-auth-secret`。
- 在本机从 Docker Registry 校验 pinned digest 并解包 `coturn/coturn:4.10.0-debian`
  amd64 rootfs，以镜像自带动态加载器直接运行 4.10.0 `turnserver`/`turnutils_uclient`，
  `ALLOCATION_OK version=4.10.0`。CTest `heyaki_coturn_allocation_probe` 在提供
  `HEYAKI_COTURN_ROOT` 时通过，环境无 coturn 时按 77 skip；deployment contract
  同步拒绝 `no-loopback-peers` 并检查新 probe。
- 新增 CI `coturn-topology` job：在 ubuntu-24.04 runner 安装 fallback coturn 包，
  构建 `heyaki-relay`，随后以 root 运行 `run_topology.sh`；已通过
  `TOPOLOGY_OK relay=8443 turn=3478 clients=10.77.0.10,10.77.1.10`。
- 本轮完成后 `M3B-10`～`M3B-13` 满足条目并勾选，M3B-01～20 实现项全部完成。

### M3B 测试与退出条件

- [x] 覆盖 token 过期/重复消费、伪造 DeviceId、错误签名、吊销 generation、重复 endpoint、租约到期和 relay 重启。
- [x] 抓取 relay DB、日志和 WSS 流量，确认不存在授权密码明文、Argon2id verifier 或私钥。
- [x] TUI 可在既有本地 profile 上完成 enrollment；重启 TUI 与独立库 demo 后均无人工输入自动登录。
- [x] TUI 与库 demo 使用同一 `DeviceId`、不同 `EndpointId` 同时在线，LAN/relay directory 合并后不混淆 endpoint。
- [x] 正常网络下登记 P95 小于 2 秒；不达标时保留测量、瓶颈和后续基线，不通过退出门禁。

---

## 7. M4：公共签名信令、WebRTC 与最小会话

### 7.1 信令与 Transport SPI

- [x] `M4-01` 实现内部 `TransportSession`/`TransportChannel` SPI、`ChannelOptions`、close reason，以及分离 `signaling_path`/`data_path` 的 `PathInfo`，不暴露为稳定第三方插件 ABI。
- [x] `M4-02` 实现 `SignalingCoordinator` 对 `LanSignalingRoute`/`RelaySignalingRoute` 的统一 connect/accept/deny/trickle 状态机；所有 pending 项都有 request ID、TTL、大小、来源和速率上限。
- [x] `M4-03` 实现 offer、answer、ICE ufrag、fingerprint、双方 ID、endpoint、nonce 和 expiry 的规范化签名与验签。
- [x] `M4-04` 建立 replay cache，拒绝重复 request ID、nonce、过期对象和 session epoch 迟到信令。
- [x] `M4-05` 未通过签名、公钥派生 ID 和 endpoint 验证时，不把 SDP/candidate 交给 transport。

### 7.2 WebRTC/ICE/TURN

- [x] `M4-06` 实现 `WebRtcTransportSession`，包装 libdatachannel PeerConnection、DataChannel callback、错误和关闭状态。
- [x] `M4-07` 配置 candidate 优先级：IPv6 host、LAN IPv4、srflx UDP、TURN/UDP、已验证的 TURN/TCP/TLS；`lan_only` 不配置 ICE server 且失败时明确终止。
- [x] `M4-08` 并行收集/检查 direct 与 relay candidate，relay 可提前分配但低优先级提名，禁止串行等待长直连超时后才开始 TURN。
- [x] `M4-09` 实现 `path_info()`、signaling route、selected candidate/data path、RTT、buffered amount、ICE state 和 restart 事件观测。
- [ ] `M4-10` 实现网络接口变化的 presence 刷新与 ICE restart；association 或 signaling route 丢失则建立新物理 session，不伪装为无损迁移。
- [x] `M4-11` 映射 libdatachannel callback 到 executor-managed 有界通道；满载、关闭和投递失败都有错误/统计。
- [x] `M4-12` 基于 `bufferedAmount` high/low water callback 暂停/恢复发送，验证底层背压能传回 API。

### 7.3 最小身份会话与诊断 UI

- [x] `M4-13` 实现 `SESSION_HELLO`，在 fingerprint 已验证的 DataChannel 上绑定签名 signaling transcript、session ID/epoch、endpoint、能力摘要和签名。
- [x] `M4-14` 实现最小状态机 `Idle -> ResolvingEndpoint -> Signaling -> Gathering -> Checking -> TransportConnected -> Authenticating -> Closed`，每次转换记录 source/reason/timestamp。
- [x] `M4-15` 在授权功能尚未实现时，成功认证的测试设备只开放内部 control ping，不开放通用业务通道。
- [x] `M4-16` TUI 设备/诊断视图展示 LAN/relay endpoint 来源、建连阶段、signaling/data path、candidate、RTT 和结构化失败。
- [x] `M4-17` 增加测试专用策略强制 `lan_only`、`relay_only`、direct、TURN/UDP、TURN/TCP/TLS 或禁止某类 candidate，避免公网偶测。

### M4 测试与 Connectivity MVP 退出条件

- [x] relay/STUN/TURN 全部未运行时，同一测试 LAN 的三台设备可发现正确 endpoint 并通过 host candidate 建立认证 DataChannel。
- [ ] 覆盖 LAN IPv4/IPv6、同 DeviceId 多 endpoint、交叉连接、direct、强制 TURN、对称 NAT、hairpin、IPv6-only、UDP blocked、高延迟、丢包、重复 candidate 和 relay 中途重启。
- [ ] 伪造/替换 LAN hello 证书指纹、fingerprint、offer、endpoint、nonce 或 expiry 时双方都拒绝，LAN MITM 与 relay 都无法冒充 peer。
- [ ] LAN 与 relay 同时可用时 endpoint 正确去重、LAN 优先/relay fallback 受策略控制，每个逻辑 attempt 只有一个 transport winner。
- [ ] 可打洞环境建连 P95 小于 3 秒；直连失败 TURN fallback P95 小于 5 秒。
- [ ] 100% 失败/取消/关闭路径最终进入终态，executor worker、Asio work、DataChannel 和 replay cache 无泄漏。
- [ ] TUI 可以从 LAN/relay 合并列表选择正确 endpoint 建立认证后的最小会话，并准确显示 signaling/data path。

### M4 实施进度（2026-08-17，第1轮）

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

### M4 实施进度（2026-08-18，第2轮）

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

### M4 实施进度（2026-08-18，第3轮）

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

### M4 实施进度（2026-08-18，第4轮）

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

### M4 实施进度（2026-08-18，第5轮）

新增内部 `PeerSession` 会话层：它接收已验证的 session binding，拥有 control channel
生命周期，在 transport connected 后发送带 wire frame 的签名 `SESSION_HELLO`；响应方只在
收到并成功 admission 后回发 hello。冲突签名、epoch、transcript、endpoint 或 capability
会关闭 transport。认证前不开放业务通道，认证后仅允许受限 control `PING/PONG`，并拒绝
重复 pending ping。loopback 测试覆盖双方 mutual hello、认证状态和 control ping/pong，
据此完成 `M4-15`。

该轮仍不勾选 `M4-13`：真实 WebRTC 测试尚未把 DTLS fingerprint 已验证的 signaling binding
传入 `PeerSession`，Node 的 LAN/relay coordinator 也尚未自动创建该层；下一轮继续补齐这两个
集成门禁。

### M4 实施进度（2026-08-18，第6轮）

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

### M4 实施进度（2026-08-19，第7轮）

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

### M4 实施进度（2026-08-19，第8轮）

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

### M4 实施进度（2026-08-19，第9轮）

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

### M4 实施进度（2026-08-19，第10轮）

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

### M4 实施进度（2026-08-19，第11轮）

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

### M4 实施进度（2026-08-19，第12轮）

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

### M4 实施进度（2026-08-19，第13轮）

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

### M4 实施进度（2026-08-19，第14轮）

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

### M4 实施进度（2026-08-19，第15轮）

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

---

## 8. M5：会话授权、调度与 ByteStream

### 8.1 Framing 与通道调度

- [ ] `M5-01` 实现增量 frame encoder/decoder，覆盖 varint、最大长度、零拷贝所有权和未来 transport 兼容。
- [ ] `M5-02` 实现 control、pairing、message、RPC、event、file、shell 逻辑通道创建规则和各自默认可靠性/顺序选项。
- [ ] `M5-03` 实现每 peer 总预算、每 channel 字节/消息预算和控制帧保留额度；配置非法时启动失败。
- [ ] `M5-04` 实现加权调度：control/Shell > RPC/message > event/file，并以可重复 benchmark 验证无饥饿。
- [ ] `M5-05` 满队列按协议选择 `reject/drop-oldest/keep-latest`，向调用方返回 `would_block` 或可取消容量等待，禁止静默 drop。
- [ ] `M5-06` 实现 capability/版本协商和局部通道关闭；单个可选业务协议错误不应无条件破坏整个 session。

### 8.2 Pairing 与 TrustGrant

- [ ] `M5-07` 完整实现 `PairingRestricted` 状态，只接受大小、时长、尝试次数受限的 pairing frame。
- [ ] `M5-08` pairing 发起方必须先在实际 DataChannel 上完成长期设备身份、endpoint、DTLS fingerprint 与 signaling transcript 验证；匿名 LAN/relay 来源不进入 pairing channel。
- [ ] `M5-09` 在端到端认证通道中提交密码、requested scopes 和一次性 nonce，目标用本地 Argon2id verifier 验证。
- [ ] `M5-10` 实现按来源设备、目标、连接/IP 的失败计数、指数退避和审计；不使用可被远程触发的永久全局锁死。
- [ ] `M5-11` 签发有方向的 TrustGrant，绑定双方 ID、scope、generation、grant ID、签发时间和可选 expiry。
- [ ] `M5-12` 实现 grant 出示、签名/范围/有效期/撤销检查，以及请求 scope、grant 与 endpoint/service policy 的交集裁决。
- [ ] `M5-13` 实现撤销、仅轮换密码、轮换并撤销旧 generation grant 三种明确操作。
- [ ] `M5-14` 会话升级后才允许创建业务通道；失败、禁用或超时发送稳定 `AUTH_DENIED` 并关闭受限会话。

### 8.3 ByteStream

- [ ] `M5-15` 实现 `STREAM_OPEN/DATA/WINDOW_UPDATE/FIN/RESET` 和 stream ID/offset 校验。
- [ ] `M5-16` 实现接收字节与 frame 双重窗口；窗口耗尽时发送方停止产生 DATA，不只依赖 SCTP buffer。
- [ ] `M5-17` 实现 `async_read_some`、`async_write`、`shutdown_write` 和 `reset` 的 deadline/cancellation/partial completion 语义。
- [ ] `M5-18` 明确成功 write 只表示进入受控发送窗口，不表示对端应用读取；普通 stream 不跨重连自动恢复。
- [ ] `M5-19` TUI 配对与信任视图支持请求 scope、输入一次性密码、查看/撤销 grant 和密码轮换。
- [ ] `M5-20` TUI Stream 视图支持文本/十六进制收发、半关闭、reset、窗口和背压状态。

### M5 测试与退出条件

- [ ] pairing-only 越权、错误密码、重放 nonce、伪造 grant、过期/撤销 grant 和 endpoint scope 收窄全部默认拒绝。
- [ ] 在每种队列满载下 control cancel/window/close 仍可发送；文件或事件流量不能饿死 control。
- [ ] frame/stream parser fuzz 覆盖截断、重复、乱序 offset、窗口溢出、未知必需 frame 和跨 session epoch 迟到数据。
- [ ] 所有队列在持续过载测试中保持配置上限，RSS 无持续线性增长，drop/reject/timeout 与统计一致。
- [ ] 已授权设备重连无需再次输入密码；被撤销设备持有旧 grant 也无法恢复权限。

---

## 9. M6：消息与 Unary RPC

### 9.1 消息服务

- [ ] `M6-01` 定义并实现 `MessageEnvelope`、类型/schema version、TTL、headers、payload 和 delivery mode 限制。
- [ ] `M6-02` 实现 `best_effort`：进入有界 transport 队列即完成，断线/过载语义明确。
- [ ] `M6-03` 实现 `peer_acked`：对端协议层基本校验后 ACK，不宣称 handler 已执行或数据已持久化。
- [ ] `M6-04` 实现按 message ID 的有界 TTL 去重缓存，记录 duplicate、expiry 和容量耗尽。
- [ ] `M6-05` 每个 message handler 检查 `message.send` scope，并通过 executor 普通任务派发；保存 future 并处理异常/拒绝。
- [ ] `M6-06` 目标离线立即返回 `peer_offline`，v1 不创建本地或 relay 离线队列。

### 9.2 Unary RPC

- [ ] `M6-07` 实现 service registry、method descriptor、schema version 和每 method scope/policy。
- [ ] `M6-08` 实现 request/response/cancel frame、相对 deadline、metadata、payload 和架构规定的 RPC status code。
- [ ] `M6-09` handler 通过有界 executor 提交；admission 拒绝或并发超限返回 `resource_exhausted`，执行异常映射为安全 `internal`。
- [ ] `M6-10` handler 接收协作取消信号；deadline 到期不假装强杀运行中 C++ 代码，迟到结果不进入已结束 request。
- [ ] `M6-11` 实现 session 内近期 request ID 结果缓存，提供配置化 at-most-once 窗口并限制内存。
- [ ] `M6-12` 连接中断时非幂等请求返回 `outcome_unknown`，绝不自动重试；仅显式幂等且 deadline 允许时执行策略化重试。
- [ ] `M6-13` v1 此阶段只开放 unary RPC；streaming API 保持未实现并返回 `unimplemented`，不交付半成品语义。

### 9.3 TUI 与文档

- [ ] `M6-14` TUI 消息视图支持 typed payload、TTL、delivery mode、ACK 和结构化失败。
- [ ] `M6-15` TUI RPC 视图支持 descriptor/raw payload、deadline、取消、状态和结果；无 descriptor 时不假定 JSON 可用。
- [ ] `M6-16` 编写消息/RPC API 示例，明确 admission、completion、ACK、handler success 和 `outcome_unknown` 的差异。

### M6 测试与 Service MVP 退出条件

- [ ] 覆盖 ACK 丢失、重复 message、TTL 到期、handler 抛异常、executor 满载、deadline/cancel 竞争和迟到响应。
- [ ] 非幂等 RPC 在请求已发出后断线稳定返回 `outcome_unknown`；测试证明库未偷偷执行第二次。
- [ ] 未授权 method、未知 service/method、schema 不兼容和超大 payload 在 handler 前被拒绝。
- [ ] direct 与 TURN 两条路径使用同一消息/RPC 测试集，业务代码不按 path 分支。
- [ ] TUI 通过公共 API 完成配对、消息和 RPC 端到端流程，无私有协议捷径。

---

## 10. M7：远程事件与文件传输

### 10.1 远程事件

- [ ] `M7-01` 实现精确 topic 和受控前缀匹配、publisher sequence、event ID、schema version、timestamp、QoS 和 payload。
- [ ] `M7-02` 实现 `best_effort_latest`，每订阅者只保留最新值并暴露 overwrite/stale/lag。
- [ ] `M7-03` 实现 `reliable_live`，只承诺当前连接内可靠，不补发断线历史。
- [ ] `M7-04` 每个远程订阅者有独立有界队列和 scope；慢订阅者不阻塞发布者或其他订阅者。
- [ ] `M7-05` 实现本地 `executor::comm::Topic<T>` 到远程事件的显式 bridge，类型和命名上区分本地 fan-out 与网络协议。
- [ ] `M7-06` 配置单设备远程订阅者/连接上限；超限明确拒绝，不把 relay 扩展为业务 Broker。
- [ ] `M7-07` TUI 事件视图支持 topic 浏览、订阅/取消、测试发布和 sequence/drop/lag 展示。

### 10.2 文件协议与安全写入

- [ ] `M7-08` 实现 file manifest、transfer ID、逻辑文件名、大小、BLAKE3、协商块大小和 metadata。
- [ ] `M7-09` 接收端在收数据前执行 `file.push/pull:<root>` scope、root mapping、单文件/总空间/并发/用户配额检查。
- [ ] `M7-10` 拒绝绝对路径、`..`、NUL、Windows device name、越界 symlink 和目录穿越；使用抗 symlink race 的平台文件 API。
- [ ] `M7-11` 实现临时文件、受限权限、块 offset/校验、bitmap 或连续 offset、整体 BLAKE3、flush/fsync 和原子 rename。
- [ ] `M7-12` 文件读写由 executor-managed Blocking I/O worker 管理，哈希等有限 CPU 工作通过普通 executor task；结果/failure 均有明确完成边界。
- [ ] `M7-13` 实现暂停、取消、断线持久化和按 transfer ID 恢复；旧 session frame 不能污染恢复后的 transfer。
- [ ] `M7-14` 实现有界发送窗口和限速，使 control/Shell/RPC 预算不被文件占满。
- [ ] `M7-15` 可选 zstd 只有在 manifest 明示且限制解压后大小时启用；默认关闭。
- [ ] `M7-16` TUI 文件视图展示逻辑 root、push/pull、进度、吞吐、暂停、取消、恢复和失败，不伪装远端绝对文件系统。

### M7 测试与退出条件

- [ ] event 慢订阅者、keep-latest 覆盖、reliable-live 断线和大规模 fan-out 上限的行为与统计一致。
- [ ] 在任意块边界、manifest 后、fsync 前和 rename 前强制断开/终止，恢复后文件 BLAKE3 正确且无越界写入。
- [ ] 覆盖磁盘满、配额竞争、hash 错误、重复块、恶意块长度、symlink race 和 Windows 特殊路径。
- [ ] 文件占满链路时 control/RPC 保持可用，调度 benchmark 达到 M1 冻结的延迟预算。
- [ ] direct/relay 路径均能完成事件和文件测试；relay/TURN 无法恢复文件明文。

---

## 11. M8：Remote Shell

### 11.1 服务端 Shell

- [ ] `M8-01` 定义 `ShellProfile`：固定程序、OS 用户、工作目录、环境 allowlist、资源、空闲和绝对时限；默认配置无 profile。
- [ ] `M8-02` 实现独立 scope `shell.open:<profile>`、本地 `ShellAuthorizer` 和并发会话限制，请求方不能覆盖 executable 或任意环境变量。
- [ ] `M8-03` 实现 `OPEN/STDIN/OUTPUT/RESIZE/SIGNAL/EOF/EXIT/ERROR/CLOSE`，明确 PTY 合流 stdout/stderr 的语义。
- [ ] `M8-04` Linux 使用受控 PTY/进程组，Windows 使用 ConPTY/job object；子进程 wait 与阻塞 I/O 纳入 executor worker 生命周期。
- [ ] `M8-05` 实现合作取消 -> TERM/受控信号 -> 超时后终止进程树的升级策略，断线默认终止。
- [ ] `M8-06` 实现输出速率/缓冲上限、空闲/绝对时限和资源约束；control/exit 不得被 stdout 洪泛饿死。
- [ ] `M8-07` 审计只记录发起设备、profile、时间、退出码和字节数，默认不记录终端原始内容。

### 11.2 TUI 安全终端

- [ ] `M8-08` 选用经过验证的 VT parser/terminal widget，记录版本和安全维护状态；不得把远端 bytes 直接写宿主终端。
- [ ] `M8-09` 限制 OSC、剪贴板、标题修改、超长/未知 escape sequence；不支持的控制序列拒绝或安全降级显示。
- [ ] `M8-10` 实现 profile 选择、交互输入、resize、signal、EOF、exit status 和显式关闭。
- [ ] `M8-11` TUI 退出/网络断开时按 profile 策略关闭 Shell，并等待 executor-managed operation 收敛。

### M8 安全测试与退出条件

- [ ] 覆盖未授权/过期 grant、任意 executable/env 注入、输出洪泛、输入背压、resize storm、signal 竞争和断线进程树回收。
- [ ] fuzz VT parser 和 Shell frame；恶意 OSC/escape 不触达宿主剪贴板、标题、文件或命令执行。
- [ ] Linux PTY 与 Windows ConPTY 生命周期测试通过，无僵尸进程、遗留 job 或 executor worker。
- [ ] 文件持续传输时 Shell 交互延迟满足冻结预算；退出和取消 control 帧始终有保留容量。
- [ ] 独立安全评审签字后才允许生产构建启用 Shell；否则 v1 保持编译存在但配置默认禁用。

---

## 12. M9：生产加固与 v1 发布

### 12.1 可观测性与运维

- [ ] `M9-01` 设备端导出架构第 13.2 节全部 LAN/relay/协议指标，并与 executor failure/status、comm stats 建立明确关联字段。
- [ ] `M9-02` relay 导出 Prometheus 指标、结构化日志、有限审计和可选 trace correlation；高频成功事件采样。
- [ ] `M9-03` 为 registration、pairing、connection、session、operation 和 transfer 建立不含机密的 correlation ID。
- [ ] `M9-04` 定义 SLO dashboard 与告警：multicast/listener readiness、presence/handshake reject、登录失败、租约续期、直连率、TURN allocation、pairing 猜测、队列拒绝、RPC overload、文件 hash 和 worker failure。
- [ ] `M9-05` 编写运维 runbook：证书/credential 轮换、设备吊销、relay/coturn 重启、数据库备份恢复、磁盘满、过载和版本回滚。

### 12.2 可靠性、兼容性与性能

- [ ] `M9-06` 完成 LAN/NAT 矩阵：same-bridge multicast、multicast blocked、multi-NIC/interface change、full-cone、restricted、port-restricted、symmetric、hairpin、CGNAT、IPv6-only 和 UDP blocked。
- [ ] `M9-07` 在 Linux/Windows 双向组合验证 LAN-only、relay-signaled direct、TURN/UDP、TURN/TCP/TLS、Windows firewall/network profile、文件权限/命名和 PTY/ConPTY。
- [ ] `M9-08` 完成 relay 重启、coturn 重启、网络切换、credential 过期、磁盘满、慢消费者和任意关闭点故障注入。
- [ ] `M9-09` 执行 24/72 小时长稳、反复发现/过期/建连/断连和容量过载测试，证明内存、fd/handle、worker、session、endpoint directory 和 TTL/replay cache 有界。
- [ ] `M9-10` 基准消息 latency、并发 RPC、事件 fan-out、单/多文件吞吐、Shell 竞争延迟、relay 内存和带宽。
- [ ] `M9-11` 基于结果重新冻结默认容量、水位、timeout 和重试参数；默认值必须有测量依据和硬上限。
- [ ] `M9-12` 完成 schema N-1/N 兼容、rolling relay upgrade 和新旧设备互通；不兼容行为必须在握手期拒绝。

### 12.3 安全与发布工程

- [ ] `M9-13` 扩展 fuzz 持续时间，覆盖所有 parser、状态机、ProfileStore migration 和 VT；保存最小化 regression corpus。
- [ ] `M9-14` 完成 secret scan、dependency vulnerability scan、SBOM、许可证、编译 hardening 和发布制品签名。
- [ ] `M9-15` 执行安全回归：multicast 洪泛/伪造/重放、LAN TLS MITM/slowloris、密码猜测/泄漏、grant/fingerprint/endpoint 伪造、降级、越权 method/topic、路径穿越、relay/TURN 放大。
- [ ] `M9-16` 编写安装、配置、部署、升级、备份、故障排查和 API 文档；示例必须从已编译源码嵌入或同步测试。
- [ ] `M9-17` 打包 client libraries、relay、TUI、coturn 示例配置与符号/许可证，验证干净机器安装和卸载。
- [ ] `M9-18` 形成 v1 release checklist，记录测试 commit、依赖 commit、协议版本、已知限制和回滚方案。

### M9/v1 最终验收

- [ ] 同区域正常网络登记 P95 < 2 秒，可打洞直连 P95 < 3 秒，TURN fallback P95 < 5 秒。
- [ ] 无 relay/STUN/TURN 的三设备测试 LAN 能自主发现、认证和建立 host-candidate DataChannel；未知/已信任 peer 分别进入 PairingRestricted/Authorized。
- [ ] TUI 本地初始化后，同 OS 用户的库应用可复用 profile 运行 LAN-only；存在 enrollment 时可无人工登录 relay，多 endpoint 同时在线且路由准确。
- [ ] 未信任设备只能进入 pairing-only，错误密码不触达业务 handler，正确密码只授予策略交集内 scope。
- [ ] LAN-only、relay-signaled direct 和 TURN 三条路径均通过消息、RPC、事件、ByteStream、文件和启用后的 Shell 端到端测试。
- [ ] 所有发送/接收/任务/诊断队列在压力下保持配置上限，无持续内存增长或静默消息损失。
- [ ] 文件可从任意已确认块恢复并通过最终 BLAKE3；非幂等 RPC 断线返回 `outcome_unknown`。
- [ ] Shell 未授权、文件越界、超额资源、协议降级、伪造签名和重放全部默认拒绝。
- [ ] relay 数据库、日志、WSS 终止点和 TURN 抓包均不能恢复授权密码、verifier、私钥或业务明文。
- [ ] TUI 仅通过 Heyaki 公共 API 覆盖全部正式能力；高频事件与窄终端下仍保持有界刷新和可用布局。
- [ ] Linux/Windows 发布矩阵、sanitizer、fuzz、长稳、故障注入、兼容性和安全评审全部通过或有明确阻断结论。

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
