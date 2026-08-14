# Heyaki MVP 至 v1 实施 TODO 计划

> - 状态：M1 首轮评审问题已整改并通过本地门禁；待更新后的 GitHub CI（含 Windows Debug/Release）与独立复审后准入 M2
> - 日期：2026-08-15
> - 设计依据：[Heyaki 设备通信基础设施设计](../design/heyaki-architecture.md)
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
- [ ] `SCOPE-03` 确认 MVP 使用单 relay region、单控制实例、SQLite 和一个 coturn 实例，不提前引入 Redis/NATS/PostgreSQL。
- [ ] `SCOPE-04` 确认 v1 不包含离线消息、持久事件、目录同步、多跳转发、无损路径迁移、detached Shell 和本机 agent。
- [ ] `SCOPE-05` 将 Linux x86_64 作为 MVP 开发基线，将 Linux/Windows x64 双平台作为 v1 发布门禁。
- [ ] `SCOPE-06` 将 Remote Shell 设为默认关闭的独立安全里程碑；Shell 未完成不得阻塞消息、RPC、事件和文件版本交付。

### 1.2 不可破坏的架构约束

- [ ] `RULE-01` 公共业务 API 只依赖 `PeerSession`/`Channel` 等 transport-neutral 契约，不暴露 libdatachannel 类型。
- [ ] `RULE-02` 设备身份始终使用完整 `DeviceId`；`ShortDeviceId` 只用于显示，不进入协议比较、主键或 ACL。
- [ ] `RULE-03` transport connected 与 authorized 分开建模；`PairingRestricted` 状态不得创建任何业务通道。
- [ ] `RULE-04` 所有队列、窗口、缓存、并发 operation 和诊断历史都有容量上限，不以无界缓存掩盖背压。
- [ ] `RULE-05` 可靠、确认、持久化、幂等和自动重试分别定义，禁止把 DataChannel 可靠传输描述为业务已处理。
- [ ] `RULE-06` relay、TURN 日志和存储中不得出现授权密码、Argon2id verifier、TrustStore 或业务明文。
- [ ] `RULE-07` 未经单独批准不得修改 pinned executor；若发现能力缺口，按仓库 `AGENTS.md` 的五项要求先报告并等待决策。

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

---

## 2. 里程碑、依赖与发布点

| 里程碑 | 目标 | 前置 | 建议发布点 |
| --- | --- | --- | --- |
| M0 | 仓库、构建、CI 与决策基线 | 无 | 内部工程基线 |
| M1 | 协议、安全和公共类型冻结 | M0 | 协议评审基线 |
| M2 | Executor/Asio runtime、ProfileStore 与身份 | M1 | 本地库 alpha |
| M3 | Relay 登记、自动登录、租约与 TUI onboarding | M2 | 控制面 alpha |
| M4 | 签名信令、WebRTC、ICE/TURN 和最小会话 | M3 | v0.1 Connectivity MVP |
| M5 | 配对、TrustGrant、通道调度和 ByteStream | M4 | 会话安全 beta |
| M6 | 消息、unary RPC 与对应 TUI | M5 | v0.2 Service MVP |
| M7 | 远程事件、文件传输与对应 TUI | M6 | v0.3 Data beta |
| M8 | Remote Shell 与安全终端 UI | M7 | v0.4 Shell beta |
| M9 | 生产加固、跨平台、兼容性与发布 | M8 | v1.0 |

关键路径为 `M0 -> M1 -> M2 -> M3 -> M4 -> M5 -> M6 -> M7 -> M8 -> M9`。TUI 不作为
最后一次性补做的界面工程，而是在 M3、M4、M6、M7、M8 中按公共 API 逐步交付，以持续充当
端到端验收客户端。

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
- [ ] golden vectors 在 Linux/Windows、Debug/Release 上得到相同字节；协议文档与 schema 版本一致。
- [x] 所有 parser 在分配 payload 前检查长度，fuzz smoke 无 crash、越界、超限分配或无限循环。
- [ ] threat model、安全默认值和 wire protocol 通过独立评审后再进入 M2；后续不兼容修改必须显式提升协议 major。

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
该 CI 与独立协议/安全复审完成前，保持对应两项退出条件未勾选，不准入 M2。

---

## 5. M2：Runtime、身份与 ProfileStore

### 5.1 Executor/Asio 集成

- [ ] `M2-01` 新增 `docs/design/concurrency-and-shutdown.md`，逐项列出 runtime owner、执行上下文、通信组件、容量、完成边界和关闭顺序。
- [ ] `M2-02` 实现进程级 runtime 装配：初始化 executor、注册 Blocking I/O worker、启动 Asio、安装 failure/comm 诊断桥接。
- [ ] `M2-03` 为 Node 与 relay 分别明确 executor 所有权模式；库默认借用调用方配置的 executor，独立 app 在进程边界拥有 executor。
- [ ] `M2-04` 用 Asio strand 串行化 Node/PeerSession 状态；外部 callback 通过有界 `MpscChannel` 进入，不跨线程共享可变 session state。
- [ ] `M2-05` 为低频状态快照选择 `DoubleBuffer`，为可覆盖指标选择 `LatestMailbox`；记录 sequence、overwrite、stale 和 lag。
- [ ] `M2-06` 为 executor 提交封装 operation ID 和安全上下文，但不复制其 task health 统计；任务异常仍由 future/failure event 观察。
- [ ] `M2-07` 实现固定关闭序列：停止 admission -> 停止生产者/重连定时器 -> 取消服务 -> 关闭 peer -> 注销 relay -> 停 Asio -> 有界等待任务/worker -> 刷新持久状态 -> owner shutdown executor。
- [ ] `M2-08` 明确借用 executor 的 Node 只 drain 自己的 operation，不得关闭共享 executor；拥有者销毁依赖数据必须晚于任务收敛。
- [ ] `M2-09` 所有 drain 和 shutdown 等待都有预算、超时状态与后续动作，不能依赖无限等待或 sleep 判断完成。

### 5.2 身份与密码材料

- [ ] `M2-10` 使用 libsodium 初始化安全随机、Ed25519、SHA-256、Argon2id 和常量时间比较；禁止自研密码原语。
- [ ] `M2-11` 实现首次身份创建、已有身份加载、公私钥匹配检查和 `DeviceId` 派生验证。
- [ ] `M2-12` 抽象 OS secret backend：Windows DPAPI/credential facilities、Linux 可用 key store；文件回退必须加密并检查权限。
- [ ] `M2-13` 实现授权密码 verifier 创建、验证、参数校准、格式版本升级和敏感临时 buffer 清理。
- [ ] `M2-14` 定义密钥不可用、secret backend 降级、权限过宽和损坏材料的稳定错误，禁止静默生成新身份覆盖旧档案。

### 5.3 ProfileStore 与 TrustStore

- [ ] `M2-15` 冻结 ProfileStore SQLite schema：identity handle、relay enrollment、password verifier、TrustStore、grant、endpoint record、file resume、preferences。
- [ ] `M2-16` 实现 `open_default()`、显式 profile 打开、创建、重命名和枚举；不存在时返回 `not_registered`，不隐式创建另一个身份。
- [ ] `M2-17` 实现 schema version、向前迁移、事务回滚、损坏检测和可恢复备份；每个 migration 有 fixture 测试。
- [ ] `M2-18` 实现同一 OS 主体的多进程文件锁/SQLite busy 策略、临时文件、flush 和原子替换；锁超时返回 `profile_locked`。
- [ ] `M2-19` 按 `application_id` 创建并持久化随机 `EndpointId`，验证同 profile 多应用得到同 `DeviceId`、不同 endpoint。
- [ ] `M2-20` 实现 TrustGrant/TrustStore 的写入、查询、撤销、过期和 password generation 索引，目标本地状态始终为最终裁决。
- [ ] `M2-21` 对 profile 导出、删除和 relay 吊销建立不同 API；删除操作在 TUI 中不得把本地删除伪装成远端吊销。

### M2 测试与退出条件

- [ ] executor overload、提交拒绝、任务异常、callback 异常、关闭期间提交和 drain timeout 均可通过既定事实源观察。
- [ ] ASAN/TSAN 覆盖 callback bridge、Node 状态转换、并发 profile 打开和 shutdown，无悬空 buffer 或数据竞争。
- [ ] 进程在每个 ProfileStore 事务点被强制终止后，重启得到旧版本或完整新版本，不出现半写状态。
- [ ] 私钥不可用、profile 权限过宽、schema 过新、锁超时和磁盘满均返回稳定错误且不破坏原数据。
- [ ] M2 demo 能创建 profile、重启后保持相同 `DeviceId`，两个 application ID 获得稳定且不同的 `EndpointId`。

---

## 6. M3：Relay 登记、自动登录与在线租约

### 6.1 Relay 控制面

- [ ] `M3-01` 实现 `heyaki-relay` TLS 1.3/WSS 服务骨架、健康检查、配置加载和有界 graceful shutdown。
- [ ] `M3-02` 实现 SQLite 表 `devices`、`bootstrap_tokens`、`device_audit` 及迁移；在线 presence 和 pending signaling 仅保存在有界 TTL 内存结构。
- [ ] `M3-03` 实现 bootstrap token 哈希、tenant 绑定、过期、使用次数和竞争消费事务。
- [ ] `M3-04` 实现 enrollment challenge-response，验证公钥派生 `DeviceId`、签名、token、`EndpointId` 和最小 capability。
- [ ] `M3-05` 实现设备吊销、enrollment generation 与审计；吊销后拒绝新登录，现有连接行为由配置明确。
- [ ] `M3-06` 实现自动登录 challenge-response，不要求 bootstrap token 或授权密码，但每次校验随机 challenge、generation 和状态。
- [ ] `M3-07` 实现 `(DeviceId, EndpointId)` 租约、心跳、到期、同设备多 endpoint 和同租户在线查询。
- [ ] `M3-08` 对 endpoint record/service manifest 验证设备签名、大小和字段上限，只暴露租户策略允许的最小信息。
- [ ] `M3-09` 为 enrollment/login/query/heartbeat 设置连接、请求、tenant 和 IP 级速率限制及明确拒绝指标。

### 6.2 TURN credential 与部署

- [ ] `M3-10` 固定 coturn 配置与容器/包版本，启用 TURN REST API 风格 HMAC 临时 credential。
- [ ] `M3-11` credential 用户名绑定到期时间、设备和租户；密钥支持轮换，日志不得记录完整 credential。
- [ ] `M3-12` 配置 allocation、带宽、并发、relay 端口范围、禁止内网管理 peer 地址、TLS certificate 和 advertised address。
- [ ] `M3-13` 建立本地一键测试拓扑：relay + coturn + 两个隔离 client namespace，不把 coturn 嵌入 relay 进程。

### 6.3 客户端 enrollment 与 TUI onboarding

- [ ] `M3-14` 实现设备端 WSS client、证书/主机名校验、可选 relay pin 和安全错误分类。
- [ ] `M3-15` 实现首次登记 API：创建/加载身份、生成 verifier、提交 enrollment、收到 record 后原子写 ProfileStore。
- [ ] `M3-16` 只有 ProfileStore 持久化成功才报告登记完成；失败时撤销或标记服务端半完成 enrollment 以便安全重试。
- [ ] `M3-17` 实现自动登录、15 秒默认心跳、3 次丢失离线和带 jitter 的有界指数退避；安全错误停止自动重试。
- [ ] `M3-18` 建立 `heyaki-tui` FTXUI shell、profile selector 和 onboarding 向导，密码控件隐藏内容且不进入 history/log。
- [ ] `M3-19` TUI Relay 与本机视图展示 profile、设备/endpoint、租约、重连、稳定错误和需要人工处理的状态。
- [ ] `M3-20` TUI renderer 只消费有界 `UiEvent` 通道；高频状态使用 latest-only 聚合，关闭时先取消 operation 再释放 profile。

### M3 测试与退出条件

- [ ] 覆盖 token 过期/重复消费、伪造 DeviceId、错误签名、吊销 generation、重复 endpoint、租约到期和 relay 重启。
- [ ] 抓取 relay DB、日志和 WSS 流量，确认不存在授权密码明文、Argon2id verifier 或私钥。
- [ ] TUI 可完成首次登记；重启 TUI 与独立库 demo 后均无人工输入自动登录。
- [ ] TUI 与库 demo 使用同一 `DeviceId`、不同 `EndpointId` 同时在线，查询和路由不混淆 endpoint。
- [ ] 正常网络下登记 P95 小于 2 秒；不达标时保留测量、瓶颈和后续基线，不通过退出门禁。

---

## 7. M4：签名信令、WebRTC 与最小会话

### 7.1 信令与 Transport SPI

- [ ] `M4-01` 实现内部 `TransportSession`/`TransportChannel` SPI、`ChannelOptions`、`PathInfo` 和 close reason，不暴露为稳定第三方插件 ABI。
- [ ] `M4-02` 实现 relay `CONNECT_REQUEST/ACCEPT/DENY` 与 trickle ICE 转发，所有 pending 项都有 request ID、TTL、大小和速率上限。
- [ ] `M4-03` 实现 offer、answer、ICE ufrag、fingerprint、双方 ID、endpoint、nonce 和 expiry 的规范化签名与验签。
- [ ] `M4-04` 建立 replay cache，拒绝重复 request ID、nonce、过期对象和 session epoch 迟到信令。
- [ ] `M4-05` 未通过签名、公钥派生 ID 和 endpoint 验证时，不把 SDP/candidate 交给 transport。

### 7.2 WebRTC/ICE/TURN

- [ ] `M4-06` 实现 `WebRtcTransportSession`，包装 libdatachannel PeerConnection、DataChannel callback、错误和关闭状态。
- [ ] `M4-07` 配置 candidate 优先级：IPv6 host、LAN IPv4、srflx UDP、TURN/UDP、已验证的 TURN/TCP/TLS。
- [ ] `M4-08` 并行收集/检查 direct 与 relay candidate，relay 可提前分配但低优先级提名，禁止串行等待长直连超时后才开始 TURN。
- [ ] `M4-09` 实现 `path_info()`、selected candidate、RTT、buffered amount、ICE state 和 restart 事件观测。
- [ ] `M4-10` 实现网络接口变化的 ICE restart；association 丢失则建立新物理 session，不伪装为无损迁移。
- [ ] `M4-11` 映射 libdatachannel callback 到 executor-managed 有界通道；满载、关闭和投递失败都有错误/统计。
- [ ] `M4-12` 基于 `bufferedAmount` high/low water callback 暂停/恢复发送，验证底层背压能传回 API。

### 7.3 最小身份会话与诊断 UI

- [ ] `M4-13` 实现 `SESSION_HELLO`，在 fingerprint 已验证的 DataChannel 上绑定签名 signaling transcript、session ID/epoch、endpoint、能力摘要和签名。
- [ ] `M4-14` 实现最小状态机 `Idle -> Signaling -> Gathering -> Checking -> TransportConnected -> Authenticating -> Closed`，每次转换记录 reason/timestamp。
- [ ] `M4-15` 在授权功能尚未实现时，成功认证的测试设备只开放内部 control ping，不开放通用业务通道。
- [ ] `M4-16` TUI 设备/诊断视图展示在线 endpoint、建连阶段、direct/relayed path、candidate、RTT 和结构化失败。
- [ ] `M4-17` 增加测试专用策略强制 direct、TURN/UDP、TURN/TCP/TLS 或禁止某类 candidate，避免公网偶测。

### M4 测试与 Connectivity MVP 退出条件

- [ ] 覆盖 direct、强制 TURN、对称 NAT、hairpin、IPv6-only、UDP blocked、高延迟、丢包、重复 candidate 和 relay 中途重启。
- [ ] 伪造/替换 fingerprint、offer、endpoint、nonce 或 expiry 时双方都拒绝，relay 无法完成 MITM。
- [ ] 可打洞环境建连 P95 小于 3 秒；直连失败 TURN fallback P95 小于 5 秒。
- [ ] 100% 失败/取消/关闭路径最终进入终态，executor worker、Asio work、DataChannel 和 replay cache 无泄漏。
- [ ] TUI 可以从在线列表选择正确 endpoint 建立认证后的最小会话，并准确显示 direct 或 relay 路径。

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
- [ ] `M5-08` pairing 发起方必须先以已登记身份登录 relay；匿名来源不进入 pairing channel。
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

- [ ] `M9-01` 设备端导出架构第 13.2 节全部协议指标，并与 executor failure/status、comm stats 建立明确关联字段。
- [ ] `M9-02` relay 导出 Prometheus 指标、结构化日志、有限审计和可选 trace correlation；高频成功事件采样。
- [ ] `M9-03` 为 registration、pairing、connection、session、operation 和 transfer 建立不含机密的 correlation ID。
- [ ] `M9-04` 定义 SLO dashboard 与告警：登录失败、租约续期、直连率、TURN allocation、pairing 猜测、队列拒绝、RPC overload、文件 hash 和 worker failure。
- [ ] `M9-05` 编写运维 runbook：证书/credential 轮换、设备吊销、relay/coturn 重启、数据库备份恢复、磁盘满、过载和版本回滚。

### 12.2 可靠性、兼容性与性能

- [ ] `M9-06` 完成 NAT 矩阵：full-cone、restricted、port-restricted、symmetric、hairpin、CGNAT、IPv6-only 和 UDP blocked。
- [ ] `M9-07` 在 Linux/Windows 双向组合验证 direct、TURN/UDP、TURN/TCP/TLS、文件权限/命名和 PTY/ConPTY。
- [ ] `M9-08` 完成 relay 重启、coturn 重启、网络切换、credential 过期、磁盘满、慢消费者和任意关闭点故障注入。
- [ ] `M9-09` 执行 24/72 小时长稳、反复建连/断连和容量过载测试，证明内存、fd/handle、worker、session 和 TTL cache 有界。
- [ ] `M9-10` 基准消息 latency、并发 RPC、事件 fan-out、单/多文件吞吐、Shell 竞争延迟、relay 内存和带宽。
- [ ] `M9-11` 基于结果重新冻结默认容量、水位、timeout 和重试参数；默认值必须有测量依据和硬上限。
- [ ] `M9-12` 完成 schema N-1/N 兼容、rolling relay upgrade 和新旧设备互通；不兼容行为必须在握手期拒绝。

### 12.3 安全与发布工程

- [ ] `M9-13` 扩展 fuzz 持续时间，覆盖所有 parser、状态机、ProfileStore migration 和 VT；保存最小化 regression corpus。
- [ ] `M9-14` 完成 secret scan、dependency vulnerability scan、SBOM、许可证、编译 hardening 和发布制品签名。
- [ ] `M9-15` 执行安全回归：密码猜测/泄漏、grant/fingerprint/endpoint 伪造、重放、降级、越权 method/topic、路径穿越、relay/TURN 放大。
- [ ] `M9-16` 编写安装、配置、部署、升级、备份、故障排查和 API 文档；示例必须从已编译源码嵌入或同步测试。
- [ ] `M9-17` 打包 client libraries、relay、TUI、coturn 示例配置与符号/许可证，验证干净机器安装和卸载。
- [ ] `M9-18` 形成 v1 release checklist，记录测试 commit、依赖 commit、协议版本、已知限制和回滚方案。

### M9/v1 最终验收

- [ ] 同区域正常网络登记 P95 < 2 秒，可打洞直连 P95 < 3 秒，TURN fallback P95 < 5 秒。
- [ ] TUI 登记后，同 OS 用户的库应用可复用 profile 无人工登录；多 endpoint 同时在线且路由准确。
- [ ] 未信任设备只能进入 pairing-only，错误密码不触达业务 handler，正确密码只授予策略交集内 scope。
- [ ] direct/relay 两条路径均通过消息、RPC、事件、ByteStream、文件和启用后的 Shell 端到端测试。
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

---

## 14. 建议拆分与合并顺序

1. 先合入 M0 构建/CI 骨架和 M1 公共类型，不在同一 PR 中引入 WebRTC 或 UI。
2. M1 的 wire protocol、签名 canonicalization 和 threat model 先评审，再生成业务实现。
3. M2 分为 runtime、identity、ProfileStore 三组 PR；runtime shutdown 测试先于任何长生命周期网络工作。
4. M3 先交付 relay enrollment/login 协议与服务端，再交付客户端和 TUI onboarding。
5. M4 先合 Transport SPI/假 transport 测试，再接 libdatachannel、coturn 与网络矩阵。
6. M5 先完成 framing/调度，再完成 pairing/TrustGrant，最后开放 ByteStream；未授权状态始终默认关闭。
7. M6 的消息与 RPC 可分 PR，但共同复用会话、ACL、deadline、取消和 executor dispatch。
8. M7 先事件、再 ByteStream 上的文件协议和安全落盘；恢复协议通过故障注入后再开放 TUI push/pull。
9. M8 的 OS Shell backend、协议、VT UI 和安全评审分别提交；安全门禁未通过不启用生产配置。
10. M9 只做加固、兼容、测量和交付，不在发布冲刺中加入 QUIC、跨 region 或业务 Broker。

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
