# M3B：Relay 控制面

> - 状态：已完成，2026-08-16 关闭
> - 所属计划：[Heyaki MVP 至 v1 实施 TODO 计划](heyaki-implementation-plan.md)
> - 前置：M2 | 建议发布点：Relay control-plane alpha

M3A 与 M3B 都依赖 M2，可并行实施。M3B 扩展广域 presence、NAT fallback 和集中运维；两条
路径必须收敛到同一 `EndpointDirectory`、`SignalingRoute` 与签名信令状态机，禁止各自复制
会话和授权逻辑。

## 任务清单

### Relay 控制面

- [x] `M3B-01` 实现 `heyaki-relay` TLS 1.3/WSS 服务骨架、健康检查、配置加载和有界 graceful shutdown。
- [x] `M3B-02` 实现 SQLite 表 `devices`、`bootstrap_tokens`、`device_audit` 及迁移；在线 presence 和 pending signaling 仅保存在有界 TTL 内存结构。
- [x] `M3B-03` 实现 bootstrap token 哈希、tenant 绑定、过期、使用次数和竞争消费事务。
- [x] `M3B-04` 实现 enrollment challenge-response，验证公钥派生 `DeviceId`、签名、token、`EndpointId` 和最小 capability。
- [x] `M3B-05` 实现设备吊销、enrollment generation 与审计；吊销后拒绝新登录，现有连接行为由配置明确。
- [x] `M3B-06` 实现自动登录 challenge-response，不要求 bootstrap token 或授权密码，但每次校验随机 challenge、generation 和状态。
- [x] `M3B-07` 实现 `(DeviceId, EndpointId)` 租约、心跳、到期、同设备多 endpoint 和同租户在线查询。
- [x] `M3B-08` 对 endpoint record/service manifest 验证设备签名、大小和字段上限，只暴露租户策略允许的最小信息。
- [x] `M3B-09` 为 enrollment/login/query/heartbeat 设置连接、请求、tenant 和 IP 级速率限制及明确拒绝指标。

### TURN credential 与部署

- [x] `M3B-10` 固定 coturn 配置与容器/包版本，启用 TURN REST API 风格 HMAC 临时 credential。
- [x] `M3B-11` credential 用户名绑定到期时间、设备和租户；密钥支持轮换，日志不得记录完整 credential。
- [x] `M3B-12` 配置 allocation、带宽、并发、relay 端口范围、禁止内网管理 peer 地址、TLS certificate 和 advertised address。
- [x] `M3B-13` 建立本地一键测试拓扑：relay + coturn + 两个隔离 client namespace，不把 coturn 嵌入 relay 进程。

### 客户端 enrollment 与 TUI

- [x] `M3B-14` 实现设备端 WSS client、证书/主机名校验、可选 relay pin 和安全错误分类。
- [x] `M3B-15` 实现可选 relay enrollment API：只使用现有本地身份/endpoint，提交成功 record 后原子写 ProfileStore，不重新生成身份或 verifier。
- [x] `M3B-16` 只有 enrollment 持久化成功才报告完成；失败时撤销或标记服务端半完成 enrollment 以便安全重试。
- [x] `M3B-17` 实现自动登录、15 秒默认心跳、3 次丢失离线和带 jitter 的有界指数退避；安全错误停止自动重试，relay 失败不关闭 LAN readiness。
- [x] `M3B-18` TUI onboarding 将“创建本地身份”和“连接 Relay”分成明确步骤，密码控件隐藏内容且不进入 history/log。
- [x] `M3B-19` TUI Relay 视图展示 enrollment、租约、重连、endpoint 来源和需要人工处理的状态；本机/LAN 视图在 relay 不可用时仍可操作。
- [x] `M3B-20` TUI renderer 只消费有界 `UiEvent` 通道；高频状态使用 latest-only 聚合，关闭时先取消 operation 再释放 profile。

## 测试与退出条件

- [x] 覆盖 token 过期/重复消费、伪造 DeviceId、错误签名、吊销 generation、重复 endpoint、租约到期和 relay 重启。
- [x] 抓取 relay DB、日志和 WSS 流量，确认不存在授权密码明文、Argon2id verifier 或私钥。
- [x] TUI 可在既有本地 profile 上完成 enrollment；重启 TUI 与独立库 demo 后均无人工输入自动登录。
- [x] TUI 与库 demo 使用同一 `DeviceId`、不同 `EndpointId` 同时在线，LAN/relay directory 合并后不混淆 endpoint。
- [x] 正常网络下登记 P95 小于 2 秒；不达标时保留测量、瓶颈和后续基线，不通过退出门禁。

## 实施进度轮总结

### 第1轮（2026-08-16）

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

### 第2轮（2026-08-16）

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

### 第3轮（2026-08-16）

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

### 第4轮（2026-08-16）

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

### 第5轮（2026-08-16）

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

### 第6轮（2026-08-16）

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

### 第7轮（2026-08-16）

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

### 第8轮（2026-08-16）

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

### 第9轮（2026-08-16）

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

### 第10轮（2026-08-16）

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

### 第11轮（2026-08-16）

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

### 第12轮（2026-08-16）

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

### 第13轮（2026-08-16）

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

### 第14轮（2026-08-16）

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

### 第15轮（2026-08-16）

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
