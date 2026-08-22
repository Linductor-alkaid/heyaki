# M2：Runtime、身份与 ProfileStore

> - 状态：已完成，2026-08-15 正式准入 M3A/M3B
> - 所属计划：[Heyaki MVP 至 v1 实施 TODO 计划](heyaki-implementation-plan.md)
> - 前置：M1 | 建议发布点：本地库 alpha

## Executor/Asio 集成

- [x] `M2-01` 新增 `docs/design/concurrency-and-shutdown.md`，逐项列出 runtime owner、执行上下文、通信组件、容量、完成边界和关闭顺序。
- [x] `M2-02` 实现进程级 runtime 装配：初始化 executor、注册 Blocking I/O worker、启动 Asio、安装 failure/comm 诊断桥接。
- [x] `M2-03` 为 Node 与 relay 分别明确 executor 所有权模式；库默认借用调用方配置的 executor，独立 app 在进程边界拥有 executor。
- [x] `M2-04` 用 Asio strand 串行化 Node/PeerSession 状态；外部 callback 通过有界 `MpscChannel` 进入，不跨线程共享可变 session state。
- [x] `M2-05` 为低频状态快照选择 `DoubleBuffer`，为可覆盖指标选择 `LatestMailbox`；记录 sequence、overwrite、stale 和 lag。
- [x] `M2-06` 为 executor 提交封装 operation ID 和安全上下文，但不复制其 task health 统计；任务异常仍由 future/failure event 观察。
- [x] `M2-07` 实现固定关闭序列：停止 admission -> 停止生产者/重连定时器 -> 取消服务 -> 关闭 peer -> 注销 relay -> 停 Asio -> 有界等待任务/worker -> 刷新持久状态 -> owner shutdown executor。
- [x] `M2-08` 明确借用 executor 的 Node 只 drain 自己的 operation，不得关闭共享 executor；拥有者销毁依赖数据必须晚于任务收敛。
- [x] `M2-09` 所有 drain 和 shutdown 等待都有预算、超时状态与后续动作，不能依赖无限等待或 sleep 判断完成。

## 身份与密码材料

- [x] `M2-10` 使用 libsodium 初始化安全随机、Ed25519、SHA-256、Argon2id 和常量时间比较；禁止自研密码原语。
- [x] `M2-11` 实现首次身份创建、已有身份加载、公私钥匹配检查和 `DeviceId` 派生验证。
- [x] `M2-12` 抽象 OS secret backend：Windows DPAPI/credential facilities、Linux 可用 key store；文件回退必须加密并检查权限。
- [x] `M2-13` 实现授权密码 verifier 创建、验证、参数校准、格式版本升级和敏感临时 buffer 清理。
- [x] `M2-14` 定义密钥不可用、secret backend 降级、权限过宽和损坏材料的稳定错误，禁止静默生成新身份覆盖旧档案。

## ProfileStore 与 TrustStore

- [x] `M2-15` 冻结 ProfileStore SQLite schema：identity handle、relay enrollment、password verifier、TrustStore、grant、endpoint record、file resume、preferences。
- [x] `M2-16` 实现 `open_default()`、显式 profile 打开、创建、重命名和枚举；不存在时返回 `not_registered`，不隐式创建另一个身份。
- [x] `M2-17` 实现 schema version、向前迁移、事务回滚、损坏检测和可恢复备份；每个 migration 有 fixture 测试。
- [x] `M2-18` 实现同一 OS 主体的多进程文件锁/SQLite busy 策略、临时文件、flush 和原子替换；锁超时返回 `profile_locked`。
- [x] `M2-19` 按 `application_id` 创建并持久化随机 `EndpointId`，验证同 profile 多应用得到同 `DeviceId`、不同 endpoint。
- [x] `M2-20` 实现 TrustGrant/TrustStore 的写入、查询、撤销、过期和 password generation 索引，目标本地状态始终为最终裁决。
- [x] `M2-21` 对 profile 导出、删除和 relay 吊销建立不同 API；删除操作在 TUI 中不得把本地删除伪装成远端吊销。

## 测试与退出条件

- [x] executor overload、提交拒绝、任务异常、callback 异常、关闭期间提交和 drain timeout 均可通过既定事实源观察。
- [x] ASAN/TSAN 覆盖 callback bridge、Node 状态转换、并发 profile 打开和 shutdown，无悬空 buffer 或数据竞争。
- [x] 进程在每个 ProfileStore 事务点被强制终止后，重启得到旧版本或完整新版本，不出现半写状态。
- [x] 私钥不可用、profile 权限过宽、schema 过新、锁超时和磁盘满均返回稳定错误且不破坏原数据。
- [x] M2 demo 能创建 profile、重启后保持相同 `DeviceId`，两个 application ID 获得稳定且不同的 `EndpointId`。

## 验证记录

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
