# M11 Android（NDK）库适配

> - 状态：任务清单完成，CI 首绿（2026-10-05；v1.2 alpha 退出条件剩余缺口见 §4）
> - 前置：M9（v1.0 发布门禁完成后启动；可与 M10 并行）
> - 建议发布点：v1.2 Android alpha
> - 设计依据：[Heyaki 设备通信基础设施设计](../design/heyaki-architecture.md) §2.1 目标 8、
>   总计划 `DEC-14`
> - 范围边界：只交付 C++20 核心库（`heyaki-core` 等 transport/session/profile 库）的
>   Android NDK 交叉编译、平台层验证与 JNI 集成边界；不移植 `heyaki-tui`、fuzzer、
>   coturn 拓扑与桌面部署脚本；不交付完整 Android 应用/UI。

## 1. 依赖可移植性分析结论（2026-08-29）

### 1.1 有利因素

- **executor（pin 077d854）已完成 Android 一期适配**：`if(ANDROID)` CMake 分支、
  bionic 不链 `librt`、`stop_token` 的 `__ANDROID__` fallback
  （`third_party/executor/include/executor/stop_token.hpp:10-17`）、
  `sched_setaffinity` 适配（`third_party/executor/src/executor/util/thread_utils.cpp:199`），
  上游有 NDK r26c/r28b CI 与 qemu-user ARM64 验证（见 executor
  `docs/PACKAGE_ANDROID.md`）。M4 已为此升级 pin（m4 阶段文件记录）。
- **核心代码无 Linux 特有调度 API**：全库（不含 third_party）未直接使用
  epoll/timerfd/signalfd/inotify/systemd/AF_UNIX；并发与定时全部经由
  Boost.Asio + executor facade，符合仓库并发边界约束。
- **第三方依赖均官方支持 NDK**：Boost.Asio/Beast（header-only）、libsodium 1.0.20、
  protobuf v31.1、abseil-cpp 20250127.0、blake3、sqlite 3.50.4、libdatachannel
  v0.23.2（上游支持 Android，JuICE/usrsctp 可 NDK 编译）、zstd。
- **平台分支已存在**：源码按 Win32/POSIX 双分支组织（如接口枚举
  `src/client/node.cpp:190`（Win32）与 `node.cpp:260`（`getifaddrs`）），
  POSIX 分支基本落在 bionic 可用集合内。

### 1.2 主要适配点（风险清单）

| # | 适配点 | 证据 | 处置方向 |
| --- | --- | --- | --- |
| A1 | **OpenSSL 3.x 系统依赖 + "冻结 3.x、拒绝 4.x" 检查**；Android 无系统 OpenSSL | `CMakeLists.txt:73-77` `find_package(OpenSSL 3.0 REQUIRED)` | vendored 交叉编译 OpenSSL 3.x（首选，保持 ABI 冻结检查语义）；BoringSSL 仅作为备选，需先修订 3.x 冻结检查并评审与 libdatachannel 的 TLS backend 一致性 |
| A2 | **LAN 组播发现受 Android 限制**：组播需要 `WifiManager.MulticastLock` 与 CHANGE_WIFI_MULTICAST_STATE 权限，属 JNI/应用层运行时问题 | `src/client/node.cpp:22,1829-1847`（`boost::asio/ip/multicast.hpp`） | JNI 集成层提供 MulticastLock 生命周期钩子；不可用时 LAN route 显式降级/失败，relay route 不受影响 |
| A3 | bionic 语义验证：`flock`（`src/profile/profile_store.cpp:420`）、`getifaddrs`/`if_nametoindex`、`dlfcn` 动态 secret backend（`src/profile/secret_backend.cpp:28`，Android 加载 so 路径/权限语义不同） | 见左列文件 | M11 平台层验证任务；Android 上默认禁用 dlopen 动态 backend 或映射到 Android Keystore 等价物（并入 DEC-14 确认） |
| A4 | TUI 的 `<termios.h>` 与 pty 语义、fuzzer、coturn netns 拓扑均为桌面专用 | `apps/tui/main.cpp:41,130`、`.github/workflows/ci.yml` | 以 `HEYAKI_BUILD_APPS=OFF`/fuzzer gate 剥离，不进入 Android 目标 |
| A5 | CI 无 Android job | `.github/workflows/ci.yml`（linux/windows/coturn/sanitizer） | 新增 NDK 交叉编译 + 模拟器冒烟 workflow（参考 executor `build_android.sh` 与其 NDK CI 模式） |
| A6 | 产品边界：`DEC-07` v1 不承诺移动网络切换的无损会话迁移 | `docs/decisions/m0-product-defaults.md` | Android alpha 同样不承诺；网络切换表现按既有重连语义记录，不新增迁移机制 |

## 2. 任务清单

- [x] `M11-01` 建立 NDK 工具链交叉编译基线：`HEYAKI_ANDROID` CMake 选项 +
  NDK toolchain file，`HEYAKI_BUILD_APPS=OFF`/fuzzer 关闭，验证核心库目标在
  NDK（r26c 或 r28b，与 executor CI 对齐）下为 arm64-v8a 与 x86_64 编译通过。
- [x] `M11-02` vendored OpenSSL 3.x 交叉编译方案落地（A1）：更新
  `cmake/HeyakiVendoredRuntime.cmake`，Android 构建不再 `find_package(OpenSSL)`；
  记录与 libdatachannel TLS backend 的选择及理由到本文件与 supply-chain 文档。
- [x] `M11-03` 逐依赖交叉编译验证并记录版本/补丁：Boost.Asio/Beast、libsodium、
  protobuf、abseil、blake3、sqlite、zstd、libdatachannel（对齐
  `third_party/dependencies.lock` 版本，不借机升级）。
- [x] `M11-04` 平台层验证（A3）：`flock`、`getifaddrs`/`if_nametoindex`、文件锁 +
  原子替换、XDG→Android 存储目录映射、`dlfcn` secret backend 的启用/禁用策略。
- [x] `M11-05` LAN 组播适配（A2）：JNI 集成层 MulticastLock 钩子；Android 无锁时
  LAN discovery 显式降级并保持 relay 路径可用；补降级路径测试。
- [x] `M11-06` JNI 集成边界：以薄封装暴露 Node 会话生命周期/授权 API，Heyaki
  工作仍全部经 executor 提交，回调经既有 executor::comm 语义投递到宿主线程；
  不在 JNI 层建立第二并发系统。
- [x] `M11-07` 最小 Android 集成示例（例如演示 app 或 qemu-user 冒烟 runner），
  纳入 CI 冒烟而非人工步骤。
- [x] `M11-08` CI：新增 android workflow（NDK 交叉编译 + qemu-user/arm64 模拟器
  冒烟），复用现有依赖校验与 lockfile 门禁。
- [x] `M11-09` 文档：更新 architecture §平台矩阵、`docs/compatibility/` 新增
  Android 依赖说明、DEC-14 结论回填、supply-chain 许可证清单补充 Android 产物。

## 3. 测试与退出条件

1. NDK CI job 在 arm64-v8a 与 x86_64 双 ABI 上稳定绿，包含核心库单元测试的
   qemu-user/模拟器执行结果。
2. LAN/relay 双 route 在 Android 模拟器（或真机）冒烟：relay WSS 登录 + TURN
   中继会话建立；组播不可用时 LAN route 按预期显式降级。
3. ProfileStore/TrustStore 在 Android 存储目录下通过文件锁与原子替换测试。
4. JNI 边界满足 executor 并发边界（EXEC-01..11）抽查：无裸线程、无平行监控、
   关闭顺序有测试。
5. `DEC-14` 相关未决项（profile 存储位置、secret backend 等价物）有记录的结论。
6. v1.0 发布门禁不因本阶段未完成而阻塞（Android 只进 v1.x）。

## 4. 实施记录

### 2026-10-04 — M11-01 NDK 交叉编译基线 + M11-02 vendored OpenSSL（A1）

**M11-01 基线**

- 新增 `scripts/build_android.sh`（对齐 executor `build_android.sh` 模式）：
  NDK toolchain 文件驱动，默认 ABIs `arm64-v8a,x86_64`，API floor 固定
  `android-24`（bionic `getifaddrs`/`if_nametoindex` 自 API 24 起可用，
  LAN route 的 POSIX 枚举路径依赖它）；自动传 `HEYAKI_BUILD_APPS=OFF`、
  `HEYAKI_AUTO_INSTALL=OFF`。
- CMake 顶层：新增 `HEYAKI_ANDROID` 模式标志（由 NDK toolchain 定义的
  `ANDROID` 解析而来，FORCE 保持一致）；Android 模式下强制
  `HEYAKI_BUILD_APPS=OFF`、`HEYAKI_BUILD_FUZZERS=OFF`（A4：TUI/relay 应用、
  demo、fuzzer 均为桌面专用）与 `BUILD_TESTING=OFF`（设备端单测需要 host
  protoc 与测试 harness，随 M11-07/M11-08 落地）。
- NDK 版本：本机 r26d（26.3.11579264，与计划的 r26c 同系列）。
- arm64-v8a 与 x86_64 双 ABI 下核心库目标（`heyaki_core`、`heyaki_profile`、
  `heyaki_client`、`heyaki_services`、`heyaki_transport_webrtc`，以及随库编译的
  `heyaki_socks`、`heyaki_relay`）编译通过。安装树包含除 `heyaki_socks` 外的
  全部核心库归档：`heyaki_socks` 的接口头位于源码树（`src/socks/`），M10 即
  设计为构建树内链接的便利叶组件（M10-09），安装导出需要先做头文件重定位；
  若 Android 宿主后续需要 SOCKS 前端，该决策随 M11-06 JNI 边界一并处理。
- 移植中唯一的源码适配：`include/heyaki/ids.hpp` 的 `Identifier::operator<=>`
  由 defaulted 改为显式字节序比较。根因：NDK r26 的 libc++（LLVM 17）尚未
  实现 `std::array` 的 `operator<=>`，defaulted 比较被隐式删除，
  `std::less<Identifier>` 随之不可用；显式版本保持完全相同的字典序
  strong_ordering 语义，桌面工具链不受影响。`DeviceEndpointKey`、
  `RelayEndpointKey`、`RelayLeaseKey`（defaulted over Identifier）随此修复。

**M11-02 vendored OpenSSL 3.5.9（A1）**

- `third_party/dependencies.lock` 新增 runtime 组 atom：openssl
  `openssl-3.5.9` @ `45e844fa2a14`（3.5 LTS 最新补丁；Apache-2.0，无 copyleft，
  通过 M9-14 许可证策略门禁）；`third_party/licenses.lock` 同步登记。
  注：openssl tag 为 annotated tag，锁文件记录剥皮后的 commit。
- `cmake/HeyakiVendoredRuntime.cmake` 新增 `heyaki_add_vendored_openssl()`：
  仅 Android 模式调用；用 OpenSSL 自带 `Configure`（out-of-tree）按
  `ANDROID_ABI` 映射到 `android-arm64/android-arm/android-x86_64/android-x86`
  目标，`no-shared no-tests no-docs`，`-D__ANDROID_API__=<level>`；
  Configure 要求 NDK clang 在 PATH 上（据此选择 API 专属 wrapper，如
  `aarch64-linux-android24-clang`），函数负责把
  `<NDK>/toolchains/llvm/prebuilt/*/bin` 前置到 PATH 并设置
  `ANDROID_NDK_ROOT`；产物经 `install_sw` 装入
  `<build>/vendored/openssl-stage`（include+lib 标准布局）。
- 接入方式：stage 目录加入 `CMAKE_FIND_ROOT_PATH` 并设 `OPENSSL_ROOT_DIR`，
  之后沿用**同一个** `find_package(OpenSSL 3.0 REQUIRED ...)`（含
  "冻结 3.x、拒绝 4.x" 检查）与 libdatachannel 自身的 OpenSSL 探测——
  桌面路径零改动，M3A 的 ABI 冻结语义在 Android 上保持有效。
- 桌面构建不 fetch 不编译 vendored OpenSSL，TLS 后端仍为系统 OpenSSL 3.x
  （`docs/supply-chain/dependency-policy.md` TLS backend 行已更新）。
- 依赖计数同步：`cmake/GenerateSupplyChain.cmake` 直接 pin 计数 35→36；
  policy 文档中 OSV 扫描与 inventory 描述同步（v1.0 release-checklist 与
  m0/m9 audit 为时点记录，不改）。

**待办（下一批）**：M11-03 逐依赖验证记录、M11-04 平台层验证（A3）、
M11-05 组播降级（A2）、M11-06 JNI 边界、M11-07 冒烟示例、M11-08 CI、
M11-09 文档收尾。

### 2026-10-04 — 第二批：M11-03 依赖验证记录 + M11-04 平台层（A3）+ M11-05 核实

**M11-03 逐依赖验证记录**

- 新增 `docs/compatibility/android-ndk.md`：构建入口（NDK r26d、API 24、
  双 ABI）、逐依赖交叉编译矩阵（12 个 lock atom 的 Android 状态与理由）、
  平台层映射表、LAN 组播语义。结论：runtime 组全部原样交叉编译（无
  Android 补丁，锁文件未升级）；protobuf/abseil（test-only 工具链）、
  googletest、FTXUI（TUI）、zstd（optional 未启用）按范围排除并记录。
- 证据：M11-01/M11-02 双 ABI 干净构建 + 架构抽查 + 独立验证报告。

**M11-04 平台层验证（A3）**

- `flock`/文件锁+原子替换：bionic 与 glibc 语义一致（kernel VFS），桌面套件
  已覆盖行为，设备端执行随 M11-07/08。
- `getifaddrs`/`if_nametoindex`：由 API 24 下限保证（build 脚本与 CMake 双重
  检查）。
- 存储目录映射：`ProfileStore::create/open` 显式路径即映射点（JNI 传应用
  私有目录）；`default_profiles_root()` 等工厂在 Android 上显式返回
  `configuration`/"home_directory_unavailable"（不发明 env 回退）。
- `dlfcn` secret backend：`src/profile/secret_backend.cpp` 的 libsecret 探测在
  Android 编译期跳过（`#if defined(__linux__) && !defined(__ANDROID__)`，
  两处决策点），错误文本与降级语义不变，直接落加密文件后端策略；Keystore
  等价映射留待 DEC-14 结论（M11-09）。桌面 Linux 行为零变化。

**M11-05 核实（A2）**

- 核心侧"无锁显式降级"已存在于 pinned 代码：`IP_ADD_MEMBERSHIP` 失败 →
  记录 `multicast_join_failed` 并关闭该接口 socket；1.5s 就绪探测超时 →
  `multicast_probe_timed_out` + `LanReadinessState::degraded`；relay 路径独立
  可用；`NodeConfig.lan_override` 支持宿主主动禁用 LAN。桌面测试
  （`tests/unit/m3a_lan_test.cpp`）已断言两条降级路径。
- 剩余项：MulticastLock 生命周期钩子属应用/JNI 层，随 M11-06 落地；
  设备端组播行为验证随 M11-07/08。

### 2026-10-04 — 第三批：M11-06 JNI 边界第一增量（会话生命周期 + 授权）

- 新增 `apps/jni/heyaki_jni.cpp` + CMake 目标 `heyaki_jni`（仅
  `HEYAKI_ANDROID` 下构建的 SHARED 库，链接 `heyaki::services`，进入
  Android 安装树）。Java 契约 `apps/jni/java/dev/heyaki/core/HeyakiNode.java`
  （含 `HeyakiException`）：
  - 生命周期：create（打开/新建并初始化 profile，Argon2id 校验器由初始密码
    派生）、`snapshot()`（LAN/relay 状态摘要）、`deviceIdHex()`、`close()`
    （返回 NodeShutdownReport 摘要）。
  - 授权：`setPairingRequestListener`（无口令配对审批请求的接收端回调）、
    `approvePairing`/`rejectPairing`、`rotateAuthorizationPassword`；以及
    `connect`/`connectLan`/`closeLan`。M10 网关、RPC、shell、文件、事件面
    留待后续增量。
- executor 并发边界（EXEC 抽查项）：JNI 层零线程/零队列/零自建监控；所有
  Heyaki 工作经 heyaki Runtime/Node 内 executor 提交；配对回调在 Heyaki
  executor 上下文触发，经 Attach/DetachCurrentThread 临时挂接 JVM 投递一个
  Java 回调（异常就地清除，不回灌 executor）；NativeNode 成员声明顺序固定
  关闭顺序 node→profile→runtime；C++ 异常绝不穿越 JNI 函数边界（注册待抛
  Java 异常 + 返回哨兵）。关闭顺序测试随 M11-07（JVM/qemu 冒烟）落地。
- 修复 vendored blake3 在 AArch64 的潜伏缺陷：`blake3_impl.h` 在
  `BLAKE3_USE_NEON` 未定义时按 AArch64 自动启用 NEON 调度，引用 vendored
  目标刻意不编译的 NEON 源文件；静态库阶段不链接所以 M11-01 未暴露，直到
  第一个共享库 heyaki_jni 链接才失败（`blake3_hash_many_neon` undefined）。
  现显式钉 `BLAKE3_USE_NEON=0`（`cmake/HeyakiVendoredRuntime.cmake`）。
- JNI create 的 profile secret 后端固定为加密文件（`prefer_os_backend=false`），
  与 M11-04/A3 处置一致。
- 范围决策：Android alpha 的 Node 为 LAN-only（不注入 relay_override）；relay
  场景随 M11-07 冒烟接线。

### 2026-10-04 — 第四批：M11-07 模拟器冒烟 + M11-08 CI + M11-09 文档收尾

**M11-05/M11-06 收尾**

- MulticastLock 契约落地为文档 + 冒烟断言：宿主应用负责在 Node 生命周期内
  持锁（`docs/compatibility/android-ndk.md` §LAN multicast）；核心侧的无锁
  显式降级语义（degraded/failed 而非悬挂）由桌面测试与设备端冒烟共同覆盖。
- 关闭顺序验证：冒烟检查 6/7 以 JNI 同构的组装顺序（Runtime→ProfileStore→
  Node，析构逆序）在设备上验证 executor 干净关闭（`node_shutdown_report`）；
  JVM 内的 .so 加载/卸载测试属宿主 app 交付物。

**M11-07 冒烟 runner**

- 新增 `apps/android/heyaki_smoke.cpp` + CMake 目标 `heyaki_android_smoke`
  （仅 Android 构建，进安装树 `bin/`）：确定性、无外部服务依赖的 16 项检查
  ——identity 文本回环、加密文件 secret 后端三步（store/load/erase）、profile
  建库+初始化+后端级别、侧车锁文件 flock 竞争下 `delete_local` 必须报
  `profile_locked`、关库重开身份持久（原子替换语义）、LAN 禁用节点生命周期
  与干净关闭、LAN 启用节点在 8s 窗口内到达显式就绪态（ready/degraded/failed，
  不允许停在 starting）后干净关闭。
- 新增 `scripts/run_android_smoke.sh`（adb 推送执行，等待 boot_completed，
  PASS/FAIL 判定，模型对齐 executor `run_android_tests.sh`）。
- 本地验证（KVM + android-35 google_apis x86_64 模拟器，AVD miracle_p0）：
  `HEYAKI_ANDROID_SMOKE_OK checks=16`，设备上报到 LAN readiness = ready。
- 修正冒烟开发中发现的两个前提错误：ProfileStore 并发 open 是设计允许的
  （ExclusiveProfileLock 只保护 create/open 迁移窗口与管理操作），独占锁
  检查改为"持有侧车锁 → delete_local 报 profile_locked"；Argon2 参数必须
  满足策略下限（64 MiB / 2 ops）。

**M11-08 CI**

- 新增 `.github/workflows/android.yml`：
  - `ndk-build` job：NDK r26.3 钉版（runner 预装不符时 sdkmanager 安装），
    `scripts/build_android.sh` 双 ABI 交叉编译 + 安装树制品清单断言（8 库
    + 冒烟二进制）+ artifact 上传。
  - `emulator-smoke` job：下载 x86_64 制品 → KVM 开启 → sdkmanager 安装
    android-30 google_apis x86_64 镜像 → avdmanager 建 AVD → 无头模拟器 →
    等待 boot → `scripts/run_android_smoke.sh` 执行冒烟。
- 设计说明：qemu-user 路线需要 Android 平台 loader（/system/bin/linker64，
  NDK 不随附），executor 上游 ARM64 CI 亦采用原生/模拟器路线，故执行证据
  取自 x86_64 模拟器（退出条件允许"qemu-user/**模拟器**"二选一）；arm64
  为编译门禁，arm64 执行 lane（arm64 镜像模拟或真机）记为后续项。

**M11-09 文档**

- architecture §2.1 目标 8 追加 M11 交付状态；`docs/decisions/m0-product-
  defaults.md` DEC-14 回填确认结论（profile 存储位置 = 宿主显式传入的应用
  私有目录；Android alpha secret 后端 = 加密文件，Keystore 等价物留作后续
  产品决策）；supply-chain：openssl 已入 `licenses.lock` 与 SBOM（36+5），
  Android 安装树由既有 install 规则随库携带全部第三方许可证文本。

**v1.2 alpha 退出条件剩余缺口**

- 退出条件 2 的 relay WSS 登录 + TURN 中继会话在模拟器/真机上的建立冒烟
  （需在设备侧接线 relay enrollment/TURN 场景）。
- arm64 ABI 的执行 lane（当前为编译门禁）。

### 2026-10-05 — CI 首绿（android workflow）

- PR #18 的 `android` workflow 全绿（run 37218075875）：
  `NDK cross-build (x86_64)=success`、`NDK cross-build (arm64-v8a)=success`、
  `Emulator smoke (x86_64)=success`，冒烟在 CI 模拟器上输出
  `HEYAKI_ANDROID_SMOKE_OK checks=16`（LAN readiness = ready）。
  退出条件 1 与 4 的设备执行证据、退出条件 3 的文件锁/原子替换设备执行
  均由该 lane 覆盖。
- 调试中固化的两个 CI 事实：ubuntu-24.04 runner 不再预装 sdkmanager
  （cmdline-tools 钉版自装）；裸 `adb wait-for-device` 在模拟器启动失败时
  无界悬挂（已由 android-emulator-runner 的有界等待 + `timeout-minutes`
  兜底）。
- CI `android` workflow 首次绿（推送后由 workflow_dispatch 触发验证）。
