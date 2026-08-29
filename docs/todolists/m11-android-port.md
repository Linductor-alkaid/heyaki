# M11 Android（NDK）库适配

> - 状态：未开始（2026-08-29 依赖可移植性分析完成，计划立项）
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

- [ ] `M11-01` 建立 NDK 工具链交叉编译基线：`HEYAKI_ANDROID` CMake 选项 +
  NDK toolchain file，`HEYAKI_BUILD_APPS=OFF`/fuzzer 关闭，验证核心库目标在
  NDK（r26c 或 r28b，与 executor CI 对齐）下为 arm64-v8a 与 x86_64 编译通过。
- [ ] `M11-02` vendored OpenSSL 3.x 交叉编译方案落地（A1）：更新
  `cmake/HeyakiVendoredRuntime.cmake`，Android 构建不再 `find_package(OpenSSL)`；
  记录与 libdatachannel TLS backend 的选择及理由到本文件与 supply-chain 文档。
- [ ] `M11-03` 逐依赖交叉编译验证并记录版本/补丁：Boost.Asio/Beast、libsodium、
  protobuf、abseil、blake3、sqlite、zstd、libdatachannel（对齐
  `third_party/dependencies.lock` 版本，不借机升级）。
- [ ] `M11-04` 平台层验证（A3）：`flock`、`getifaddrs`/`if_nametoindex`、文件锁 +
  原子替换、XDG→Android 存储目录映射、`dlfcn` secret backend 的启用/禁用策略。
- [ ] `M11-05` LAN 组播适配（A2）：JNI 集成层 MulticastLock 钩子；Android 无锁时
  LAN discovery 显式降级并保持 relay 路径可用；补降级路径测试。
- [ ] `M11-06` JNI 集成边界：以薄封装暴露 Node 会话生命周期/授权 API，Heyaki
  工作仍全部经 executor 提交，回调经既有 executor::comm 语义投递到宿主线程；
  不在 JNI 层建立第二并发系统。
- [ ] `M11-07` 最小 Android 集成示例（例如演示 app 或 qemu-user 冒烟 runner），
  纳入 CI 冒烟而非人工步骤。
- [ ] `M11-08` CI：新增 android workflow（NDK 交叉编译 + qemu-user/arm64 模拟器
  冒烟），复用现有依赖校验与 lockfile 门禁。
- [ ] `M11-09` 文档：更新 architecture §平台矩阵、`docs/compatibility/` 新增
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

（随实施追加。）
