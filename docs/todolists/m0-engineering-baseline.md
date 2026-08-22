# M0：仓库、构建与质量基线

> - 状态：已完成，2026-08-14 正式准入 M1
> - 所属计划：[Heyaki MVP 至 v1 实施 TODO 计划](heyaki-implementation-plan.md)
> - 前置：无 | 建议发布点：内部工程基线

## 仓库骨架

- [x] `M0-01` 新增顶层 `CMakeLists.txt`、`CMakePresets.json` 和 C++20 编译基线，提供 Debug/Release/ASAN/UBSAN/TSAN 预设。
- [x] `M0-02` 建立设计规定的目录：`include/heyaki/`、`src/`、`proto/`、`apps/relay/`、`apps/tui/`、`tests/{unit,integration,network}`。
- [x] `M0-03` 建立 targets：`heyaki::core`、`heyaki::profile`、`heyaki::client`、`heyaki::services`、`heyaki::transport_webrtc`、`heyaki-relay`、`heyaki-tui`。
- [x] `M0-04` 用 CMake target 约束依赖方向，加入“公共头不可包含 libdatachannel/FTXUI 私有类型”的编译测试。
- [x] `M0-05` 统一 warning、`clang-format`、`clang-tidy`、include-what-you-use（若环境可用）与禁止异常配置的项目选项。
- [x] `M0-06` 为生成的 Protobuf 文件、测试临时 profile、credential 和 fuzz corpus 明确构建目录及清理规则，防止机密进入源码树。

## 依赖与供应链

- [x] `M0-07` 运行 `scripts/fetch_third_party.sh --check --all`，补齐当前未抓取的 `googletest` 与可选 `zstd` 验证路径。
- [x] `M0-08` 为 Boost、TLS backend 和 coturn 确定可复现版本策略；不能只依赖开发机上未记录的系统版本。
- [x] `M0-09` 验证 libdatachannel v0.23.2 的 ICE backend、TURN/TCP/TLS、证书库和 Windows 构建组合，形成兼容矩阵。
- [x] `M0-10` 对所有 pinned 依赖生成许可证清单和 SBOM；确认静态/动态链接与发布包合规。
- [x] `M0-11` 给依赖升级建立单独流程：更新 ref/commit、验证 moved tag、运行全量协议/网络回归并记录版本差异。

## CI 与测试入口

- [x] `M0-12` 建立 Linux GCC/Clang 与 Windows MSVC 构建矩阵，至少执行 configure、build、unit test 和安装后 consumer compile test。
- [x] `M0-13` 建立 ASAN/UBSAN 常规任务、TSAN 专项任务和 fuzz smoke 任务；宿主不支持时记录目标机补跑门禁。
- [x] `M0-14` 建立测试标签：`unit`、`protocol`、`integration`、`network`、`security`、`fuzz`、`performance`、`tui`、`windows`。
- [x] `M0-15` 建立测试证书、bootstrap token、relay database 和 profile fixture 生成器；fixture 只能包含测试密钥。
- [x] `M0-16` 建立 network namespace + nftables/netem harness 的 Linux-only 入口，并在无权限环境明确 skip 原因。
- [x] `M0-17` 建立版本、构建 commit、协议版本和 feature flags 的可查询接口，供 relay、TUI 和诊断输出复用。

## 测试与退出条件

- [x] 空实现 targets 在 Linux GCC/Clang 和 Windows MSVC 上可构建、安装并由外部最小 consumer 引用。
- [x] runtime、test、optional 三组 dependency pin 均可离线校验，依赖缺失时 configure 给出可操作错误。
- [x] 单元、集成、网络、fuzz 和 sanitizer 命令均有稳定入口，CI 不以“无测试可运行”冒充成功。
- [x] 产品决策 `DEC-01` 至 `DEC-09` 已确认，或明确记录暂定默认值、负责人和最迟冻结里程碑。

## 验证记录

M0 验证记录（2026-08-14）：本机 GCC 13.3 的 Debug、Release、UBSAN、禁异常、可选依赖及 pinned libdatachannel 最小静态 DataChannel profile 构建通过，安装后 consumer 通过；ASAN 因宿主 ptrace 限制、TSAN 因宿主地址映射限制而明确 skip。GitHub Actions 在 commit `72c55d7` 上完成 Linux GCC/Clang、Windows MSVC、ASAN、UBSAN、TSAN 和 fuzz smoke 矩阵，configure、build、CTest、安装后 consumer 以及三平台 pinned libdatachannel 构建全部通过，CI 不允许 sanitizer runtime skip。Linux network harness 在缺少 `CAP_NET_ADMIN` 的环境明确 skip。供应链生成器覆盖 9 个直接 pin、5 个 libdatachannel submodule、许可证文件存在性与 SPDX 父子关系，相关 CI 清单测试通过；当前安装/链接闭包见 [M0 链接与许可证审计](../supply-chain/m0-linkage-license-audit.md)。默认 libjuice 明确不支持 TURN/TCP/TLS，该负向能力结论与后续 libnice/coturn 门禁见 [兼容矩阵](../compatibility/libdatachannel-v0.23.2.md)。产品默认值、owner 与冻结点见 [M0 产品决策默认值](../decisions/m0-product-defaults.md)。据此 `M0-01` 至 `M0-17` 及全部 M0 退出条件完成，正式准入 M1。
