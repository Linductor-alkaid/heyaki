# M1：协议、安全与公共契约基线

> - 状态：已完成，2026-08-15 正式准入 M2
> - 所属计划：[Heyaki MVP 至 v1 实施 TODO 计划](heyaki-implementation-plan.md)
> - 前置：M0 | 建议发布点：协议评审基线

## 公共类型和限制

- [x] `M1-01` 定义 `DeviceId`、`EndpointId`、`SessionId`、`OperationId`、`MessageId`、`RequestId` 和 `TransferId` 的强类型与文本/二进制编码。
- [x] `M1-02` 实现 `DeviceId = SHA-256(public_key)` 与 `hy1_` base32 文本格式，覆盖非法字符、长度和大小写规则。
- [x] `M1-03` 定义稳定 `ErrorCode`、`Error` 和 `Result<T>`，覆盖架构第 13.1 节全部类别，禁止调用方依赖错误字符串分支。
- [x] `M1-04` 定义 monotonic deadline、wall-clock metadata 和相对时限的使用规则，不在协议正确性上假设设备时钟同步。
- [x] `M1-05` 建立集中 `Limits` 配置和安全最小/最大值，覆盖 frame、message、RPC、队列、窗口、文件、配对、endpoint manifest 和诊断缓冲。
- [x] `M1-06` 定义 operation 生命周期 `pending/success/error/cancelled/outcome_unknown`，并为跨重连状态增加 session epoch。

## Wire protocol

- [x] `M1-07` 新增 `docs/design/heyaki-wire-protocol.md`，冻结 framing 字段、varint、字节序、最大长度、未知帧和关闭规则。
- [x] `M1-08` 按协议域拆分 versioned Protobuf Lite schema：enrollment、signaling、session、pairing、message、RPC、event、stream、file、shell。
- [x] `M1-09` 定义 major/minor 和 capability bits 协商；未知可选字段可跳过，未知必需能力必须明确拒绝。
- [x] `M1-10` 定义规范化签名对象：enrollment、endpoint record、service manifest、offer/answer/candidate、`SESSION_HELLO`、TrustGrant。
- [x] `M1-11` 为签名对象明确 domain separator、字段顺序、长度编码、nonce、expiry 和双方身份绑定，禁止直接签名不稳定 JSON/Protobuf 序列化结果。
- [x] `M1-12` 生成并提交跨语言可复验的 golden vectors：ID 派生、规范化字节、签名、frame 和 Protobuf envelope。
- [x] `M1-13` 定义每个业务协议的状态机、重复帧、乱序帧、迟到帧、超大帧和局部通道失败行为。

## Threat model 与安全门禁

- [x] `M1-14` 新增 `docs/security/threat-model.md`，覆盖恶意设备、被控制 relay、密码猜测、ProfileStore 窃取、重放、降级、资源耗尽、路径穿越、恶意 VT 和供应链。
- [x] `M1-15` 定义密钥、token、密码、verifier 和 payload 的日志分类与脱敏测试；结构化字段只允许安全上下文。
- [x] `M1-16` 定义 replay cache 的 key、TTL、容量和满载策略；容量耗尽必须可观测且默认拒绝高风险请求。
- [x] `M1-17` 定义密码强度、Argon2id 参数版本/校准范围、安全 buffer 清理和 password generation 规则。
- [x] `M1-18` 评审 TLS/DTLS 信任边界和签名 signaling transcript 绑定，证明 relay 替换 fingerprint、ICE generation 或 offer/answer 时会在设备侧失败。
- [x] `M1-19` 建立 parser/state-machine fuzz targets，初始 corpus 包含 golden vectors、截断、重复、边界长度和未知字段。

## 测试与退出条件

- [x] 所有公共强类型、错误码、限制默认值和序列化边界有单元测试及公开头独立编译测试。
- [x] golden vectors 在 Linux/Windows、Debug/Release 上得到相同字节；协议文档与 schema 版本一致。
- [x] 所有 parser 在分配 payload 前检查长度，fuzz smoke 无 crash、越界、超限分配或无限循环。
- [x] threat model、安全默认值和 wire protocol 通过独立评审后再进入 M2；后续不兼容修改必须显式提升协议 major。

## 验证记录

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
