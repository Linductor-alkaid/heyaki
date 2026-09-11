# M9-07 跨平台（Linux/Windows）组合验证

> 状态：CI 覆盖已交付（Windows 本机矩阵 + 防火墙 allow/block 路径）；真·跨机 Linux↔Windows 组合在 GitHub 托管 runner 上被平台能力阻断，自托管程序见下文。
> 相关：[m9-production-hardening.md](../todolists/m9-production-hardening.md) M9-07、[runbook](runbook.md)

## 结论与边界

| 组合 | 状态 | 覆盖位置 |
| --- | --- | --- |
| LAN-only（发现 + 认证 + 会话 + 服务） | Windows CI 每 PR | `heyaki_windows_network_matrix` 场景 `lan_only`（双向发起）；LAN 会话建立另有 `m3a` 套件常驻 |
| relay-signaled direct | Windows CI 每 PR | 同上场景 `relay_direct`（Windows relay + 双向发起） |
| TURN/UDP | Windows CI 每 PR | 同上场景 `turn_udp`（`heyaki-test-turn-server` 内嵌 libjuice TURN，双向发起）。注：单机矩阵接受 `turn_udp` 与 `direct_srflx` 两种提名标签——后者是本地 srflx 候选与对端 relayed 候选组对（数据仍经对端 TURN 中转），"双方都走中转"的严格断言是 Linux netns 拓扑的属性（M9-06），单机无法拓扑强制 |
| UDP blocked（有界显式失败） | Linux CI 每 PR；Windows 仅跨 OS 模式 | Linux：`heyaki_m4_network_matrix` 的 `udp_blocked`（iptables 对真实网络路径真阻断）。Windows 单机不可仿真——WFP 豁免 loopback 流量，程序级阻断规则永远碰不到同机 TURN server（首跑实证：规则创建成功但会话照常建立）；跨 OS 模式（TURN 在远端 Linux）下防火墙规则有效，harness 显式支持 |
| Windows firewall/network profile | Windows CI 每 PR | `heyaki_windows_firewall_harness`：Public profile 阻断（负向）+ 程序级放行规则恢复发现（正向） |
| 文件权限/命名 | Windows CI 每 PR | 全量单测在 Windows 上运行：`m7_codec`（Windows 保留名/尾点空格/反斜杠拒绝）、`m7_file`（CON 推送拒绝）、`m2_profile`（ProfileStore 权限，Windows 分支）；文件传输在矩阵每场景经 NTFS 落盘（`m7_file=1` 断言） |
| PTY/ConPTY 生命周期 | Windows CI 每 PR | `m8_pty`/`m8_shell` 全套（真 ConPTY spawn/exit/升级阶梯/空闲超时/关停回收；两处 Windows 专属 skip 有注释说明） |
| TURN/TCP、TURN/TLS | **被 pinned 依赖阻断** | 见下文"TURN/TCP 与 TURN/TLS 依赖限制" |
| Linux↔Windows 真跨机组合 | **CI 不可达**，自托管执行 | 见下文"自托管跨 OS 程序" |

## CI 不可达的依据

GitHub 托管 runner 无法承载真·跨机 Linux↔Windows 组合：

1. 两个 job 的 runner 之间没有网络可达性——runner 都在 NAT 后、不接受入站连接，
   heyaki 的 relay/TURN 需要至少一侧可寻址；
2. 单机双 OS 不可靠：windows-2025 镜像的 WSL2 长期损坏/不支持
   （actions/runner-images [#11784](https://github.com/actions/runner-images/issues/11784)、
   [#11869](https://github.com/actions/runner-images/issues/11869)，
   根因是无嵌套虚拟化）；Linux runner 无 KVM，跑 Windows VM 仅剩纯模拟、不可行；
3. 借道公网会合点（隧道/免费中继）会引入不受控的外部依赖，不符合供应链与
   确定性要求。

因此 M9-07 按"每 OS 全组合 + 双向发起 + 平台特有行为"在各自 CI 内验证
（如上表），真·跨机互通由自托管混合机队执行并留档。最终验收标准里
"或明确阻断结论"即对应本节。

## TURN/TCP 与 TURN/TLS 依赖限制

pinned libdatachannel v0.23.2 的默认 ICE 后端 libjuice 只实现 UDP 传输的
TURN 客户端（vendored `deps/libjuice` 的 `juice_create` 只绑 UDP socket；
`rtc::Configuration::enableIceTcp` 形同虚设）。heyaki 已把该事实编码进
配置校验：`WebRtcTransportConfig::tcp_turn_backend_verified` 默认 false，
开启 `allow_turn_tcp`/`allow_turn_tls` 而 backend 未验证时
`valid_config` 直接拒绝（`webrtc_transport_session.cpp`，单测覆盖于
`m4_webrtc_transport_test`）。协议面（wire 标签、candidate policy、
IceServerKind::turn_tcp/turn_tls）已就绪，升级依赖后只需验证后端并把
标记置真。与 M9-01 的丢包估计缺口同类（第三方依赖 API 面，非 executor
限制，不进 executor ledger）；重估时点：M9-10 基准之后。

## 自托管跨 OS 程序

在一台 Linux 主机与一台 Windows 主机（同一 LAN，或 Windows 可路由到
Linux 主机的公网/VPN 地址）上执行。Linux 侧提供 relay 与 TURN，两侧各跑
一个矩阵节点，发起方向各跑一遍。

### Linux 侧（relay + TURN）

```bash
# 仓库根目录，构建 relay 与矩阵节点（Release 为宜）
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DHEYAKI_BUILD_APPS=ON
cmake --build build --target heyaki-relay heyaki-m4-matrix-node \
  heyaki-m3b-relay-demo heyaki-test-turn-server --parallel

# 生成 CA/证书（<LAN_IP> = Linux 主机在 Windows 侧可达的地址）
mkdir cross-os && cd cross-os
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -set_serial 1 \
  -subj "/CN=heyaki-crossos-relay" -keyout ca-key.pem -out ca.pem
openssl req -newkey rsa:2048 -nodes -subj "/CN=<LAN_IP>" \
  -keyout relay-key.pem -out relay.csr
printf 'subjectAltName=IP:<LAN_IP>\n' > san.ext
openssl x509 -req -in relay.csr -CA ca.pem -CAkey ca-key.pem -CAcreateserial \
  -days 1 -extfile san.ext -out relay-cert.pem

# bootstrap token + relay（配置文件键同 tests/network 的矩阵脚本）
build/heyaki-m3b-relay-demo seed-token relay.sqlite crossos-tenant \
  TEST-ONLY-crossos-token-0123456789 \
  $(( $(date +%s%3N) + 3600000 )) 64
cat > relay.conf <<EOF
listen_address = 0.0.0.0
listen_port = 8443
tls_certificate_file = $PWD/relay-cert.pem
tls_private_key_file = $PWD/relay-key.pem
database_file = $PWD/relay.sqlite
EOF
build/heyaki-relay --config relay.conf &

# TURN/UDP：内嵌 libjuice server（无需 coturn；coturn 亦可）
build/heyaki-test-turn-server --port 3480 --username linux-side \
  --credential crossos-turn --external <LAN_IP> \
  --relay-port-begin 49200 --relay-port-end 49299 &

# 参与方 profile（Linux 侧）
build/heyaki-m4-matrix-node init-profile linux.sqlite matrix.linux
```

把 `ca.pem` 复制到 Windows 主机。Linux 侧加入会话（responder 为例）：

```bash
build/heyaki-m4-matrix-node seed-trust linux.sqlite windows.sqlite  # 见下方说明
build/heyaki-m4-matrix-node enroll linux.sqlite matrix.linux \
  wss://<LAN_IP>:8443 ca.pem crossos-tenant TEST-ONLY-crossos-token-0123456789
build/heyaki-m4-matrix-node run linux.sqlite matrix.linux \
  wss://<LAN_IP>:8443 ca.pem crossos-tenant 60000 \
  --role responder \
  --turn <LAN_IP>:3480 --turn-username linux-side --turn-credential crossos-turn
```

（`seed-trust` 要求两个 profile 在同一文件系统上；跨机预置信任的当前做法是
在任一侧生成两个 profile、`seed-trust` 后把 `windows.sqlite*` 整组文件复制
到 Windows 侧。）

### Windows 侧

```powershell
# 构建产物与 ca.pem 就位后（管理员 PowerShell 不必需，lan_only 除外项见下）
build\heyaki-m4-matrix-node.exe enroll windows.sqlite matrix.windows `
  wss://<LAN_IP>:8443 ca.pem crossos-tenant TEST-ONLY-crossos-token-0123456789
build\heyaki-m4-matrix-node.exe run windows.sqlite matrix.windows `
  wss://<LAN_IP>:8443 ca.pem crossos-tenant 60000 `
  --role initiator `
  --turn <LAN_IP>:3480 --turn-username linux-side --turn-credential crossos-turn
```

或直接用矩阵 harness 的跨 OS 模式（Windows 本机全部场景，relay 指向 Linux）：

```powershell
powershell -File tests\network\run_windows_network_matrix.ps1 `
  -MatrixBin build\heyaki-m4-matrix-node.exe `
  -RelayBin build\heyaki-relay.exe `
  -DemoBin build\heyaki-m3b-relay-demo.exe `
  -TurnServerBin build\heyaki-test-turn-server.exe `
  -RelayUrl wss://<LAN_IP>:8443 -RelayCaFile ca.pem `
  -EnrollToken TEST-ONLY-crossos-token-0123456789 `
  -TurnEndpoint <LAN_IP>:3480 -TurnUsername linux-side `
  -TurnCredential crossos-turn `
  -Scenario lan_only,relay_direct,turn_udp
```

（跨 OS 模式下两个 Windows 节点互连、信令与 TURN 走 Linux 侧，防火墙
udp_blocked 场景也在此模式可用——出站 UDP 到远端 TURN 端口真穿网络栈；
单向 Linux↔Windows 节点组合用上面的裸命令各方向跑一遍。）

### 断言与留档

- 每个方向断言双侧 `MATRIX_RESULT authenticated=1`、发起侧
  `m6_message_acked=1 m6_rpc_status>=0 m7_file=1`；
- `relay_direct` 场景 `data_path=direct_host`；强制 TURN 时
  `data_path` ∈ {`turn_udp`, `direct_srflx`}（见上表注）；`duration_ms`
  记入发布清单（M9-18）；
- Windows 防火墙处于部署形态（Public + runbook 放行规则）时复跑
  `lan_only`，证明规则集在真实 profile 下足够；
- 结果（日期、两机 OS 版本、每方向 duration/P95、原始输出）附在
  M9-18 release checklist 的"跨 OS 验证"条目下。
