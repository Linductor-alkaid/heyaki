# M10 Gateway 代理安全评审记录

> 里程碑：M10 Gateway 代理服务（protocol 1.3 `gateway_v1`）
> 评审日期：2026-09-20（Round 5，随 M10-12 交付）
> 评审范围：设计 `docs/design/gateway-service.md` §9 七条威胁条目与实现的对账
> 结论：**通过（无 P0/P1）**；遗留项见文末

## 评审方式

按 M8 模式：设计威胁条目逐条对账到实现与测试证据；测试证据来自 IVA 独立验证四轮
（m10_protocol 27 例、m10_gateway_policy 55 例、m10_gateway_service 27 例、
m10_round4 20 例；ASan/LSAN/TSan 在受影响套件 0 发现），外加 CI 全矩阵。

## 条目对账

| # | 设计 §9 威胁 | 实现缓解 | 证据 |
| --- | --- | --- | --- |
| 1 | 授权 gateway 等价于把 A 放进 B 防火墙内侧 | 默认关闭（空 profile 集不建服务，入站 reset `unimplemented`）；显式 CIDR allowlist（catch-all 需 `allow_internet`，否则启动失败）；每 session/每 profile 双并发帽；字节/速率/空闲/时长配额；人工确认 never/first_use/always（30s 无应答自动拒绝）；全程审计 | policy 套件 catch_all_without_internet/quota 全轴；service 套件并发帽/配额/清扫；round4 确认流 8 例 |
| 2 | B 视角 SSRF（环回/链路本地/管理段/隧道端点） | 内置 deny 表不可配置移除：0.0.0.0/8、127/8、169.254/16、224/4、255.255.255.255/32、100.64/10、::/128、::1/128、fe80::/10、ff00::/8、**::ffff:0:0/96**（IPv4-mapped 整段——IVA 对抗复验发现 mapped 环回绕过后补入并冻结语义）；denied_cidrs 可叠加；**解析后逐地址校验**（域名由 B 侧解析，存活子集才可拨） | policy 套件内置 deny 11 段+mapped 段；round4 假域名→B 解析失败→REP 0x01（域名透传不在 A 侧解析）。**隧道端点运行时 deny 未实现**（遗留 L1） |
| 3 | 端口扫描/探测 oracle | 拨号错误粗粒度合并（refused/unreachable/filtered → 单一 `unavailable`），wire §6.3.1 冻结映射；每 host 并发/字节配额与审计提供扫描面观测 | protocol 套件映射表快照；service 套件 ClosedPort→unavailable。**每 host 尝试速率限制未实现**（遗留 L2，配额兜底） |
| 4 | 公网出口滥用 | `allow_internet` 默认 false；profile 聚合字节/速率配额 fail-closed；`PeerPathPolicy.gateway_paths`（direct_only 拒 TURN 路径网关）；审计+指标（per-profile 字节、TURN 路径占比） | policy 套件 allow_internet 轴；service 套件配额中途 reset |
| 5 | 信息泄漏（host 自由文本/拓扑） | host 文法校验（LDH/IPv4/IPv6、253B、禁控制字符/空格/下划线）先于一切日志；错误 detail 全部稳定 token（`is_safe_detail_token` 强制）；审计记录只含已过文法的 host；无网关侧元数据帧（prelude 之外） | protocol 套件文法全表 + safe_detail token 校验；审计记录类型层面无自由文本来源 |
| 6 | relay 视角不变 | gateway 复用 stream 域既有 STREAM_* 帧，无新帧类型；relay 仅见 DTLS 密文 | wire §6.3.1；M9 NAT/TURN 矩阵回归（Round 1 CI） |
| 7 | 资源耗尽 | 并发流（8 默认/64 硬帽）、每流单 16KiB in-flight chunk（两方向各有界 by construction）、profile 配额、dial deadline（10s/30s）、确认挂起 30s 自动拒、SOCKS 前端并发帽；满载 fail-closed 拒绝并计数 | service 套件配额/清扫；SOCKS 容量断连；关闭测试（会话关闭全量回收 0 detached） |

## M10 期间抓出并修复的安全相关缺陷

- `::1` 字节装配错位使内置环回 deny 全部失配（Round 2 IVA，安全级，已修+oracle 交叉验证）
- IPv4-mapped IPv6 绕过 deny 表（Round 2 复验发现，补 `::ffff:0:0/96` 整段 deny）
- 公共流 API 跨线程竞争（Round 3 TSan，facade 编组至 owning strand 修复）
- SOCKS 写缓冲 UAF（Round 4 IVA，公共 span 契约锚定修复）

## 遗留项

| # | 项 | 等级 | 处置 |
| --- | --- | --- | --- |
| L1 | 隧道端点（B 自身 Heyaki 控制/信令地址）运行时 deny：设计 §9.2 要求 dial 目标解析为与 A 的隧道端点时拒绝；当前内置表覆盖环回/链路本地段，但未在运行时比对会话实际 TURN/信令端点地址 | P2 | M10 集成轮（netns 拓扑）补运行时端点比对；当前缓解：管理段通常落于 127/8、169.254/16 或显式 denied_cidrs，TURN 服务器地址可由部署方叠加 denied_cidrs |
| L2 | 每 host 连接尝试速率限制（扫描节流）：设计 §9.3 缓解清单含"每 host 尝试速率限制"；当前靠并发/字节配额与审计观测兜底 | P3 | v1.x Gateway beta 观察期后按审计数据决定参数；先以指标 `heyaki_gateway_refused_*` 观测 |
| L3 | first_use 确认记忆为会话级（跨重启重新询问） | P4 | 设计允许（"可持久化"）；v1.x 接 ProfileStore 本地策略 |

## 签字

- 实现方（主循环）：Round 1–5 交付记录见 `docs/todolists/m10-gateway-proxy.md`
- 独立验证（IVA）：四轮报告（含上述缺陷的证据链）归档于各轮实施记录
- 生产启用姿态：默认关闭（无 profile 即不服务）；启用需显式配置 profile 与
  `gateway.provide`/`gateway.use` scope（均不进任何标准 pairing 模板）
