# Zeno Agent

Zeno Agent 是 Zeno 的独立主机探针，负责主动向 Zeno Controller 上报：

- heartbeat / 在线状态
- 系统与硬件信息
- CPU、内存、磁盘、网络速率与累计流量
- TCP Ping / ICMP Ping / HTTP GET 探测结果
- 公网 IPv4 / IPv6 / 国家码 best-effort 识别

Controller 本体仓库：<https://github.com/shuijiao1/Zeno>

## 支持矩阵与兼容性

| Agent 平台 | 架构 | 官方服务安装方式 |
| --- | --- | --- |
| Linux | amd64、arm64、armv6、armv7 | systemd，专用 `zeno-agent` 非登录用户 |
| macOS | Intel amd64、Apple Silicon arm64 | LaunchDaemon，专用 `_zeno-agent` 用户 |
| Windows | amd64、arm64 | Windows service，虚拟服务账户 |

Linux 官方安装器要求 systemd；其他 init 系统只能手动运行二进制，不属于安装器支持范围。Windows on ARM 需要支持原生 arm64 服务的系统版本。

Controller 与 Agent 独立发布，版本号不要求相同。当前验证组合不在 README 硬编码，以免过期；请以 Controller 的 [COMPATIBILITY.md](https://github.com/shuijiao1/Zeno/blob/main/docs/COMPATIBILITY.md) 和对应 Release Notes 为准。未列出的旧 Agent 组合仅为 best effort，排障前请先升级。

## 一键安装

先在 Zeno Admin 后台创建 / 编辑服务器并生成一次性 Agent 安装命令，然后按目标系统执行。安装器会把命令中的 enrollment token 兑换为随机 runtime token；旧版后台生成的 `ZENO_AGENT_TOKEN` 命令仍兼容。

后台默认命令解析最新稳定 Agent，方便首次安装。需要可复现升级/回滚时，在生成命令或受控环境中固定 `ZENO_AGENT_VERSION=vX.Y.Z`，并先核对兼容表；不要把 mutable `latest` 当作明确回滚目标。Linux/macOS 安装需要 root/sudo，Windows 需要管理员 PowerShell。

Linux / macOS：

```bash
set -o pipefail
curl -fsSL https://zeno.shuijiao.de/agent/install.sh | sudo env \
  ZENO_CONTROLLER_URL=https://zeno.example.com \
  ZENO_NODE_ID=<node-id> \
  ZENO_ENROLLMENT_TOKEN=<one-time-enrollment-token> \
  bash
```

Windows：使用管理员 PowerShell 执行后台生成的 `powershell -NoProfile ...` 命令。它会从 `https://zeno.shuijiao.de/agent/install.ps1` 下载安装脚本，安装 `zeno-agent.exe`，并注册 `zeno-agent` Windows 服务。

安装器会下载 Release 中的 `SHA256SUMS` 并校验 Agent 压缩包，且默认使用 Release Sigstore bundle（旧 Release 缺少 bundle 时使用 GitHub attestation API）验证构建来源和 workflow identity。每个 Linux、macOS、Windows 架构归档均提供对应的 CycloneDX SBOM，并一起纳入 checksum 与 provenance。下载、哈希或 provenance 验证失败时会在替换当前版本前安全停止。仅在明确接受只做哈希校验的风险时，才可设置 `ZENO_VERIFY_ATTESTATION=false`。

变量说明：

- `ZENO_CONTROLLER_URL`：Controller 公网地址，例如 `https://zeno.shuijiao.li`
- `ZENO_NODE_ID`：后台服务器 ID
- `ZENO_ENROLLMENT_TOKEN`：后台安装命令中的一次性 enrollment token；安装时兑换为本机 runtime token
- `ZENO_AGENT_TOKEN`：兼容旧安装命令的直接 runtime token；不能与 `ZENO_ENROLLMENT_TOKEN` 同时设置
- `ZENO_VERIFY_ATTESTATION`：默认 `true`；设为 `false` 会显式关闭 Release provenance 验证
- `ZENO_AGENT_VERSION`：默认 `latest`，一般不需要设置
- `ZENO_AGENT_STATE_INTERVAL`：实时资源 state 上报间隔，默认 `3s`；旧 `ZENO_AGENT_INTERVAL` 仍作为兼容别名
- `ZENO_AGENT_HEARTBEAT_INTERVAL`：heartbeat 上报间隔，默认 `15s`，用于 last_seen/debug
- `ZENO_AGENT_HOST_INTERVAL`：静态机器信息上报间隔，默认 `30m`
- `ZENO_AGENT_IDENTITY_REFRESH_INTERVAL`：公网 IPv4/IPv6 与 GeoIP 刷新间隔，默认 `12h`
- `ZENO_AGENT_NETWORK_INTERFACES`：网络接口 allowlist，逗号分隔；默认排除 Docker/veth/br-/tun/tailscale/kube/vmbr/tap 等虚拟接口
- `ZENO_AGENT_DISK_MOUNTS`：磁盘统计路径 allowlist，逗号分隔；默认汇总真实文件系统分区并排除 overlay/tmpfs/proc/sysfs/docker/kubelet 等挂载
- `ZENO_AGENT_TOKEN_FILE`：token 文件路径，默认 `/etc/zeno/agent-token`
- `ZENO_AGENT_BIN`：二进制安装路径，默认 `/usr/local/bin/zeno-agent`

远程 Controller 默认必须使用 HTTPS。为兼容无反代的直连部署，“远程直接 IP + 显式端口”的 HTTP URL 必须给安装器显式设置 `ZENO_ALLOW_INSECURE_HTTP=1`，安装器才会在服务配置中持久化 `-allow-insecure-http`；这会让 enrollment/runtime bearer token 以明文传输，应只在已明确接受该风险的受控网络使用。主机名 HTTP、无显式端口的远程 HTTP 仍会被拒绝，手动运行二进制时也必须显式提供该 flag。

Linux 安装脚本会创建固定的非 root `zeno-agent` 系统账户，写入 / 更新 `zeno-agent.service`，并只保留 ICMP 所需的 `CAP_NET_RAW`；token 由 root 持有且仅向服务私有主组开放读取。若主机已有同名普通账户、共享组或不符合 nologin/no-home 约束的账户，安装器会拒绝继续，避免扩大 token 读取范围；安装失败时会原样恢复既有 token 的 owner/mode，并清理本次尚未提交的服务账户。macOS 会创建固定的非登录 `_zeno-agent` 系统账户，写入 `/Library/LaunchDaemons/li.shuijiao.zeno-agent.plist`，并通过 `/etc/newsyslog.d/zeno-agent.conf` 轮转仅该账户可读写的 Agent 日志；未知的同名 newsyslog 配置不会被覆盖。Windows fresh install 使用 `NT SERVICE\zeno-agent` 虚拟账户、受限 required-privileges 列表和 service-SID token ACL；为保证可回滚，未知账户的既有 Windows 服务不会自动迁移。三个平台都会在修改服务配置前使用 token 文件执行严格安装检查，只有 Controller 同时接受该 node 的 heartbeat 和 state 后才会继续。安装脚本可重复执行，并把旧二进制备份轮转为最新 3 份；安装脚本不会安装 Controller，也不会修改业务服务。

## 安装、升级与卸载边界

- **安装**：只使用对应节点的一次性 enrollment 命令。安装器会校验 checksum/provenance、创建受限服务账户、写 token 文件和服务配置；不会安装 Controller、修改防火墙或业务服务。
- **升级**：在同一节点重新运行后台新生成的命令。安装器先验证候选版本和 Controller 回执，失败时恢复原二进制、token、服务状态与权限；不要用另一节点的 token 覆盖。
- **降级**：只有兼容表或 Release Notes 明确允许时，才设置 `ZENO_AGENT_VERSION=<older-tag>` 重新运行安装器。Controller 数据库不随 Agent 降级。
- **卸载**：当前安装器没有自动卸载模式。先在 Controller 禁用/删除对应测试节点，再停止并禁用 `zeno-agent` 服务，删除该平台的服务定义、Agent 二进制和 token 文件。仅当专用服务账户确由 Zeno 创建且没有其他文件/用途时才删除它。卸载 Agent 不会删除 Controller 中已有历史数据，也不应修改同机的其他服务。

具体路径可能被 `ZENO_AGENT_BIN`、`ZENO_AGENT_TOKEN_FILE` 或 `ZENO_AGENT_INSTALL_DIR` 覆盖；清理前先检查实际服务定义，禁止照抄默认路径覆盖未知安装。

## 手动构建

```bash
go test ./...
version=$(cat VERSION)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w -X main.defaultVersion=$version" -o dist/zeno-agent ./cmd/zeno-agent
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags "-s -w -X main.defaultVersion=$version" -o dist/zeno-agent-darwin-arm64 ./cmd/zeno-agent
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w -X main.defaultVersion=$version" -o dist/zeno-agent.exe ./cmd/zeno-agent
```

## systemd

安装后服务名固定为：

```bash
systemctl status zeno-agent.service
journalctl -u zeno-agent.service -f
```

## 安全边界

Zeno Agent 不提供远程命令、终端、文件管理或任务执行能力，只主动向 Controller 发起 HTTPS/JSON 上报（或仅在上述显式直连 opt-in 下使用明文 HTTP），并通过 presence WebSocket 接收“探针配置已变更”的轻量通知；完整探针配置仍由 Agent 使用原 HTTP 鉴权接口主动拉取。

Agent 会采集/上报主机名、OS/kernel/架构/虚拟化、CPU/内存/swap/磁盘、进程数/TCP 连接数、网络接口累计流量和速率、uptime、best-effort 公网 IPv4/IPv6 与 GeoIP 国家码，以及管理员配置的 ICMP/TCP/HTTP 探测结果。Controller 的 public page/API 可展示管理员配置的节点名称/地区、公网地址字段、在线状态、资源/流量摘要、到期/配额和探测统计；不会展示 runtime/enrollment token 或 Agent 本地 token 路径。管理员应在公开页面上线前复核节点名称、地址和地区是否适合公开。

安全漏洞请通过 <https://github.com/shuijiao1/Zeno-Agent/security/advisories/new> 私密报告；也请参阅 Controller [SECURITY.md](https://github.com/shuijiao1/Zeno/blob/main/docs/SECURITY.md)。不要在公开 Issue 中粘贴 runtime/enrollment token、完整安装命令、Authorization header、服务定义、token 文件、Controller 数据库或通知凭据。普通 bug 报告请只提供脱敏后的 Agent/Controller 版本、OS/架构、错误类别和相关时间窗。
