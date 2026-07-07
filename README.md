# Zeno Agent

Zeno Agent 是 Zeno 的独立主机探针，负责主动向 Zeno Controller 上报：

- heartbeat / 在线状态
- 系统与硬件信息
- CPU、内存、磁盘、网络速率与累计流量
- TCP Ping / ICMP Ping / HTTP GET 探测结果
- 公网 IPv4 / IPv6 / 国家码 best-effort 识别

Controller 本体仓库：<https://github.com/shuijiao1/Zeno>

## 一键安装

先在 Zeno Admin 后台创建 / 编辑服务器并生成该节点的 Agent token，然后按目标系统复制后台生成的命令执行。

Linux / macOS：

```bash
curl -fsSL https://raw.githubusercontent.com/shuijiao1/Zeno-Agent/main/install.sh | sudo env \
  ZENO_CONTROLLER_URL=https://zeno.example.com \
  ZENO_NODE_ID=<node-id> \
  ZENO_AGENT_TOKEN=<agent-token> \
  ZENO_AGENT_VERSION=v0.1.0 \
  bash
```

Windows：使用管理员 PowerShell 执行后台生成的 `powershell -NoProfile ...` 命令。它会下载 `install.ps1`，安装 `zeno-agent.exe`，并注册 `zeno-agent` Windows 服务。

变量说明：

- `ZENO_CONTROLLER_URL`：Controller 公网地址，例如 `https://zeno.shuijiao.li`
- `ZENO_NODE_ID`：后台服务器 ID
- `ZENO_AGENT_TOKEN`：该节点 token
- `ZENO_AGENT_VERSION`：默认 `latest`，可固定为 `v0.1.0`
- `ZENO_AGENT_INTERVAL`：状态上报间隔，默认 `2s`
- `ZENO_AGENT_TOKEN_FILE`：token 文件路径，默认 `/etc/zeno/agent-token`
- `ZENO_AGENT_BIN`：二进制安装路径，默认 `/usr/local/bin/zeno-agent`

Linux 安装脚本会写入 / 更新 `zeno-agent.service`；macOS 会写入 `/Library/LaunchDaemons/li.shuijiao.zeno-agent.plist`；Windows 会注册 `zeno-agent` 服务。安装脚本不会安装 Controller，也不会修改业务服务。

## 手动构建

```bash
go test ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o dist/zeno-agent ./cmd/zeno-agent
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o dist/zeno-agent-darwin-arm64 ./cmd/zeno-agent
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o dist/zeno-agent.exe ./cmd/zeno-agent
```

## systemd

安装后服务名固定为：

```bash
systemctl status zeno-agent.service
journalctl -u zeno-agent.service -f
```

## 安全边界

Zeno Agent 不提供远程命令、终端、文件管理或任务执行能力，只主动向 Controller 发起 HTTPS/JSON 上报。
