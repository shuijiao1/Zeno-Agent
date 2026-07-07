#!/usr/bin/env bash
set -euo pipefail

REPO="${ZENO_AGENT_REPO:-shuijiao1/Zeno-Agent}"
VERSION="${ZENO_AGENT_VERSION:-latest}"
INSTALL_DIR="${ZENO_AGENT_INSTALL_DIR:-}"
BIN="${ZENO_AGENT_BIN:-}"
TOKEN_FILE="${ZENO_AGENT_TOKEN_FILE:-}"
CONTROLLER_URL="${ZENO_CONTROLLER_URL:-}"
NODE_ID="${ZENO_NODE_ID:-}"
TOKEN="${ZENO_AGENT_TOKEN:-}"
INTERVAL="${ZENO_AGENT_INTERVAL:-2s}"
NETWORK_INTERFACES="${ZENO_AGENT_NETWORK_INTERFACES:-}"
DISK_MOUNTS="${ZENO_AGENT_DISK_MOUNTS:-}"

fail() {
  echo "错误: $*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || fail "未找到 $1，请先安装后重试"
}

[ -n "$CONTROLLER_URL" ] || fail "必须设置 ZENO_CONTROLLER_URL"
[ -n "$NODE_ID" ] || fail "必须设置 ZENO_NODE_ID"
[ -n "$TOKEN" ] || [ -s "$TOKEN_FILE" ] || fail "必须设置 ZENO_AGENT_TOKEN 或提供已有 token 文件"

need uname
need sed
need tar
need mktemp

if command -v curl >/dev/null 2>&1; then
  DL='curl -fsSL'
elif command -v wget >/dev/null 2>&1; then
  DL='wget -qO-'
else
  fail "未找到 curl 或 wget"
fi

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$OS" in
  linux) GOOS=linux ;;
  darwin) GOOS=darwin ;;
  *) fail "暂不支持系统: $OS" ;;
esac
case "$ARCH" in
  x86_64|amd64) GOARCH=amd64 ;;
  aarch64|arm64) GOARCH=arm64 ;;
  armv7l|armv6l) GOARCH=arm ;;
  *) fail "暂不支持架构: $ARCH" ;;
esac

if [ "$VERSION" = "latest" ]; then
  VERSION=$($DL "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)
  [ -n "$VERSION" ] || fail "无法获取最新版本"
fi

ASSET="zeno-agent_${GOOS}_${GOARCH}.tar.gz"
URL="https://github.com/$REPO/releases/download/$VERSION/$ASSET"
TMP=$(mktemp -d)
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

echo "下载 Zeno Agent $VERSION ($GOOS/$GOARCH)..."
if command -v curl >/dev/null 2>&1; then
  curl -fL "$URL" -o "$TMP/$ASSET"
else
  wget -O "$TMP/$ASSET" "$URL"
fi

tar -xzf "$TMP/$ASSET" -C "$TMP"
FOUND=$(find "$TMP" -type f -name 'zeno-agent' | head -n1)
[ -n "$FOUND" ] || fail "压缩包内未找到 zeno-agent"

if [ -z "$INSTALL_DIR" ]; then
  case "$GOOS" in
    darwin) INSTALL_DIR="/Library/Application Support/Zeno Agent" ;;
    *) INSTALL_DIR="/opt/zeno-agent" ;;
  esac
fi
if [ -z "$BIN" ]; then
  BIN="/usr/local/bin/zeno-agent"
fi
if [ -z "$TOKEN_FILE" ]; then
  case "$GOOS" in
    darwin) TOKEN_FILE="/Library/Application Support/Zeno/agent-token" ;;
    *) TOKEN_FILE="/etc/zeno/agent-token" ;;
  esac
fi

extra_args=()
if [ -n "$NETWORK_INTERFACES" ]; then
  extra_args+=("-network-interfaces" "$NETWORK_INTERFACES")
fi
if [ -n "$DISK_MOUNTS" ]; then
  extra_args+=("-disk-mounts" "$DISK_MOUNTS")
fi

install -d -m 755 "$(dirname "$BIN")" "$INSTALL_DIR" "$(dirname "$TOKEN_FILE")"
install -m 755 "$FOUND" "$BIN"
if [ -n "$TOKEN" ]; then
  umask 077
  printf '%s\n' "$TOKEN" > "$TOKEN_FILE"
fi
chmod 600 "$TOKEN_FILE"

if [ "$GOOS" = "darwin" ]; then
  PLIST="/Library/LaunchDaemons/li.shuijiao.zeno-agent.plist"
  xml_escape() {
    printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g'
  }
  plist_extra_args=""
  for arg in "${extra_args[@]}"; do
    plist_extra_args="${plist_extra_args}    <string>$(xml_escape "$arg")</string>
"
  done
  cat > "$PLIST" <<EOF_PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>li.shuijiao.zeno-agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>$(xml_escape "$BIN")</string>
    <string>-controller-url</string><string>$(xml_escape "$CONTROLLER_URL")</string>
    <string>-node-id</string><string>$(xml_escape "$NODE_ID")</string>
    <string>-token-file</string><string>$(xml_escape "$TOKEN_FILE")</string>
    <string>-interval</string><string>$(xml_escape "$INTERVAL")</string>
    <string>-version</string><string>$(xml_escape "$VERSION")</string>
${plist_extra_args}
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>/var/log/zeno-agent.log</string>
  <key>StandardErrorPath</key><string>/var/log/zeno-agent.err.log</string>
</dict>
</plist>
EOF_PLIST
  chown root:wheel "$PLIST" 2>/dev/null || true
  chmod 644 "$PLIST"
  launchctl bootout system "$PLIST" >/dev/null 2>&1 || true
  launchctl bootstrap system "$PLIST"
  launchctl enable system/li.shuijiao.zeno-agent >/dev/null 2>&1 || true
  launchctl kickstart -k system/li.shuijiao.zeno-agent >/dev/null 2>&1 || true
else
  systemd_extra_args=""
  if [ "${#extra_args[@]}" -gt 0 ]; then
    printf -v systemd_extra_args ' %q' "${extra_args[@]}"
  fi
  cat > /etc/systemd/system/zeno-agent.service <<EOF_SERVICE
[Unit]
Description=Zeno Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BIN -controller-url $CONTROLLER_URL -node-id $NODE_ID -token-file $TOKEN_FILE -interval $INTERVAL -version $VERSION${systemd_extra_args}
Restart=always
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF_SERVICE

  systemctl daemon-reload
  systemctl enable --now zeno-agent.service >/dev/null
  systemctl restart zeno-agent.service
  systemctl is-active --quiet zeno-agent.service
fi

echo "Zeno Agent 已安装并启动: node=$NODE_ID version=$VERSION"
