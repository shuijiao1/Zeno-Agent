#!/usr/bin/env bash
set -euo pipefail

REPO="${ZENO_AGENT_REPO:-shuijiao1/Zeno-Agent}"
VERSION="${ZENO_AGENT_VERSION:-latest}"
INSTALL_DIR="${ZENO_AGENT_INSTALL_DIR:-/opt/zeno-agent}"
BIN="${ZENO_AGENT_BIN:-/usr/local/bin/zeno-agent}"
TOKEN_FILE="${ZENO_AGENT_TOKEN_FILE:-/etc/zeno/agent-token}"
CONTROLLER_URL="${ZENO_CONTROLLER_URL:-}"
NODE_ID="${ZENO_NODE_ID:-}"
TOKEN="${ZENO_AGENT_TOKEN:-}"
INTERVAL="${ZENO_AGENT_INTERVAL:-2s}"

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

install -d -m 755 "$(dirname "$BIN")" "$INSTALL_DIR" /etc/zeno
install -m 755 "$FOUND" "$BIN"
if [ -n "$TOKEN" ]; then
  umask 077
  printf '%s\n' "$TOKEN" > "$TOKEN_FILE"
fi
chmod 600 "$TOKEN_FILE"

cat > /etc/systemd/system/zeno-agent.service <<EOF_SERVICE
[Unit]
Description=Zeno Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$BIN -controller-url $CONTROLLER_URL -node-id $NODE_ID -token-file $TOKEN_FILE -interval $INTERVAL -version $VERSION
Restart=always
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF_SERVICE

systemctl daemon-reload
systemctl enable --now zeno-agent.service >/dev/null
systemctl restart zeno-agent.service
systemctl is-active --quiet zeno-agent.service

echo "Zeno Agent 已安装并启动: node=$NODE_ID version=$VERSION"
