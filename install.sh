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
ENROLLMENT_TOKEN="${ZENO_ENROLLMENT_TOKEN:-}"
VERIFY_ATTESTATION="${ZENO_VERIFY_ATTESTATION:-true}"
# Do not let either credential remain in the inherited environment of download,
# package, or service-management subprocesses.
unset ZENO_AGENT_TOKEN ZENO_ENROLLMENT_TOKEN
STATE_INTERVAL="${ZENO_AGENT_STATE_INTERVAL:-${ZENO_AGENT_INTERVAL:-3s}}"
HEARTBEAT_INTERVAL="${ZENO_AGENT_HEARTBEAT_INTERVAL:-15s}"
HOST_INTERVAL="${ZENO_AGENT_HOST_INTERVAL:-30m}"
IDENTITY_REFRESH_INTERVAL="${ZENO_AGENT_IDENTITY_REFRESH_INTERVAL:-12h}"
NETWORK_INTERFACES="${ZENO_AGENT_NETWORK_INTERFACES:-}"
DISK_MOUNTS="${ZENO_AGENT_DISK_MOUNTS:-}"
SERVICE_NAME="zeno-agent"

fail() {
  echo "错误: $*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || fail "未找到 $1，请先安装后重试"
}

download_stdout() {
  local url="$1"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 3 --retry-delay 2 "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO- --tries=3 "$url"
  else
    fail "未找到 curl 或 wget"
  fi
}

download_file() {
  local url="$1"
  local dest="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fL --retry 3 --retry-delay 2 "$url" -o "$dest"
  elif command -v wget >/dev/null 2>&1; then
    wget --tries=3 -O "$dest" "$url"
  else
    fail "未找到 curl 或 wget"
  fi
}

download_optional_file() {
  local url="$1"
  local dest="$2"
  rm -f "$dest"
  if command -v curl >/dev/null 2>&1; then
    curl -fL --retry 3 --retry-delay 2 "$url" -o "$dest"
  elif command -v wget >/dev/null 2>&1; then
    wget --tries=3 -O "$dest" "$url"
  else
    fail "未找到 curl 或 wget"
  fi
}

sha256_file() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print tolower($1)}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print tolower($1)}'
  else
    fail "未找到 sha256sum 或 shasum，无法校验下载完整性"
  fi
}

verify_asset_checksum() {
  local asset="$1"
  local archive="$2"
  local sums_file="$3"
  local expected
  expected=$(awk -v f="$asset" '$2 == f { print tolower($1); found=1; exit } END { if (!found) exit 1 }' "$sums_file") || \
    fail "SHA256SUMS 中未找到 $asset 的校验值"
  local actual
  actual=$(sha256_file "$archive")
  [ "$actual" = "$expected" ] || fail "下载完整性校验失败: $asset"
}

verify_release_provenance() {
  local asset_path="$1"
  local bundle_path="$2"
  if [ "$VERIFY_ATTESTATION" = "false" ]; then
    echo "警告: 已显式关闭 Agent provenance 验证。" >&2
    return 0
  fi
  [ "$VERIFY_ATTESTATION" = "true" ] || fail "ZENO_VERIFY_ATTESTATION 必须是 true 或 false"

  local gh_version="2.65.0"
  local verifier_os verifier_arch verifier_ext verifier_sha
  case "$GOOS/$GOARCH" in
    linux/amd64) verifier_os="linux"; verifier_arch="amd64"; verifier_ext="tar.gz"; verifier_sha="762569efe785082b7d1feb06995efece1a9cecce16da8503ac6fdbcbea04085b" ;;
    linux/arm64) verifier_os="linux"; verifier_arch="arm64"; verifier_ext="tar.gz"; verifier_sha="8bcec9f3ee5c7c3700359a75da774c71221064a0ba017537795aa32ac8bbb481" ;;
    linux/arm) verifier_os="linux"; verifier_arch="armv6"; verifier_ext="tar.gz"; verifier_sha="72b4949ba83a19938b486c9ec58b23c97d6ec1f17f613084c163503dd3bb0b8d" ;;
    darwin/amd64) verifier_os="macOS"; verifier_arch="amd64"; verifier_ext="zip"; verifier_sha="0d33a2b5263304e9110051e3ec6b710b26f37cb10170031c1a79a81d2d9a871b" ;;
    darwin/arm64) verifier_os="macOS"; verifier_arch="arm64"; verifier_ext="zip"; verifier_sha="5acb7110fa6f18d2e1a7bea41526bb8532584f4a10067b40217488bf9f3ad9ab" ;;
    *) fail "当前平台不支持 provenance 验证: $GOOS/$GOARCH" ;;
  esac
  local verifier_archive="gh_${gh_version}_${verifier_os}_${verifier_arch}.${verifier_ext}"
  local verifier_url="https://github.com/cli/cli/releases/download/v${gh_version}/${verifier_archive}"
  download_file "$verifier_url" "$TMP/$verifier_archive"
  [ "$(sha256_file "$TMP/$verifier_archive")" = "$verifier_sha" ] || fail "provenance verifier 校验失败"
  local verifier_dir="$TMP/provenance-verifier"
  mkdir -p "$verifier_dir"
  if [ "$verifier_ext" = "zip" ]; then
    need unzip
    unzip -q "$TMP/$verifier_archive" -d "$verifier_dir"
  else
    tar -xzf "$TMP/$verifier_archive" -C "$verifier_dir"
  fi
  local verifier
  verifier=$(find "$verifier_dir" -type f -path '*/bin/gh' | head -n1)
  [ -n "$verifier" ] || fail "provenance verifier 缺少可执行文件"
  chmod 700 "$verifier"
  local certificate_identity="https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/${VERSION}"
  local verify_args=(
    attestation verify "$asset_path"
    --repo "$REPO"
    --cert-identity "$certificate_identity"
    --deny-self-hosted-runners
  )
  if [ -s "$bundle_path" ]; then
    if "$verifier" "${verify_args[@]}" --bundle "$bundle_path" >/dev/null; then
      return 0
    fi
    # A release bundle is only a transport for GitHub's signed attestation.
    # Retrying against GitHub's attestation API preserves fail-closed
    # verification while allowing recovery from a corrupt bundle mirror.
    echo "警告: Release provenance bundle 验证失败，改用 GitHub attestation API 重试。" >&2
  fi
  "$verifier" "${verify_args[@]}" >/dev/null || fail "Agent provenance 验证失败"
}

reject_systemd_arg() {
  case "$1" in
    *$'\n'*|*$'\r'*) fail "systemd 参数包含非法换行" ;;
  esac
}

systemd_escape_arg() {
  local value="$1"
  reject_systemd_arg "$value"
  value=${value//\\/\\\\}
  value=${value//\"/\\\"}
  value=${value//%/%%}
  value=${value//\$/\$\$}
  printf '"%s"' "$value"
}

systemd_join_args() {
  local first=1
  local arg
  for arg in "$@"; do
    if [ "$first" -eq 0 ]; then
      printf ' '
    fi
    first=0
    systemd_escape_arg "$arg"
  done
}

xml_escape() {
  printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g'
}

is_decimal_octet() {
  local octet="$1"
  case "$octet" in
    ''|*[!0-9]*) return 1 ;;
  esac
  [ "${#octet}" -le 3 ] || return 1
  local value=$((10#$octet))
  [ "$value" -ge 0 ] && [ "$value" -le 255 ]
}

is_ipv4_loopback() {
  local value="$1"
  local a b c d extra
  IFS=. read -r a b c d extra <<<"$value"
  [ -z "${extra:-}" ] || return 1
  is_decimal_octet "$a" && is_decimal_octet "$b" && is_decimal_octet "$c" && is_decimal_octet "$d" || return 1
  [ "$((10#$a))" -eq 127 ]
}

is_ipv4_literal() {
  local value="$1"
  local a b c d extra
  IFS=. read -r a b c d extra <<<"$value"
  [ -z "${extra:-}" ] || return 1
  is_decimal_octet "$a" && is_decimal_octet "$b" && is_decimal_octet "$c" && is_decimal_octet "$d"
}

is_hex16() {
  local value="$1"
  case "$value" in
    ''|*[!0-9a-fA-F]*) return 1 ;;
  esac
  [ "${#value}" -le 4 ]
}

is_ipv4_mapped_hex_loopback() {
  local value="$1"
  local high low extra
  IFS=: read -r high low extra <<<"$value"
  [ -z "${extra:-}" ] || return 1
  is_hex16 "$high" && is_hex16 "$low" || return 1
  local high_value=$((16#$high))
  (( high_value >= 0x7f00 && high_value <= 0x7fff ))
}

is_ipv4_mapped_loopback() {
  local value="$1"
  local suffix=""
  case "$value" in
    ::ffff:*) suffix="${value#::ffff:}" ;;
    0:0:0:0:0:ffff:*) suffix="${value#0:0:0:0:0:ffff:}" ;;
    0000:0000:0000:0000:0000:ffff:*) suffix="${value#0000:0000:0000:0000:0000:ffff:}" ;;
    *) return 1 ;;
  esac
  is_ipv4_loopback "$suffix" || is_ipv4_mapped_hex_loopback "$suffix"
}

controller_url_host() {
  local authority="$1"
  local host rest
  if [[ "$authority" == \[* ]]; then
    rest="${authority#\[}"
    host="${rest%%]*}"
    [ "$host" != "$rest" ] || return 1
    rest="${rest#"$host"}"
    rest="${rest#]}"
    case "$rest" in
      ''|:*) printf '%s' "$host" ;;
      *) return 1 ;;
    esac
    return 0
  fi
  host="${authority%%:*}"
  [ -n "$host" ] || return 1
  printf '%s' "$host"
}

controller_url_has_explicit_port() {
  local authority="$1"
  local port
  if [[ "$authority" == \[* ]]; then
    local rest="${authority#*]}"
    case "$rest" in
      :*) port="${rest#:}" ;;
      *) return 1 ;;
    esac
  else
    case "$authority" in
      *:*) port="${authority##*:}" ;;
      *) return 1 ;;
    esac
  fi
  case "$port" in
    ''|*[!0-9]*) return 1 ;;
  esac
  [ "$port" -ge 1 ] && [ "$port" -le 65535 ]
}

validate_controller_url() {
  local value="$1"
  case "$value" in
    *'?'*|*'#'*) fail "ZENO_CONTROLLER_URL 不能包含查询参数或片段" ;;
  esac
  local authority="${value#*://}"
  authority="${authority%%/*}"
  [ -n "$authority" ] || fail "ZENO_CONTROLLER_URL 缺少主机"
  case "$authority" in
    *@*) fail "ZENO_CONTROLLER_URL 不能包含凭据" ;;
    :*) fail "ZENO_CONTROLLER_URL 缺少主机" ;;
  esac
  case "$value" in
    https://*) return 0 ;;
    http://*)
      local host
      host=$(controller_url_host "$authority") || fail "ZENO_CONTROLLER_URL 缺少主机"
      local normalized_host="${host,,}"
      local localhost_host="${normalized_host%.}"
      if [ "$localhost_host" = "localhost" ]; then
        return 0
      fi
      if [ "$normalized_host" = "::1" ] || is_ipv4_loopback "$normalized_host" || is_ipv4_mapped_loopback "$normalized_host"; then
        return 0
      fi
      if controller_url_has_explicit_port "$authority" && { is_ipv4_literal "$normalized_host" || [[ "$normalized_host" == *:* ]]; }; then
        return 0
      fi
      fail "远程 ZENO_CONTROLLER_URL 必须使用 https"
      ;;
    *) fail "ZENO_CONTROLLER_URL 必须使用 http 或 https" ;;
  esac
}

json_escape() {
  local value="$1"
  if [[ "$value" =~ [[:cntrl:]] ]]; then
    fail "enrollment 字段包含非法控制字符"
  fi
  value=${value//\\/\\\\}
  value=${value//\"/\\\"}
  printf '%s' "$value"
}

generate_runtime_token() {
  local generated
  generated=$(LC_ALL=C od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
  [ "${#generated}" -eq 64 ] || fail "生成 Agent runtime token 失败"
  case "$generated" in
    *[!0-9a-f]*) fail "生成 Agent runtime token 失败" ;;
  esac
  printf '%s' "$generated"
}

exchange_agent_enrollment() {
  local runtime_token="$1"
  local endpoint="${CONTROLLER_URL%/}/api/agent/v1/enroll"
  local node_json enrollment_json runtime_json
  node_json=$(json_escape "$NODE_ID")
  enrollment_json=$(json_escape "$ENROLLMENT_TOKEN")
  runtime_json=$(json_escape "$runtime_token")
  # Send the credential body on stdin rather than curl's argv. Enrollment is
  # deliberately not retried: a successful exchange consumes it once; after
  # an ambiguous network failure the administrator must issue a new command.
  if ! printf '{"node_id":"%s","enrollment_token":"%s","runtime_token":"%s"}' "$node_json" "$enrollment_json" "$runtime_json" | \
      curl -fsS --connect-timeout 10 --max-time 30 \
        -H 'Content-Type: application/json' \
        -H 'Accept: application/json' \
        --data-binary @- \
        -o /dev/null \
        "$endpoint"; then
    fail "一次性 enrollment token 兑换失败；请重新生成安装命令"
  fi
}

atomic_install_binary() {
  local source="$1"
  local dest="$2"
  local backup_var="$3"
  local dest_dir
  dest_dir=$(dirname "$dest")
  local dest_base
  dest_base=$(basename "$dest")
  local new_bin="$dest_dir/.${dest_base}.new.$$"
  local backup=""
  install -m 755 "$source" "$new_bin"
  if [ -e "$dest" ]; then
    backup="$dest.bak-$(date -u +%Y%m%d%H%M%S)"
    cp -p "$dest" "$backup"
  fi
  mv -f "$new_bin" "$dest"
  printf -v "$backup_var" '%s' "$backup"
}

restore_binary_backup() {
  local backup="$1"
  local dest="$2"
  if [ -z "$backup" ] || [ ! -f "$backup" ]; then
    echo "旧二进制备份不存在，无法恢复: $backup" >&2
    return 1
  fi
  local dest_dir
  dest_dir=$(dirname "$dest")
  local dest_base
  dest_base=$(basename "$dest")
  local restore_tmp="$dest_dir/.${dest_base}.restore.$$"
  rm -f "$restore_tmp"
  if ! cp -p "$backup" "$restore_tmp"; then
    rm -f "$restore_tmp"
    echo "复制旧二进制备份失败，备份仍保留: $backup" >&2
    return 1
  fi
  if ! mv -f "$restore_tmp" "$dest"; then
    rm -f "$restore_tmp"
    echo "原子恢复旧二进制失败，备份仍保留: $backup" >&2
    return 1
  fi
  if [ "$(sha256_file "$backup")" != "$(sha256_file "$dest")" ]; then
    echo "旧二进制恢复校验失败，备份仍保留: $backup" >&2
    return 1
  fi
}

stop_linux_service_for_restore() {
  if ! command -v systemctl >/dev/null 2>&1; then
    return 0
  fi
  systemctl stop "$SERVICE_NAME.service" >/dev/null 2>&1 || true
  local i=0
  while [ "$i" -lt 30 ]; do
    if ! systemctl is-active --quiet "$SERVICE_NAME.service" 2>/dev/null; then
      return 0
    fi
    sleep 0.5
    i=$((i + 1))
  done
  echo "服务 $SERVICE_NAME 停止超时，拒绝覆盖旧二进制" >&2
  return 1
}

stop_macos_service_for_restore() {
  if ! command -v launchctl >/dev/null 2>&1; then
    return 0
  fi
  launchctl bootout system/li.shuijiao.zeno-agent >/dev/null 2>&1 || \
    launchctl bootout system "$service_config" >/dev/null 2>&1 || true
  local i=0
  while [ "$i" -lt 30 ]; do
    if ! launchctl print system/li.shuijiao.zeno-agent >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.5
    i=$((i + 1))
  done
  echo "服务 li.shuijiao.zeno-agent 停止超时，拒绝覆盖旧二进制" >&2
  return 1
}

restore_file_backup_atomic() {
  local backup="$1"
  local dest="$2"
  local label="$3"
  if [ -z "$backup" ] || [ ! -f "$backup" ]; then
    echo "$label 备份不存在，无法恢复: $backup" >&2
    return 1
  fi
  local dest_dir
  dest_dir=$(dirname "$dest")
  local dest_base
  dest_base=$(basename "$dest")
  local restore_tmp="$dest_dir/.${dest_base}.restore.$$"
  rm -f "$restore_tmp"
  if ! cp -p "$backup" "$restore_tmp"; then
    rm -f "$restore_tmp"
    echo "$label 备份复制失败，备份仍保留: $backup" >&2
    return 1
  fi
  if ! mv -f "$restore_tmp" "$dest"; then
    rm -f "$restore_tmp"
    echo "$label 原子恢复失败，备份仍保留: $backup" >&2
    return 1
  fi
}

reject_symlink_path() {
  local path="$1"
  local label="$2"
  if [ -L "$path" ]; then
    fail "$label 不能是符号链接: $path"
  fi
}

assert_regular_file_or_absent() {
  local path="$1"
  local label="$2"
  reject_symlink_path "$path" "$label"
  if [ -e "$path" ] && [ ! -f "$path" ]; then
    fail "$label 必须是普通文件: $path"
  fi
}

token_owner_group() {
  case "$GOOS" in
    darwin) printf 'root:wheel' ;;
    linux) printf 'root:root' ;;
    *) fail "暂不支持系统: $GOOS" ;;
  esac
}

token_expected_owner_mode() {
  case "$GOOS" in
    darwin) printf '0:0:600' ;;
    linux) printf '0:0:600' ;;
    *) fail "暂不支持系统: $GOOS" ;;
  esac
}

file_owner_mode() {
  local path="$1"
  case "$GOOS" in
    darwin) stat -f '%u:%g:%Lp' "$path" ;;
    linux) stat -c '%u:%g:%a' "$path" ;;
    *) fail "暂不支持系统: $GOOS" ;;
  esac
}

assert_token_file_secure() {
  reject_symlink_path "$TOKEN_FILE" "token 文件"
  local actual
  actual=$(file_owner_mode "$TOKEN_FILE")
  local expected
  expected=$(token_expected_owner_mode)
  [ "$actual" = "$expected" ] || fail "token 文件 owner/mode 不安全: $actual，期望 $expected ($(token_owner_group))"
}

set_token_owner_mode() {
  local path="$1"
  reject_symlink_path "$path" "token 文件"
  chown "$(token_owner_group)" "$path"
  chmod 600 "$path"
}

restore_token_backup() {
  restore_file_backup_atomic "$backup_token" "$TOKEN_FILE" "token 文件" || return 1
  set_token_owner_mode "$TOKEN_FILE" || return 1
  assert_token_file_secure
}

write_token_file() {
  reject_symlink_path "$TOKEN_FILE" "token 文件"
  if [ -n "$TOKEN" ]; then
    local token_dir
    token_dir=$(dirname "$TOKEN_FILE")
    local tmp_token="$token_dir/.agent-token.tmp.$$"
    rm -f "$tmp_token"
    umask 077
    if ! printf '%s\n' "$TOKEN" > "$tmp_token"; then
      rm -f "$tmp_token"
      fail "写入临时 token 文件失败"
    fi
    set_token_owner_mode "$tmp_token"
    mv -f "$tmp_token" "$TOKEN_FILE"
  else
    [ -f "$TOKEN_FILE" ] || fail "已有 token 路径不是普通文件: $TOKEN_FILE"
  fi
  set_token_owner_mode "$TOKEN_FILE"
  assert_token_file_secure
}

install_linux_service() {
  local backup_bin="$1"
  local exec_start
  exec_start=$(systemd_join_args \
    "$BIN" \
    -controller-url "$CONTROLLER_URL" \
    -node-id "$NODE_ID" \
    -token-file "$TOKEN_FILE" \
    -state-interval "$STATE_INTERVAL" \
    -heartbeat-interval "$HEARTBEAT_INTERVAL" \
    -host-interval "$HOST_INTERVAL" \
    -identity-refresh-interval "$IDENTITY_REFRESH_INTERVAL" \
    -version "$VERSION" \
    "${extra_args[@]}")

  local unit="/etc/systemd/system/${SERVICE_NAME}.service"
  local unit_tmp="${unit}.tmp.$$"
  local unit_backup=""
  service_kind="linux"
  service_config="$unit"
  service_enable_state=$(systemctl is-enabled "$SERVICE_NAME.service" 2>/dev/null || true)
  if systemctl is-active --quiet "$SERVICE_NAME.service" 2>/dev/null; then
    service_was_active=1
  else
    service_was_active=0
  fi
  if [ -f "$unit" ]; then
    service_config_existed=1
    unit_backup="$unit.bak-$(date -u +%Y%m%d%H%M%S)"
    cp -p "$unit" "$unit_backup"
    service_config_backup="$unit_backup"
  fi

  cat > "$unit_tmp" <<EOF_SERVICE
[Unit]
Description=Zeno Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$exec_start
Restart=always
RestartSec=5s
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=full
ProtectHome=read-only
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
ProtectKernelLogs=true
LockPersonality=true
RestrictRealtime=true
RestrictNamespaces=true
SystemCallArchitectures=native
MemoryDenyWriteExecute=true
CapabilityBoundingSet=CAP_NET_RAW
AmbientCapabilities=CAP_NET_RAW
UMask=0077

[Install]
WantedBy=multi-user.target
EOF_SERVICE
  mv -f "$unit_tmp" "$unit"
  chown root:root "$unit"
  chmod 644 "$unit"

  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME.service" >/dev/null
  if ! systemctl restart "$SERVICE_NAME.service" || ! systemctl is-active --quiet "$SERVICE_NAME.service"; then
    fail "Zeno Agent 启动失败，准备回滚到旧二进制"
  fi
}

install_macos_service() {
  local backup_bin="$1"
  local plist="/Library/LaunchDaemons/li.shuijiao.zeno-agent.plist"
  local plist_tmp="${plist}.tmp.$$"
  local plist_backup=""
  service_kind="darwin"
  service_config="$plist"
  if launchctl print-disabled system 2>/dev/null | grep -Eq '"li\.shuijiao\.zeno-agent"[[:space:]]*=>[[:space:]]*true'; then
    service_was_enabled=0
  else
    service_was_enabled=1
  fi
  if launchctl print system/li.shuijiao.zeno-agent >/dev/null 2>&1; then
    service_was_active=1
  else
    service_was_active=0
  fi
  if [ -f "$plist" ]; then
    service_config_existed=1
    plist_backup="$plist.bak-$(date -u +%Y%m%d%H%M%S)"
    cp -p "$plist" "$plist_backup"
    service_config_backup="$plist_backup"
  fi

  local plist_extra_args=""
  local arg
  for arg in "${extra_args[@]}"; do
    plist_extra_args="${plist_extra_args}    <string>$(xml_escape "$arg")</string>
"
  done

  cat > "$plist_tmp" <<EOF_PLIST
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
    <string>-state-interval</string><string>$(xml_escape "$STATE_INTERVAL")</string>
    <string>-heartbeat-interval</string><string>$(xml_escape "$HEARTBEAT_INTERVAL")</string>
    <string>-host-interval</string><string>$(xml_escape "$HOST_INTERVAL")</string>
    <string>-identity-refresh-interval</string><string>$(xml_escape "$IDENTITY_REFRESH_INTERVAL")</string>
    <string>-version</string><string>$(xml_escape "$VERSION")</string>
${plist_extra_args}
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Background</string>
  <key>LowPriorityIO</key><true/>
  <key>Umask</key><integer>63</integer>
  <key>StandardOutPath</key><string>/var/log/zeno-agent.log</string>
  <key>StandardErrorPath</key><string>/var/log/zeno-agent.err.log</string>
</dict>
</plist>
EOF_PLIST
  plutil -lint "$plist_tmp" >/dev/null || fail "LaunchDaemon 配置校验失败，未停止旧服务"
  mv -f "$plist_tmp" "$plist"
  chown root:wheel "$plist"
  chmod 644 "$plist"
  launchctl bootout system "$plist" >/dev/null 2>&1 || true
  if [ "$service_was_enabled" -eq 0 ]; then
    launchctl enable system/li.shuijiao.zeno-agent >/dev/null
  fi
  launchctl bootstrap system "$plist" || fail "Zeno Agent 启动失败，准备回滚到旧二进制"
  launchctl kickstart -k system/li.shuijiao.zeno-agent >/dev/null
  if ! launchctl print system/li.shuijiao.zeno-agent >/dev/null 2>&1; then
    fail "Zeno Agent 启动状态验证失败，准备回滚到旧二进制"
  fi
}

[ -n "$CONTROLLER_URL" ] || fail "必须设置 ZENO_CONTROLLER_URL"
[ -n "$NODE_ID" ] || fail "必须设置 ZENO_NODE_ID"
[ -z "$TOKEN" ] || [ -z "$ENROLLMENT_TOKEN" ] || fail "ZENO_AGENT_TOKEN 与 ZENO_ENROLLMENT_TOKEN 不能同时设置"
validate_controller_url "$CONTROLLER_URL"

need uname
need sed
need tar
need mktemp
need awk
need date
need find
need grep
need stat
need od
need tr

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)
case "$OS" in
  linux)
    GOOS=linux
    need systemctl
    ;;
  darwin)
    GOOS=darwin
    need plutil
    need launchctl
    ;;
  *) fail "暂不支持系统: $OS" ;;
esac
case "$ARCH" in
  x86_64|amd64) GOARCH=amd64 ;;
  aarch64|arm64) GOARCH=arm64 ;;
  armv7l|armv6l) GOARCH=arm ;;
  *) fail "暂不支持架构: $ARCH" ;;
esac

if [ "$VERSION" = "latest" ]; then
  VERSION=$(download_stdout "https://api.github.com/repos/$REPO/releases/latest" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)
  [ -n "$VERSION" ] || fail "无法获取最新版本"
fi
[[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9][A-Za-z0-9.-]*)?$ ]] || fail "版本标签格式无效: $VERSION"

ASSET="zeno-agent_${GOOS}_${GOARCH}.tar.gz"
URL="https://github.com/$REPO/releases/download/$VERSION/$ASSET"
SUMS_URL="https://github.com/$REPO/releases/download/$VERSION/SHA256SUMS"
PROVENANCE_ASSET="zeno-agent_provenance.sigstore.json"
PROVENANCE_URL="https://github.com/$REPO/releases/download/$VERSION/$PROVENANCE_ASSET"
TMP=$(mktemp -d)
install_started=0
install_committed=0
had_existing_binary=0
had_existing_token=0
backup_bin=""
backup_token=""
service_kind=""
service_config=""
service_config_backup=""
service_config_existed=0
service_enable_state=""
service_was_enabled=0
service_was_active=0
enrollment_token_installed=0

cleanup() {
  local status=$?
  local cleanup_status=$status
  local can_restore_binary=1
  if [ "$status" -ne 0 ] && [ "$install_started" -eq 1 ] && [ "$install_committed" -eq 0 ]; then
    if [ "$service_kind" = "linux" ]; then
      if ! stop_linux_service_for_restore; then
        cleanup_status=1
        can_restore_binary=0
      fi
      if ! systemctl disable "$SERVICE_NAME.service" >/dev/null 2>&1; then
        echo "清理安装器创建的 systemd enable 链接失败" >&2
        cleanup_status=1
      fi
    elif [ "$service_kind" = "darwin" ]; then
      if ! stop_macos_service_for_restore; then
        cleanup_status=1
        can_restore_binary=0
      fi
    fi
    if [ "$had_existing_binary" -eq 1 ]; then
      if [ -n "$backup_bin" ]; then
        if [ "$can_restore_binary" -eq 0 ]; then
          echo "服务未确认停止，未覆盖恢复旧二进制；备份仍保留: $backup_bin" >&2
        elif ! restore_binary_backup "$backup_bin" "$BIN"; then
          echo "旧二进制恢复失败，备份仍保留: $backup_bin" >&2
          cleanup_status=1
        fi
      fi
    else
      rm -f "$BIN" 2>/dev/null || true
    fi
    if [ "$enrollment_token_installed" -eq 0 ]; then
      if [ "$had_existing_token" -eq 1 ]; then
        if ! restore_token_backup; then
          echo "token 文件恢复失败，备份仍保留: $backup_token" >&2
          cleanup_status=1
        fi
      else
        if ! rm -f "$TOKEN_FILE" 2>/dev/null; then
          echo "移除新 token 文件失败: $TOKEN_FILE" >&2
          cleanup_status=1
        fi
      fi
    fi
    if [ -n "$service_config" ]; then
      if [ "$service_config_existed" -eq 1 ]; then
        if ! restore_file_backup_atomic "$service_config_backup" "$service_config" "服务配置"; then
          echo "服务配置恢复失败: $service_config_backup -> $service_config" >&2
          cleanup_status=1
        else
          if [ "$service_kind" = "linux" ]; then
            chown root:root "$service_config" || cleanup_status=1
            chmod 644 "$service_config" || cleanup_status=1
          elif [ "$service_kind" = "darwin" ]; then
            chown root:wheel "$service_config" || cleanup_status=1
            chmod 644 "$service_config" || cleanup_status=1
          fi
        fi
      else
        if ! rm -f "$service_config" 2>/dev/null; then
          echo "移除新服务配置失败: $service_config" >&2
          cleanup_status=1
        fi
      fi
      if [ "$service_kind" = "linux" ]; then
        if ! systemctl daemon-reload >/dev/null 2>&1; then
          echo "systemd daemon-reload 失败" >&2
          cleanup_status=1
        fi
        if systemctl list-unit-files "$SERVICE_NAME.service" >/dev/null 2>&1 || [ -n "$service_enable_state" ] || [ "$service_was_active" -eq 1 ]; then
          case "$service_enable_state" in
            enabled)
              if ! systemctl enable "$SERVICE_NAME.service" >/dev/null 2>&1; then
                echo "恢复 systemd enabled 状态失败" >&2
                cleanup_status=1
              fi
              ;;
            enabled-runtime)
              if ! systemctl enable --runtime "$SERVICE_NAME.service" >/dev/null 2>&1; then
                echo "恢复 systemd enabled-runtime 状态失败" >&2
                cleanup_status=1
              fi
              ;;
            masked)
              if ! systemctl mask "$SERVICE_NAME.service" >/dev/null 2>&1; then
                echo "恢复 systemd masked 状态失败" >&2
                cleanup_status=1
              fi
              ;;
            masked-runtime)
              if ! systemctl mask --runtime "$SERVICE_NAME.service" >/dev/null 2>&1; then
                echo "恢复 systemd masked-runtime 状态失败" >&2
                cleanup_status=1
              fi
              ;;
            ''|disabled|static|indirect|generated|transient|alias|not-found)
              ;;
            *)
              echo "无法精确恢复未知 systemd enable 状态: $service_enable_state" >&2
              cleanup_status=1
              ;;
          esac
          if [ "$service_was_active" -eq 1 ]; then
            if ! systemctl restart "$SERVICE_NAME.service" >/dev/null 2>&1; then
              echo "恢复 systemd active 状态失败" >&2
              cleanup_status=1
            fi
          else
            systemctl stop "$SERVICE_NAME.service" >/dev/null 2>&1 || true
          fi
        fi
      elif [ "$service_kind" = "darwin" ]; then
        if [ "$service_was_enabled" -eq 0 ]; then
          if ! launchctl disable system/li.shuijiao.zeno-agent >/dev/null 2>&1; then
            echo "恢复 launchd disabled 状态失败" >&2
            cleanup_status=1
          fi
        fi
        if [ "$service_was_active" -eq 1 ]; then
          if ! launchctl bootstrap system "$service_config" >/dev/null 2>&1; then
            echo "恢复 launchd active 状态失败" >&2
            cleanup_status=1
          fi
        fi
      fi
    fi
  fi
  if [ "$status" -eq 0 ] && [ -n "$backup_token" ]; then
    rm -f "$backup_token" 2>/dev/null || true
  fi
  rm -rf "$TMP"
  return "$cleanup_status"
}
trap cleanup EXIT

echo "下载 Zeno Agent $VERSION ($GOOS/$GOARCH)..."
download_file "$URL" "$TMP/$ASSET"
download_file "$SUMS_URL" "$TMP/SHA256SUMS"
verify_asset_checksum "$ASSET" "$TMP/$ASSET" "$TMP/SHA256SUMS"
if [ "$VERIFY_ATTESTATION" = "true" ]; then
  if ! download_optional_file "$PROVENANCE_URL" "$TMP/$PROVENANCE_ASSET"; then
    rm -f "$TMP/$PROVENANCE_ASSET"
    echo "警告: Release 未提供 provenance bundle，改用 GitHub attestation API 验证。" >&2
  fi
fi
verify_release_provenance "$TMP/$ASSET" "$TMP/$PROVENANCE_ASSET"

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
reject_symlink_path "$TOKEN_FILE" "token 文件"
[ -n "$TOKEN" ] || [ -n "$ENROLLMENT_TOKEN" ] || [ -s "$TOKEN_FILE" ] || fail "必须设置 ZENO_ENROLLMENT_TOKEN、ZENO_AGENT_TOKEN 或提供已有 token 文件"

extra_args=()
if [ -n "$NETWORK_INTERFACES" ]; then
  extra_args+=("-network-interfaces" "$NETWORK_INTERFACES")
fi
if [ -n "$DISK_MOUNTS" ]; then
  extra_args+=("-disk-mounts" "$DISK_MOUNTS")
fi

install -d -m 755 "$(dirname "$BIN")" "$INSTALL_DIR" "$(dirname "$TOKEN_FILE")"
assert_regular_file_or_absent "$BIN" "Agent 二进制"
if [ "$GOOS" = "darwin" ]; then
  assert_regular_file_or_absent "/Library/LaunchDaemons/li.shuijiao.zeno-agent.plist" "LaunchDaemon 配置"
else
  assert_regular_file_or_absent "/etc/systemd/system/${SERVICE_NAME}.service" "systemd unit"
  current_enable_state=$(systemctl is-enabled "$SERVICE_NAME.service" 2>/dev/null || true)
  case "$current_enable_state" in
    masked|masked-runtime) fail "服务当前为 $current_enable_state；请先明确解除 mask 后再安装" ;;
  esac
fi
if [ -e "$BIN" ]; then
  had_existing_binary=1
fi
if [ -e "$TOKEN_FILE" ]; then
  reject_symlink_path "$TOKEN_FILE" "token 文件"
  [ -f "$TOKEN_FILE" ] || fail "已有 token 路径不是普通文件: $TOKEN_FILE"
  had_existing_token=1
  backup_token=$(mktemp "$(dirname "$TOKEN_FILE")/.agent-token.backup.XXXXXXXXXX")
  cp -p "$TOKEN_FILE" "$backup_token"
  set_token_owner_mode "$backup_token"
fi
install_started=1
if [ -n "$ENROLLMENT_TOKEN" ]; then
  need curl
  TOKEN=$(generate_runtime_token)
  # Prove that the runtime token can be persisted before consuming the
  # one-time enrollment credential. A failed exchange is then rolled back to
  # the prior token; a successful exchange keeps this new token on any later
  # installer failure so the restored service can promote it.
  write_token_file
  exchange_agent_enrollment "$TOKEN"
  enrollment_token_installed=1
  # The new token is the only credential the service may need after its first
  # authenticated request promotes it. Do not retain the old runtime token as
  # an installer backup, and do not roll the new file back on later failures.
  if [ -n "$backup_token" ]; then
    rm -f "$backup_token"
    backup_token=""
  fi
  ENROLLMENT_TOKEN=""
else
  write_token_file
fi
atomic_install_binary "$FOUND" "$BIN" backup_bin

if [ "$GOOS" = "darwin" ]; then
  install_macos_service "$backup_bin"
else
  install_linux_service "$backup_bin"
fi
install_committed=1

if [ -n "$backup_bin" ]; then
  echo "已保留旧二进制: $backup_bin"
fi
echo "Zeno Agent 已安装并启动: node=$NODE_ID version=$VERSION"
