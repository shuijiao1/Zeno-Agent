#!/usr/bin/env bash
set -euo pipefail
[ "$(uname -s)" = Linux ] || { echo 'SKIP: Linux only'; exit 0; }
[ "$(id -u)" -eq 0 ] || { echo 'SKIP: requires root'; exit 0; }
systemctl show-environment >/dev/null 2>&1 || { echo 'SKIP: systemd is not running'; exit 0; }
command -v go >/dev/null && command -v python3 >/dev/null || { echo 'SKIP: go/python3 unavailable'; exit 0; }

repo=$(cd "$(dirname "$0")/.." && pwd)
cd "$repo"
tmp=$(mktemp -d)
unit="zeno-agent-receipt-harness-$$"
nonce=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
runtime_dir="$unit"
receipt="/run/$runtime_dir/receipt-$nonce"
port_file="$tmp/port"
server_pid=''
cleanup() {
  systemctl stop "$unit.service" >/dev/null 2>&1 || true
  rm -f "/etc/systemd/system/$unit.service"
  systemctl daemon-reload >/dev/null 2>&1 || true
  [ -z "$server_pid" ] || kill "$server_pid" >/dev/null 2>&1 || true
  rm -rf "$tmp"
}
trap cleanup EXIT

cat >"$tmp/server.py" <<'PY'
import http.server, pathlib, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        if self.headers.get('X-Node-ID') != 'receipt-harness' or self.headers.get('Authorization') != 'Bearer fixture-only-token':
            self.send_response(401); self.end_headers(); return
        self.send_response(204); self.end_headers()
    def log_message(self, *_): pass
s=http.server.ThreadingHTTPServer(('127.0.0.1', 0), H)
pathlib.Path(sys.argv[1]).write_text(str(s.server_port))
s.serve_forever()
PY
python3 "$tmp/server.py" "$port_file" & server_pid=$!
for _ in $(seq 1 50); do [ -s "$port_file" ] && break; sleep .1; done
port=$(cat "$port_file")
printf '%s\n' fixture-only-token >"$tmp/token"
chmod 644 "$tmp/token"; chmod 755 "$tmp"
go build -o "$tmp/zeno-agent" ./cmd/zeno-agent
cat >"/etc/systemd/system/$unit.service" <<EOF
[Service]
User=nobody
Group=$(id -gn nobody)
RuntimeDirectory=$runtime_dir
RuntimeDirectoryMode=0700
ExecStart=$tmp/zeno-agent -controller-url http://127.0.0.1:$port -node-id receipt-harness -token-file $tmp/token -state-interval 1s -heartbeat-interval 1s -install-receipt-file $receipt -install-receipt-nonce $nonce
EOF
systemctl daemon-reload
systemctl start "$unit.service"
for _ in $(seq 1 30); do [ -f "$receipt" ] && break; sleep 1; done
[ "$(cat "$receipt")" = "zeno-agent-install-receipt-v1 $nonce" ]
[ "$(stat -c %u "$receipt")" = "$(id -u nobody)" ]
pid=$(systemctl show -p MainPID --value "$unit.service")
[ "$(awk '/^Uid:/{print $2}' "/proc/$pid/status")" = "$(id -u nobody)" ]
echo 'PASS: real systemd low-privilege heartbeat/state receipt verified'
