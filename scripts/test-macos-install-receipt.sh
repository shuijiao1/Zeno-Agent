#!/usr/bin/env bash
set -euo pipefail
[ "$(uname -s)" = Darwin ] || { echo 'SKIP: macOS only'; exit 0; }
[ "$(id -u)" -eq 0 ] || { echo 'SKIP: requires root'; exit 0; }
command -v go >/dev/null && command -v python3 >/dev/null || { echo 'SKIP: go/python3 unavailable'; exit 0; }
repo=$(cd "$(dirname "$0")/.." && pwd); cd "$repo"
tmp=$(mktemp -d); label="li.shuijiao.zeno-agent.receipt-harness.$$"
plist="/Library/LaunchDaemons/$label.plist"; nonce=$(openssl rand -hex 32)
receipt="/var/tmp/$label-$nonce"; port_file="$tmp/port"; server_pid=''
cleanup() {
  launchctl bootout "system/$label" >/dev/null 2>&1 || true
  rm -f "$plist" "$receipt"
  [ -z "$server_pid" ] || kill "$server_pid" >/dev/null 2>&1 || true
  rm -rf "$tmp"
}
trap cleanup EXIT
cat >"$tmp/server.py" <<'PY'
import http.server, pathlib, sys
class H(http.server.BaseHTTPRequestHandler):
 def do_POST(self):
  ok=self.headers.get('X-Node-ID')=='receipt-harness' and self.headers.get('Authorization')=='Bearer fixture-only-token'
  self.send_response(204 if ok else 401); self.end_headers()
 def log_message(self,*_): pass
s=http.server.ThreadingHTTPServer(('127.0.0.1',0),H); pathlib.Path(sys.argv[1]).write_text(str(s.server_port)); s.serve_forever()
PY
python3 "$tmp/server.py" "$port_file" & server_pid=$!
for _ in {1..50}; do [ -s "$port_file" ] && break; sleep .1; done
port=$(cat "$port_file"); printf '%s\n' fixture-only-token >"$tmp/token"; chmod 644 "$tmp/token"; chmod 755 "$tmp"
go build -o "$tmp/zeno-agent" ./cmd/zeno-agent
cat >"$plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict>
<key>Label</key><string>$label</string><key>UserName</key><string>_nobody</string><key>RunAtLoad</key><true/><key>ProgramArguments</key><array>
<string>$tmp/zeno-agent</string><string>-controller-url</string><string>http://127.0.0.1:$port</string><string>-node-id</string><string>receipt-harness</string><string>-token-file</string><string>$tmp/token</string><string>-state-interval</string><string>1s</string><string>-heartbeat-interval</string><string>1s</string><string>-install-receipt-file</string><string>$receipt</string><string>-install-receipt-nonce</string><string>$nonce</string>
</array></dict></plist>
EOF
chown root:wheel "$plist"; chmod 644 "$plist"; plutil -lint "$plist" >/dev/null
launchctl bootstrap system "$plist"
for _ in {1..30}; do [ -f "$receipt" ] && break; sleep 1; done
[ "$(cat "$receipt")" = "zeno-agent-install-receipt-v1 $nonce" ]
uid=$(id -u _nobody); [ "$(stat -f %u "$receipt")" = "$uid" ]
pid=$(launchctl print "system/$label" | awk '$1=="pid"&&$2=="="{print $3;exit}')
[ "$(ps -o uid= -p "$pid" | tr -d ' ')" = "$uid" ]
echo 'PASS: real launchd low-privilege heartbeat/state receipt verified'
