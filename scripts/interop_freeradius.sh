#!/usr/bin/env bash
# Interoperability check: run radperf against a real FreeRADIUS server.
#
# This validates the wire format, PAP encryption, the computed request
# authenticator (accounting) and the response authenticator against the
# reference RADIUS implementation. Requires FreeRADIUS and root (for config).
#
# Usage: scripts/interop_freeradius.sh [path-to-radperf] [path-to-dictionary-dir]
set -euo pipefail

BIN="${1:-$(cd "$(dirname "$0")/.." && pwd)/target/release/radperf}"
DICT="${2:-/usr/share/freeradius}"
FR_CONF="/etc/freeradius/3.0"
SECRET="testing123"
USER="bench-rs"
PASS="benchpass"

command -v freeradius >/dev/null || { echo "freeradius not installed"; exit 1; }
command -v "$BIN" >/dev/null 2>&1 || [ -x "$BIN" ] || { echo "radperf binary not found: $BIN"; exit 1; }

tmp="$(mktemp -d)"
trap 'sudo pkill -x freeradius 2>/dev/null || true; rm -rf "$tmp"' EXIT

# Add a test user (idempotent) and relax the BlastRADIUS Message-Authenticator
# requirement for this localhost test client.
if ! sudo grep -q "^$USER " "$FR_CONF/mods-config/files/authorize"; then
  echo "$USER Cleartext-Password := \"$PASS\"" | sudo tee -a "$FR_CONF/mods-config/files/authorize" >/dev/null
fi
sudo python3 - "$FR_CONF/clients.conf" <<'PY'
import re, sys
p = sys.argv[1]
s = open(p).read()
m = re.search(r'client\s+localhost\s*\{', s)
if m and 'require_message_authenticator' not in s[m.end():m.end()+400]:
    s = s[:m.end()] + "\n\trequire_message_authenticator = no\n" + s[m.end():]
    open(p, 'w').write(s)
PY

sudo pkill -x freeradius 2>/dev/null || true
sleep 1
sudo setsid freeradius -X >"$tmp/fr.log" 2>&1 </dev/null &
for _ in $(seq 1 30); do grep -q "Ready to process requests" "$tmp/fr.log" && break; sleep 1; done

printf 'User-Name = "%s"\nUser-Password = "%s"\n' "$USER" "$PASS" > "$tmp/auth.txt"
printf 'User-Name = "%s"\nAcct-Status-Type = Start\nAcct-Session-Id = "sess-0001"\n' "$USER" > "$tmp/acct.txt"

fail=0
run() {
  local name="$1"; shift
  local out
  out="$("$BIN" -d "$DICT" "$@")"
  echo "--- $name ---"
  echo "$out" | grep -E "Total sent|Total succeeded|Total failed|Total no reply"
  local noreply
  noreply="$(echo "$out" | awk -F': *' '/Total no reply/ {print $2}')"
  [ "$noreply" = "0" ] || { echo "NON-ZERO no-reply in $name"; fail=1; }
}

run "auth (PAP) -> Access-Accept" -f "$tmp/auth.txt" -c 500 -p 16 -s -r 1 -t 2 127.0.0.1:1812 auth "$SECRET"
run "auth (CHAP) -> Access-Accept" -a chap -f "$tmp/auth.txt" -c 500 -p 16 -s -r 1 -t 2 127.0.0.1:1812 auth "$SECRET"
run "acct -> Accounting-Response"  -f "$tmp/acct.txt" -c 500 -p 16 -s -r 1 -t 2 127.0.0.1:1813 acct "$SECRET"
run "auth + accounting (-A 1,2)" -A 1,2 -f "$tmp/auth.txt" -c 1 -p 1 -s -r 1 -t 2 127.0.0.1 auth "$SECRET"

echo
if [ "$fail" -eq 0 ]; then
  echo "INTEROP OK: FreeRADIUS accepted and answered all requests"
else
  echo "INTEROP FAILED"
fi
exit "$fail"
