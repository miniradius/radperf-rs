#!/usr/bin/env bash
# Verify PAP, CHAP, and accounting against a temporary FreeRADIUS instance.
#
# Usage: scripts/interop_freeradius.sh [path-to-radperf] [path-to-dictionary-dir]
set -euo pipefail
umask 077

BIN="${1:-$(cd "$(dirname "$0")/.." && pwd)/target/release/radperf}"
DICT="${2:-/usr/share/freeradius}"
FR_CONF="/etc/freeradius/3.0"

command -v freeradius >/dev/null || { echo "freeradius not installed" >&2; exit 1; }
command -v "$BIN" >/dev/null 2>&1 || { echo "radperf binary not found: $BIN" >&2; exit 1; }

tmp="$(mktemp -d)"
trap 'sudo -n rm -rf -- "$tmp"' EXIT
chmod 0711 "$tmp"
sudo cp -a "$FR_CONF" "$tmp/conf"

sudo -n python3 - "$tmp/conf" <<'PY'
import os
import re
import sys
from pathlib import Path

root = Path(sys.argv[1]).resolve()

def copied_file(name):
    path = (root / name).resolve()
    if not path.is_relative_to(root):
        raise SystemExit(f"Configuration file points outside the temporary copy: {name}")
    return path

copied_file("clients.conf").write_text(
    "client localhost {\n"
    "    ipaddr = 127.0.0.1\n"
    "    secret = testing123\n"
    "    require_message_authenticator = yes\n"
    "}\n"
    "client localhost_ipv6 {\n"
    "    ipv6addr = ::1\n"
    "    secret = testing123\n"
    "    require_message_authenticator = yes\n"
    "}\n"
)
authorize = copied_file("mods-config/files/authorize")
authorize.write_text('bench-rs Cleartext-Password := "benchpass"\n\n' + authorize.read_text())

site = copied_file("sites-enabled/default")
settings = site.read_text()
settings = re.sub(r"(?m)^([ \t]*ipaddr[ \t]*=[ \t]*)\*", r"\g<1>127.0.0.1", settings)
settings = re.sub(r"(?m)^([ \t]*ipv6addr[ \t]*=[ \t]*)::(?=[ \t]*($|#))", r"\g<1>::1", settings)
site.write_text(settings)

state = root.parent / "state"
state.mkdir(mode=0o750)
os.chown(state, root.stat().st_uid, root.stat().st_gid)
radiusd = copied_file("radiusd.conf")
settings = radiusd.read_text()
for key in ("logdir", "run_dir"):
    settings = re.sub(rf"(?m)^{key}[ \t]*=.*$", f"{key} = {state}", settings)
radiusd.write_text(settings)
PY

python3 - "$BIN" "$DICT" "$tmp" <<'PY'
import json
import subprocess
import sys
import time
from pathlib import Path

binary, dictionary, tmp = sys.argv[1:]
root = Path(tmp)
auth = root / "auth.txt"
wrong_password = root / "wrong-password.txt"
acct = root / "acct.txt"
auth.write_text('User-Name = "bench-rs"\nUser-Password = "benchpass"\n')
wrong_password.write_text('User-Name = "bench-rs"\nUser-Password = "wrong"\n')
acct.write_text('User-Name = "bench-rs"\nAcct-Status-Type = Start\nAcct-Session-Id = "sess-0001"\n')

def run(name, input_file, destination, command, options, succeeded, rejected=0):
    args = [
        binary, "-d", dictionary, "-f", str(input_file), "-j", "-r", "1", "-t", "2",
        *options, destination, command, "testing123",
    ]
    process = subprocess.run(args, capture_output=True, text=True, timeout=30)
    if process.returncode:
        raise SystemExit(f"{name}: radperf exited with {process.returncode}\n{process.stderr}")
    summary = json.loads(process.stdout)
    expected = {
        "total_sent": succeeded + rejected,
        "total_succeeded": succeeded,
        "total_failed": rejected,
        "total_retransmits": 0,
        "total_no_reply": 0,
    }
    actual = {key: int(summary[key]) for key in expected}
    if actual != expected:
        raise SystemExit(f"{name}: expected {expected}, got {actual}")
    print(f"{name}: {succeeded} succeeded, {rejected} rejected, 0 retransmits, 0 timeouts", flush=True)

server_log = root / "freeradius.log"
with server_log.open("w") as log:
    server = subprocess.Popen(
        ["sudo", "-n", "freeradius", "-X", "-d", str(root / "conf")],
        stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
        start_new_session=True,
    )
try:
    for _ in range(100):
        if "Ready to process requests" in server_log.read_text(errors="replace"):
            break
        if server.poll() is not None:
            break
        time.sleep(0.1)
    else:
        raise SystemExit("FreeRADIUS did not start within 10 seconds.")
    if server.poll() is not None:
        log_tail = "\n".join(server_log.read_text(errors="replace").splitlines()[-12:])
        raise SystemExit(f"FreeRADIUS failed to start. Ensure ports 1812 and 1813 are free.\n{log_tail}")

    run("PAP", auth, "127.0.0.1:1812", "auth", ["-c", "500", "-p", "16"], 500)
    run("CHAP", auth, "127.0.0.1:1812", "auth", ["-a", "chap", "-c", "500", "-p", "16"], 500)
    run("Accounting", acct, "127.0.0.1:1813", "acct", ["-c", "500", "-p", "16"], 500)
    run("CHAP wrong password", wrong_password, "127.0.0.1:1812", "auth", ["-a", "chap", "-c", "20", "-p", "16"], 0, 20)
    run("Auth with two accounting sessions", auth, "127.0.0.1", "auth", ["-A", "1,2", "-c", "2", "-p", "2"], 8)
    print("INTEROP OK")
finally:
    if server.poll() is None:
        subprocess.run(["sudo", "-n", "kill", "-TERM", "--", f"-{server.pid}"], check=False)
        server.wait(timeout=5)
PY
