#!/usr/bin/env bash
# Capture reference outputs from the RadPerf reference binary for Linux (x86_64).
#
# Runs the real binary in an amd64 Linux container (native on x86_64, Rosetta
# on Apple Silicon) and records the help/version text and the -xx debug output
# for user generation, the `auto` command and tagged attributes. Writes to
# reference/.
#
# Usage:
#   scripts/capture_reference.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RP="${RADPERF_ORIG:-$ROOT/../radperf/linux/opt/networkradius/radperf}"
OUT="$ROOT/reference"
mkdir -p "$OUT"

if [ ! -x "$RP/bin/radperf" ]; then
  echo "RadPerf reference binary not found at $RP/bin/radperf" >&2
  echo "set RADPERF_ORIG to the extracted 'radperf' directory (with bin/ and lib/)" >&2
  exit 1
fi

if command -v docker >/dev/null 2>&1; then
  RUNTIME=docker
elif command -v podman >/dev/null 2>&1; then
  RUNTIME=podman
else
  echo "docker or podman is required" >&2
  exit 1
fi

read -r -d '' CAPTURE <<'EOS' || true
set -u
# Runtime libraries needed by the shipped libfreeradius-radius.so.
apt-get update -qq >/dev/null 2>&1 || true
apt-get install -y -qq libcap2 libpcap0.8 >/dev/null 2>&1 || true

cd /opt/radperf
export LD_LIBRARY_PATH=lib
B=./bin/radperf
D="-d /opt/radperf/share"

printf 'User-Name = "bob"\nUser-Password = "hello"\n' > /tmp/in.txt
printf 'User-Name = "bob"\nTunnel-Type:1 = VLAN\n' > /tmp/tag.txt

$B -h > /out/help.txt 2>&1 || true
$B -v > /out/version.txt 2>&1 || true

# -xx prints the packet dump (no server needed; short timeout keeps it fast).
$B $D -xx -c 1 -t 0.1 -r 1 -f /tmp/in.txt 127.0.0.1:18120 auth secret > /out/debug2.txt 2>&1 || true
$B $D -xx -u 3 -c 1 -t 0.1 -r 1 -f /tmp/in.txt 127.0.0.1:18120 auth secret > /out/users2.txt 2>&1 || true
$B $D -xx -c 1 -t 0.1 -r 1 -f /tmp/in.txt 127.0.0.1:18120 auto secret > /out/auto2.txt 2>&1 || true
$B $D -xx -c 1 -t 0.1 -r 1 -f /tmp/tag.txt 127.0.0.1:18120 auth secret > /out/tagged2.txt 2>&1 || true

echo "capture complete"
EOS

"$RUNTIME" run --rm --platform linux/amd64 \
  -v "$RP:/opt/radperf:ro" \
  -v "$OUT:/out" \
  debian:bookworm-slim bash -c "$CAPTURE"

echo "reference files written to $OUT"
ls -1 "$OUT"
