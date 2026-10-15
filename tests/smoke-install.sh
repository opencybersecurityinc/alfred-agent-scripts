#!/usr/bin/env bash
# Installs the agent for real against a local mock of the Alfred API, then
# checks the status and registration exit codes. Needs passwordless sudo, so
# it is meant for disposable CI runners only.
set -euo pipefail
cd "$(dirname "$0")/.."

case "$(uname -s)" in
  Linux) INSTALLER=./install-linux.sh ;;
  Darwin) INSTALLER=./install-macos.sh ;;
  *) echo "unsupported platform" >&2; exit 1 ;;
esac
PORT=18080
KEY="alfa_smoke$(printf '%032d' 0)"
LOG="$(mktemp)"
MOCK_PID=""

start_mock() {
  python3 tests/mock-alfred.py "$PORT" "$LOG" "$KEY" &
  MOCK_PID=$!
  for _ in $(seq 1 50); do
    curl -s -o /dev/null "http://127.0.0.1:$PORT/" && return 0
    sleep 0.1
  done
  echo "mock API did not start" >&2
  exit 1
}
stop_mock() { [ -z "$MOCK_PID" ] || kill "$MOCK_PID" 2>/dev/null || true; wait "$MOCK_PID" 2>/dev/null || true; MOCK_PID=""; }
cleanup() {
  stop_mock
  sudo alfred-agent uninstall >/dev/null 2>&1 || true
  rm -f "$LOG"
}
trap cleanup EXIT

export ALFRED_KEY="$KEY" ALFRED_OWNER_EMAIL="smoke@example.com" ALFRED_REGION="us"
export ALFRED_API_URL="http://127.0.0.1:$PORT" ALFRED_ALLOW_INSECURE_LOCALHOST=1 ALFRED_AGENT_DIR="$PWD"
export ALFRED_REGISTRATION_DELAY=1

expect_exit() {
  local want="$1" label="$2" got=0
  shift 2
  "$@" >/tmp/smoke.out 2>&1 || got=$?
  if [ "$got" -ne "$want" ]; then
    cat /tmp/smoke.out
    echo "FAIL $label: exit $got, expected $want" >&2
    exit 1
  fi
  echo "ok   $label (exit $got)"
}

start_mock

expect_exit 1 "invalid switch value is refused" env ALFRED_NOSTART=yes "$INSTALLER"

tampered="$(mktemp -d)"
cp alfred-agent.sh "$tampered/" && printf '\n# tampered\n' >>"$tampered/alfred-agent.sh"
expect_exit 1 "tampered agent is refused" env ALFRED_AGENT_DIR="$tampered" "$INSTALLER"
grep -q "Checksum mismatch" /tmp/smoke.out
rm -rf "$tampered"

expect_exit 0 "install without starting" env ALFRED_NOSTART=true "$INSTALLER"
expect_exit 1 "status before the schedule runs" sudo alfred-agent status
conf_dir=/etc/alfred-agent
[ "$(uname -s)" != Darwin ] || conf_dir="/Library/Application Support/Alfred Device Monitor"
mode="$(sudo stat -c '%a %U' "$conf_dir/agent.conf" 2>/dev/null || sudo stat -f '%Lp %Su' "$conf_dir/agent.conf")"
[ "$mode" = "600 root" ] || { echo "FAIL agent.conf is $mode, expected 600 root" >&2; exit 1; }
sudo grep -Eq '^ACTIVATION_NONCE=[0-9]{13}$' "$conf_dir/agent.conf" || { echo "FAIL no activation nonce" >&2; exit 1; }
echo "ok   bootstrap config is root-only 0600 with an activation nonce"

expect_exit 0 "full install with registration check" "$INSTALLER"
grep -q '"path": "/v1/agent/enroll"' "$LOG"
grep '"/v1/agent/enroll"' "$LOG" | grep -Eq '"activationNonce": [0-9]{13}'
echo "ok   enrollment carried the activation nonce"
expect_exit 0 "check-registration when registered" sudo alfred-agent check-registration
expect_exit 0 "status when running and registered" sudo alfred-agent status
expect_exit 0 "check-in with AI inventory" sudo alfred-agent checkin
grep -q '"path": "/v1/agent/ai-inventory"' "$LOG"
echo "ok   AI inventory was sent"
if grep '"/v1/agent/ai-inventory"' "$LOG" | grep -qi 'smoke@example.com\|alfa_smoke'; then
  echo "FAIL the AI inventory leaked the owner or the key" >&2
  exit 1
fi

stop_mock
: >"$LOG"
start_mock
expect_exit 3 "check-registration when Alfred forgot the device" sudo alfred-agent check-registration
expect_exit 2 "status when running but not registered" sudo alfred-agent status

expect_exit 0 "uninstall" sudo alfred-agent uninstall
echo "smoke install passed"
