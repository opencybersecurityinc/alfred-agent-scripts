#!/usr/bin/env bash
# Installs the Alfred Device Monitor on Linux (systemd).
#
# Required environment variables:
#   ALFRED_KEY          Agent key from Alfred > Settings > Agent keys (alfa_...)
#   ALFRED_OWNER_EMAIL  Email of the person who owns this computer
#   ALFRED_REGION       us, eu or aus
#   ALFRED_API_URL      Your Alfred address, for example https://alfred.example.com
# Optional:
#   ALFRED_NOSTART=true Install without enrolling or starting the timer yet
set -euo pipefail
umask 077

AGENT_URL="https://raw.githubusercontent.com/opencybersecurityinc/alfred-agent-scripts/main/alfred-agent.sh"
# Must match alfred-agent.sh in this repository; run ./update-checksums.sh after editing the agent.
AGENT_SHA256="2cc99706e779ce898bed419c6e8b2cdce3bb90e68192d640c55ad0258ef6974e"
SUPPORT="support@trust.builders"

BIN_PATH="/usr/local/bin/alfred-agent"
CONFIG_DIR="/etc/alfred-agent"
UNIT_DIR="/etc/systemd/system"

fail() {
  printf '\033[31m%s\n\nNeed help? Contact %s.\033[0m\n' "$*" "$SUPPORT" >&2
  exit 1
}
step() { printf '\033[34m\n* %s\n\033[0m' "$*"; }

[ "$(uname -s)" = "Linux" ] || fail "This installer is for Linux. Use install-macos.sh or install-windows.ps1."
command -v systemctl >/dev/null 2>&1 || fail "systemd is required to schedule check-ins."
for tool in curl sha256sum; do
  command -v "$tool" >/dev/null 2>&1 || fail "$tool is required. Install it with your package manager and retry."
done

ALFRED_KEY="${ALFRED_KEY:-}"
ALFRED_OWNER_EMAIL="${ALFRED_OWNER_EMAIL:-}"
ALFRED_REGION="${ALFRED_REGION:-}"
ALFRED_API_URL="${ALFRED_API_URL:-}"
ALFRED_API_URL="${ALFRED_API_URL%/}"

[[ "$ALFRED_KEY" =~ ^alfa_[A-Za-z0-9_-]{32,64}$ ]] ||
  fail "Set ALFRED_KEY to an agent key from Alfred > Settings > Agent keys."
[[ "$ALFRED_OWNER_EMAIL" =~ ^[^[:space:]@\"\\]{1,64}@[^[:space:]@\"\\]{1,255}$ ]] ||
  fail "Set ALFRED_OWNER_EMAIL to the email of the person who owns this computer."
case "$ALFRED_REGION" in us | eu | aus) ;; *) fail "Set ALFRED_REGION to us, eu or aus." ;; esac
[[ "$ALFRED_API_URL" =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$ ]] ||
  fail "Set ALFRED_API_URL to your Alfred https:// address."

as_root() {
  if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo "$@"; fi
}

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

step "Downloading the Alfred Device Monitor agent"
curl -fsSL --proto '=https' --tlsv1.2 --max-time 60 -o "$WORK_DIR/alfred-agent" "$AGENT_URL" ||
  fail "Could not download the agent from $AGENT_URL."

step "Verifying the agent checksum"
actual="$(sha256sum "$WORK_DIR/alfred-agent" | cut -d' ' -f1)"
[ "$actual" = "$AGENT_SHA256" ] || fail "Checksum mismatch (expected $AGENT_SHA256, got $actual). Installation stopped."

step "Installing. You might be asked for your password..."
as_root install -d -o root -g root -m 755 /usr/local/bin
as_root install -o root -g root -m 755 "$WORK_DIR/alfred-agent" "$BIN_PATH"
as_root install -d -o root -g root -m 700 "$CONFIG_DIR"

# Written through stdin so the key never appears in a process argument list.
write_private() {
  # shellcheck disable=SC2016 # $1 expands in the child shell
  as_root sh -c 'umask 077; rm -f "$1"; cat >"$1"' sh "$1"
}
printf 'API_URL=%s\nOWNER_EMAIL=%s\nREGION=%s\n' "$ALFRED_API_URL" "$ALFRED_OWNER_EMAIL" "$ALFRED_REGION" |
  write_private "$CONFIG_DIR/agent.conf"
printf 'header = "Authorization: Bearer %s"\n' "$ALFRED_KEY" | write_private "$CONFIG_DIR/auth.curl"

write_unit() {
  # shellcheck disable=SC2016 # $1 expands in the child shell
  as_root sh -c 'umask 022; cat >"$1"' sh "$1"
}
write_unit "$UNIT_DIR/alfred-agent.service" <<EOF
[Unit]
Description=Alfred Device Monitor check-in
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=$BIN_PATH checkin
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=read-only
ProtectSystem=full
EOF
write_unit "$UNIT_DIR/alfred-agent.timer" <<'EOF'
[Unit]
Description=Hourly Alfred Device Monitor check-in

[Timer]
OnBootSec=2min
OnCalendar=hourly
RandomizedDelaySec=10min
Persistent=true

[Install]
WantedBy=timers.target
EOF
as_root systemctl daemon-reload

if [ "${ALFRED_NOSTART:-}" = "true" ]; then
  printf '\033[32m\nInstalled without starting. Run "sudo alfred-agent enroll" and\n"sudo systemctl enable --now alfred-agent.timer" when ready.\033[0m\n'
  exit 0
fi

step "Enrolling this device"
as_root "$BIN_PATH" enroll || fail "Enrollment failed. Check the key, owner email and ALFRED_API_URL."

step "Scheduling hourly check-ins"
as_root systemctl enable --now alfred-agent.timer

printf '\033[32m
The Alfred Device Monitor is installed and reports to Alfred every hour.

  Status:     sudo alfred-agent status
  Check in:   sudo alfred-agent checkin
  Uninstall:  sudo alfred-agent uninstall
\033[0m\n'
