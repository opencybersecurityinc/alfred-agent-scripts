#!/usr/bin/env bash
# Installs the Alfred Device Monitor on macOS.
#
# Required environment variables:
#   ALFRED_KEY          Agent key from Alfred > Settings > Agent keys (alfa_...)
#   ALFRED_OWNER_EMAIL  Email of the person who owns this computer
#   ALFRED_REGION       us, eu or aus
#   ALFRED_API_URL      Your Alfred address, for example https://alfred.example.com
# Optional:
#   ALFRED_NOSTART=true Install without enrolling or scheduling check-ins yet
set -euo pipefail
umask 077

AGENT_URL="https://raw.githubusercontent.com/opencybersecurityinc/alfred-agent-scripts/main/alfred-agent.sh"
# Must match alfred-agent.sh in this repository; run ./update-checksums.sh after editing the agent.
AGENT_SHA256="2cc99706e779ce898bed419c6e8b2cdce3bb90e68192d640c55ad0258ef6974e"
SUPPORT="support@trust.builders"

LABEL="com.alfred.devicemonitor"
BIN_PATH="/usr/local/bin/alfred-agent"
CONFIG_DIR="/Library/Application Support/Alfred Device Monitor"
PLIST_PATH="/Library/LaunchDaemons/$LABEL.plist"
LOG_PATH="/var/log/alfred-agent.log"

fail() {
  printf '\033[31m%s\n\nNeed help? Contact %s.\033[0m\n' "$*" "$SUPPORT" >&2
  exit 1
}
step() { printf '\033[34m\n* %s\n\033[0m' "$*"; }

[ "$(uname -s)" = "Darwin" ] || fail "This installer is for macOS. Use install-linux.sh or install-windows.ps1."

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
actual="$(shasum -a 256 "$WORK_DIR/alfred-agent" | cut -d' ' -f1)"
[ "$actual" = "$AGENT_SHA256" ] || fail "Checksum mismatch (expected $AGENT_SHA256, got $actual). Installation stopped."

step "Installing. You might be asked for your password..."
as_root /bin/mkdir -p /usr/local/bin
as_root /usr/bin/install -o root -g wheel -m 755 "$WORK_DIR/alfred-agent" "$BIN_PATH"
as_root /bin/mkdir -p "$CONFIG_DIR"
as_root /usr/sbin/chown root:wheel "$CONFIG_DIR"
as_root /bin/chmod 700 "$CONFIG_DIR"

# Written through stdin so the key never appears in a process argument list.
write_private() {
  # shellcheck disable=SC2016 # $1 expands in the child shell
  as_root /bin/sh -c 'umask 077; rm -f "$1"; cat >"$1"' sh "$1"
}
printf 'API_URL=%s\nOWNER_EMAIL=%s\nREGION=%s\n' "$ALFRED_API_URL" "$ALFRED_OWNER_EMAIL" "$ALFRED_REGION" |
  write_private "$CONFIG_DIR/agent.conf"
printf 'header = "Authorization: Bearer %s"\n' "$ALFRED_KEY" | write_private "$CONFIG_DIR/auth.curl"

# shellcheck disable=SC2016 # $1 expands in the child shell
as_root /bin/sh -c 'umask 022; cat >"$1"' sh "$PLIST_PATH" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$BIN_PATH</string>
    <string>checkin</string>
  </array>
  <key>StartInterval</key>
  <integer>3600</integer>
  <key>RunAtLoad</key>
  <true/>
  <key>StandardOutPath</key>
  <string>$LOG_PATH</string>
  <key>StandardErrorPath</key>
  <string>$LOG_PATH</string>
</dict>
</plist>
EOF
as_root /usr/sbin/chown root:wheel "$PLIST_PATH"
as_root /bin/chmod 644 "$PLIST_PATH"

if [ "${ALFRED_NOSTART:-}" = "true" ]; then
  printf '\033[32m\nInstalled without starting. Run "sudo alfred-agent enroll" and\n"sudo launchctl bootstrap system %s" when ready.\033[0m\n' "$PLIST_PATH"
  exit 0
fi

step "Enrolling this Mac"
as_root "$BIN_PATH" enroll || fail "Enrollment failed. Check the key, owner email and ALFRED_API_URL."

step "Scheduling hourly check-ins"
as_root /bin/launchctl bootout "system/$LABEL" 2>/dev/null || true
as_root /bin/launchctl bootstrap system "$PLIST_PATH"

printf '\033[32m
The Alfred Device Monitor is installed and reports to Alfred every hour.

  Status:     sudo alfred-agent status
  Check in:   sudo alfred-agent checkin
  Uninstall:  sudo alfred-agent uninstall
\033[0m\n'
