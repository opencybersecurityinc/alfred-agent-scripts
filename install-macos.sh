#!/usr/bin/env bash
# Installs the Alfred Device Monitor on macOS.
#
# Required environment variables:
#   ALFRED_KEY          Agent key from Alfred > Settings > Agent keys (alfa_...)
#   ALFRED_OWNER_EMAIL  Email of the person who owns this computer
#   ALFRED_REGION       us, eu or aus
#   ALFRED_API_URL      Your Alfred address, for example https://alfred.example.com
# Optional:
#   ALFRED_AGENT_DIR=/path            Install from a local copy (offline); the pins still apply
#   ALFRED_SKIP_REGISTRATION_CHECK=true  Do not wait for Alfred to confirm the registration
#   ALFRED_NOSTART=true Install without enrolling or scheduling check-ins yet
set -euo pipefail
umask 077

AGENT_URL="https://raw.githubusercontent.com/opencybersecurityinc/alfred-agent-scripts/main/alfred-agent.sh"
# Must match alfred-agent.sh in this repository; run ./update-checksums.sh after editing the agent.
AGENT_SHA256="df3421bdeba57412d986471ae788b986c7b801c250bb600e9fb8dc5b3bc97132"
SUPPORT="support@trust.builders"
# Publishing a signature is optional until a signing certificate is pinned
# below; once SIGNING_CERT_SHA256 is set, a missing or invalid signature stops
# the installation. Run ./update-checksums.sh after editing the agent.
SIGNING_IDENTITY=""
SIGNING_CERT_SHA256=""
SIG_URL="$AGENT_URL.sig"
CERT_URL="${AGENT_URL%/*}/alfred-agent-signing.pem"
REGISTRATION_ATTEMPTS="${ALFRED_REGISTRATION_ATTEMPTS:-6}"
REGISTRATION_DELAY="${ALFRED_REGISTRATION_DELAY:-10}"

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
# ALFRED_ALLOW_INSECURE_LOCALHOST=1 admits a plain-http loopback API for local testing only.
if ! [[ "$ALFRED_API_URL" =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$ ]] &&
  ! { [ "${ALFRED_ALLOW_INSECURE_LOCALHOST:-}" = "1" ] &&
    [[ "$ALFRED_API_URL" =~ ^http://(127\.0\.0\.1|localhost)(:[0-9]{1,5})?$ ]]; }; then
  fail "Set ALFRED_API_URL to your Alfred https:// address."
fi

ALFRED_NOSTART="${ALFRED_NOSTART:-}"
ALFRED_SKIP_REGISTRATION_CHECK="${ALFRED_SKIP_REGISTRATION_CHECK:-}"
for switch in ALFRED_NOSTART ALFRED_SKIP_REGISTRATION_CHECK; do
  case "${!switch}" in "" | true | false) ;; *) fail "Set $switch to true or false." ;; esac
done
[[ "$REGISTRATION_ATTEMPTS" =~ ^[1-9][0-9]?$ && "$REGISTRATION_DELAY" =~ ^[0-9]{1,3}$ ]] ||
  fail "ALFRED_REGISTRATION_ATTEMPTS must be 1-99 and ALFRED_REGISTRATION_DELAY 0-999 seconds."

as_root() {
  if [ "$(id -u)" -eq 0 ]; then "$@"; else sudo "$@"; fi
}

download() {
  curl -fsSL --proto '=https' --tlsv1.2 --max-time 60 -o "$2" "$1"
}

# Hashes with whichever SHA-256 tool exists and fails closed when none does,
# so the pin can never be skipped silently.
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d' ' -f1
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 -r "$1" | cut -d' ' -f1
  else
    fail "No SHA-256 tool (sha256sum, shasum or openssl) found, so the agent cannot be verified. Installation stopped."
  fi
}

normalize_fingerprint() { tr -d ':[:space:]' | tr '[:lower:]' '[:upper:]'; }

# Verifies the detached signature against the published certificate, which
# must carry the pinned identity and the pinned SHA-256 fingerprint.
verify_signature() {
  local file="$1" sig="$WORK_DIR/agent.sig" cert="$WORK_DIR/signing.pem" der="$WORK_DIR/agent.sig.der"
  local fingerprint subject
  if [ -z "$SIGNING_CERT_SHA256" ]; then
    printf 'No signing certificate is pinned in this installer; relying on the SHA-256 pin.\n'
    return 0
  fi
  command -v openssl >/dev/null 2>&1 || fail "openssl is required to verify the agent signature. Installation stopped."
  [ -f "$sig" ] || download "$SIG_URL" "$sig" || fail "Could not download the agent signature from $SIG_URL."
  [ -f "$cert" ] || download "$CERT_URL" "$cert" || fail "Could not download the signing certificate from $CERT_URL."
  fingerprint="$(openssl x509 -in "$cert" -noout -fingerprint -sha256 2>/dev/null | sed 's/^[^=]*=//' | normalize_fingerprint)"
  [ "$fingerprint" = "$(printf '%s' "$SIGNING_CERT_SHA256" | normalize_fingerprint)" ] ||
    fail "Signing certificate fingerprint does not match. Installation stopped."
  subject="$(openssl x509 -in "$cert" -noout -subject 2>/dev/null)"
  case "$subject" in
    *"CN = $SIGNING_IDENTITY"* | *"CN=$SIGNING_IDENTITY"*) ;;
    *) fail "Signing certificate identity does not match \"$SIGNING_IDENTITY\". Installation stopped." ;;
  esac
  openssl base64 -d -A -in "$sig" -out "$der" 2>/dev/null || fail "The agent signature is not valid base64."
  openssl x509 -in "$cert" -noout -pubkey >"$WORK_DIR/signing.pub" || fail "Could not read the signing certificate."
  openssl dgst -sha256 -verify "$WORK_DIR/signing.pub" -signature "$der" "$file" >/dev/null 2>&1 ||
    fail "The agent signature is invalid. Installation stopped."
  printf 'Signature by "%s" verified.\n' "$SIGNING_IDENTITY"
}

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

step "Downloading the Alfred Device Monitor agent"
if [ -n "${ALFRED_AGENT_DIR:-}" ]; then
  cp "$ALFRED_AGENT_DIR/alfred-agent.sh" "$WORK_DIR/alfred-agent" || fail "No alfred-agent.sh in $ALFRED_AGENT_DIR."
  SIG_URL="" CERT_URL=""
  [ ! -f "$ALFRED_AGENT_DIR/alfred-agent.sh.sig" ] || cp "$ALFRED_AGENT_DIR/alfred-agent.sh.sig" "$WORK_DIR/agent.sig"
  [ ! -f "$ALFRED_AGENT_DIR/alfred-agent-signing.pem" ] || cp "$ALFRED_AGENT_DIR/alfred-agent-signing.pem" "$WORK_DIR/signing.pem"
else
  download "$AGENT_URL" "$WORK_DIR/alfred-agent" || fail "Could not download the agent from $AGENT_URL."
fi

step "Verifying the agent checksum and signature"
actual="$(sha256_of "$WORK_DIR/alfred-agent")"
[[ "$actual" =~ ^[0-9a-f]{64}$ ]] || fail "Could not compute the agent checksum. Installation stopped."
[ "$actual" = "$AGENT_SHA256" ] || fail "Checksum mismatch (expected $AGENT_SHA256, got $actual). Installation stopped."
verify_signature "$WORK_DIR/alfred-agent"

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
# The activation nonce is the install time in epoch milliseconds. Alfred keeps
# the newest nonce per device and refuses enrollments that present an older
# one, so a copied or replayed bootstrap config cannot re-bind the device.
ACTIVATION_NONCE="$(date +%s%3N 2>/dev/null || true)"
[[ "$ACTIVATION_NONCE" =~ ^[0-9]{13}$ ]] || ACTIVATION_NONCE="$(date +%s)000"
INSECURE_LINE=""
case "$ALFRED_API_URL" in http://*) INSECURE_LINE="ALLOW_INSECURE_LOCALHOST=1" ;; esac
printf 'API_URL=%s\nOWNER_EMAIL=%s\nREGION=%s\nACTIVATION_NONCE=%s\n%s\n' \
  "$ALFRED_API_URL" "$ALFRED_OWNER_EMAIL" "$ALFRED_REGION" "$ACTIVATION_NONCE" "$INSECURE_LINE" |
  write_private "$CONFIG_DIR/agent.conf"
printf 'header = "Authorization: Bearer %s"\n' "$ALFRED_KEY" | write_private "$CONFIG_DIR/auth.curl"
as_root /usr/sbin/chown root:wheel "$CONFIG_DIR/agent.conf" "$CONFIG_DIR/auth.curl"
as_root /bin/chmod 600 "$CONFIG_DIR/agent.conf" "$CONFIG_DIR/auth.curl"

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

if [ "$ALFRED_NOSTART" = "true" ]; then
  printf '\033[32m\nInstalled without starting. Run "sudo alfred-agent enroll" and\n"sudo launchctl bootstrap system %s" when ready.\033[0m\n' "$PLIST_PATH"
  exit 0
fi

step "Enrolling this Mac"
as_root "$BIN_PATH" enroll || fail "Enrollment failed. Check the key, owner email and ALFRED_API_URL."

step "Scheduling hourly check-ins"
as_root /bin/launchctl bootout "system/$LABEL" 2>/dev/null || true
as_root /bin/launchctl bootstrap system "$PLIST_PATH"

wait_for_registration() {
  local attempt=1
  while :; do
    if as_root "$BIN_PATH" check-registration >/dev/null 2>&1; then
      printf 'Alfred confirmed this device is registered.\n'
      return 0
    fi
    [ "$attempt" -lt "$REGISTRATION_ATTEMPTS" ] || break
    attempt=$((attempt + 1))
    sleep "$REGISTRATION_DELAY"
  done
  fail "Alfred has not confirmed the registration after $REGISTRATION_ATTEMPTS attempts. Run \"sudo alfred-agent status\" to see why."
}

if [ "${ALFRED_SKIP_REGISTRATION_CHECK:-}" = "true" ]; then
  printf 'Skipping the registration check (ALFRED_SKIP_REGISTRATION_CHECK=true).\n'
else
  step "Confirming the registration with Alfred"
  wait_for_registration
fi

printf '\033[32m
The Alfred Device Monitor is installed and reports to Alfred every hour.

  Status:     sudo alfred-agent status   (exit 0 running, 2 not registered)
  AI scan:    sudo alfred-agent ai-scan
  Check in:   sudo alfred-agent checkin
  Uninstall:  sudo alfred-agent uninstall
\033[0m\n'
