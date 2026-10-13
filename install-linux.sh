#!/usr/bin/env bash
# Installs the Alfred Device Monitor on Linux (systemd).
#
# Required environment variables:
#   ALFRED_KEY          Agent key from Alfred > Settings > Agent keys (alfa_...)
#   ALFRED_OWNER_EMAIL  Email of the person who owns this computer
#   ALFRED_REGION       us, eu or aus
#   ALFRED_API_URL      Your Alfred address, for example https://alfred.example.com
# Optional:
#   ALFRED_AGENT_DIR=/path            Install from a local copy (offline); the pins still apply
#   ALFRED_SKIP_REGISTRATION_CHECK=true  Do not wait for Alfred to confirm the registration
#   ALFRED_NOSTART=true Install without enrolling or starting the timer yet
set -euo pipefail
umask 077

AGENT_URL="https://raw.githubusercontent.com/opencybersecurityinc/alfred-agent-scripts/main/alfred-agent.sh"
# Must match alfred-agent.sh in this repository; run ./update-checksums.sh after editing the agent.
AGENT_SHA256="4c569cf6e26ad3d59727bae0d3599b2796f9fdfd0e3abbd1286f06370b60155b"
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
command -v curl >/dev/null 2>&1 || fail "curl is required. Install it with your package manager and retry."

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
as_root install -d -o root -g root -m 755 /usr/local/bin
as_root install -o root -g root -m 755 "$WORK_DIR/alfred-agent" "$BIN_PATH"
as_root install -d -o root -g root -m 700 "$CONFIG_DIR"

# Written through stdin so the key never appears in a process argument list.
write_private() {
  # shellcheck disable=SC2016 # $1 expands in the child shell
  as_root sh -c 'umask 077; rm -f "$1"; cat >"$1"' sh "$1"
}
# The activation nonce is the install time in epoch milliseconds. Alfred keeps
# the newest nonce per device and refuses enrollments that present an older
# one, so a copied or replayed bootstrap config cannot re-bind the device.
ACTIVATION_NONCE="$(date +%s%3N 2>/dev/null || true)"
[[ "$ACTIVATION_NONCE" =~ ^[0-9]{13}$ ]] || ACTIVATION_NONCE="$(date +%s)000"
printf 'API_URL=%s\nOWNER_EMAIL=%s\nREGION=%s\nACTIVATION_NONCE=%s\n' \
  "$ALFRED_API_URL" "$ALFRED_OWNER_EMAIL" "$ALFRED_REGION" "$ACTIVATION_NONCE" |
  write_private "$CONFIG_DIR/agent.conf"
printf 'header = "Authorization: Bearer %s"\n' "$ALFRED_KEY" | write_private "$CONFIG_DIR/auth.curl"
as_root chown root:root "$CONFIG_DIR/agent.conf" "$CONFIG_DIR/auth.curl"
as_root chmod 600 "$CONFIG_DIR/agent.conf" "$CONFIG_DIR/auth.curl"

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

if [ "$ALFRED_NOSTART" = "true" ]; then
  printf '\033[32m\nInstalled without starting. Run "sudo alfred-agent enroll" and\n"sudo systemctl enable --now alfred-agent.timer" when ready.\033[0m\n'
  exit 0
fi

step "Enrolling this device"
as_root "$BIN_PATH" enroll || fail "Enrollment failed. Check the key, owner email and ALFRED_API_URL."

step "Scheduling hourly check-ins"
as_root systemctl enable --now alfred-agent.timer

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
