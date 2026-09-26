#!/usr/bin/env bash
# Alfred Device Monitor agent for macOS and Linux.
# Reports device posture (hardware UUID, OS, serial, disk encryption) to the Alfred API.
set -euo pipefail
umask 077
export LC_ALL=C
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

readonly AGENT_VERSION="1.0.0"
readonly EMAIL_PATTERN='^[^[:space:]@"\\]{1,64}@[^[:space:]@"\\]{1,255}$'
readonly UUID_PATTERN='^[A-Za-z0-9-]{8,64}$'
readonly BAD_UUIDS=" FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA \
00000000-0000-0000-0000-000000000000 11111111-1111-1111-1111-111111111111 \
03000200-0400-0500-0006-000700080009 03020100-0504-0706-0809-0A0B0C0D0E0F \
10000000-0000-8000-0040-000000000000 01234567-8910-1112-1314-151617181920 "

case "$(uname -s)" in
  Darwin)
    PLATFORM="macos"
    DEFAULT_CONFIG_DIR="/Library/Application Support/Alfred Device Monitor"
    ;;
  Linux)
    PLATFORM="linux"
    DEFAULT_CONFIG_DIR="/etc/alfred-agent"
    ;;
  *)
    echo "alfred-agent: unsupported operating system" >&2
    exit 1
    ;;
esac

# ALFRED_CONFIG_DIR exists for tests and MDM packaging; services always use the default.
CONFIG_DIR="${ALFRED_CONFIG_DIR:-$DEFAULT_CONFIG_DIR}"
CONFIG_FILE="$CONFIG_DIR/agent.conf"
AUTH_FILE="$CONFIG_DIR/auth.curl"

die() {
  echo "alfred-agent: $*" >&2
  exit 1
}

log() {
  printf '%s alfred-agent: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

require_root() {
  if [ "$(id -u)" -ne 0 ] && [ -z "${ALFRED_CONFIG_DIR:-}" ]; then
    die "this command must run as root (use sudo)"
  fi
}

check_private_file() {
  local file="$1"
  [ -e "$file" ] || die "missing $file; reinstall the Alfred Device Monitor"
  [ ! -L "$file" ] || die "refusing to read symlink $file"
  [ -O "$file" ] || die "$file must be owned by the current user"
  if [ -n "$(find "$file" -perm -g=r -o -perm -o=r -o -perm -g=w -o -perm -o=w 2>/dev/null)" ]; then
    die "$file must not be readable or writable by group or others (chmod 600)"
  fi
}

conf_get() {
  local wanted="$1" line key
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in '' | '#'*) continue ;; esac
    key="${line%%=*}"
    if [ "$key" = "$wanted" ]; then
      printf '%s' "${line#*=}"
      return 0
    fi
  done <"$CONFIG_FILE"
  return 1
}

valid_api_url() {
  local url="$1"
  [[ "$url" =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$ ]] && return 0
  if [ "${ALFRED_ALLOW_INSECURE_LOCALHOST:-}" = "1" ] &&
    [[ "$url" =~ ^http://(localhost|127\.0\.0\.1)(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$ ]]; then
    return 0
  fi
  return 1
}

load_config() {
  check_private_file "$CONFIG_FILE"
  check_private_file "$AUTH_FILE"
  API_URL="$(conf_get API_URL)" || die "API_URL missing from $CONFIG_FILE"
  OWNER_EMAIL="$(conf_get OWNER_EMAIL)" || die "OWNER_EMAIL missing from $CONFIG_FILE"
  REGION="$(conf_get REGION)" || REGION="us"
  API_URL="${API_URL%/}"
  valid_api_url "$API_URL" || die "API_URL must be an https:// URL"
  [[ "$OWNER_EMAIL" =~ $EMAIL_PATTERN ]] || die "OWNER_EMAIL is not a valid email address"
}

# ── Device facts ─────────────────────────────────────────────────────────────

ioreg_platform_value() {
  ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null | awk -F'"' -v k="$1" '$2 == k { print $4; exit }'
}

hardware_uuid() {
  local uuid=""
  if [ "$PLATFORM" = "macos" ]; then
    uuid="$(ioreg_platform_value IOPlatformUUID)"
  elif [ -r /sys/class/dmi/id/product_uuid ]; then
    uuid="$(tr -d '[:space:]' </sys/class/dmi/id/product_uuid)"
  fi
  uuid="$(printf '%s' "$uuid" | tr '[:lower:]' '[:upper:]')"
  [[ "$uuid" =~ $UUID_PATTERN ]] || return 1
  case "$BAD_UUIDS" in *" $uuid "*) return 1 ;; esac
  printf '%s' "$uuid"
}

serial_number() {
  if [ "$PLATFORM" = "macos" ]; then
    ioreg_platform_value IOPlatformSerialNumber
  elif [ -r /sys/class/dmi/id/product_serial ]; then
    tr -d '\n' </sys/class/dmi/id/product_serial
  fi
}

os_name() {
  if [ "$PLATFORM" = "macos" ]; then
    sw_vers -productName 2>/dev/null || echo "macOS"
  elif [ -r /etc/os-release ]; then
    os_release_value NAME
  else
    echo "Linux"
  fi
}

os_version() {
  if [ "$PLATFORM" = "macos" ]; then
    sw_vers -productVersion 2>/dev/null || true
  elif [ -r /etc/os-release ]; then
    os_release_value VERSION_ID
  fi
}

os_release_value() {
  local line
  while IFS= read -r line; do
    case "$line" in
      "$1="*)
        line="${line#*=}"
        line="${line#\"}"
        printf '%s' "${line%\"}"
        return 0
        ;;
    esac
  done </etc/os-release
}

# Prints true, false, or nothing when encryption cannot be determined.
disk_encrypted() {
  if [ "$PLATFORM" = "macos" ]; then
    case "$(fdesetup isactive 2>/dev/null || true)" in
      true) echo true ;;
      false) echo false ;;
    esac
    return 0
  fi
  local source types
  source="$(findmnt -no SOURCE / 2>/dev/null || true)"
  source="${source%%\[*}"
  case "$source" in /dev/*) ;; *) return 0 ;; esac
  types="$(lsblk -s -no TYPE "$source" 2>/dev/null || true)"
  [ -n "$types" ] || return 0
  if printf '%s\n' "$types" | grep -qx crypt; then echo true; else echo false; fi
}

# ── JSON ─────────────────────────────────────────────────────────────────────

json_string() {
  local value
  value="$(printf '%s' "$1" | tr -d '\000-\037\177')"
  value="${value:0:$2}"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  printf '"%s"' "$value"
}

device_report() {
  local include_owner="$1" uuid encrypted body value
  uuid="$(hardware_uuid)" || die "no unique hardware UUID found; this device is not supported"
  body="\"hardwareUuid\":$(json_string "$uuid" 64)"
  body+=",\"agentVersion\":$(json_string "$AGENT_VERSION" 50)"
  value="$(hostname 2>/dev/null || uname -n)"
  [ -z "$value" ] || body+=",\"hostname\":$(json_string "$value" 200)"
  value="$(os_name)"
  [ -z "$value" ] || body+=",\"os\":$(json_string "$value" 100)"
  value="$(os_version)"
  [ -z "$value" ] || body+=",\"osVersion\":$(json_string "$value" 50)"
  value="$(serial_number || true)"
  [ -z "$value" ] || body+=",\"serial\":$(json_string "$value" 100)"
  encrypted="$(disk_encrypted)"
  [ -z "$encrypted" ] || body+=",\"isEncrypted\":$encrypted"
  if [ "$include_owner" = "1" ]; then
    body+=",\"ownerEmail\":$(json_string "$OWNER_EMAIL" 320)"
  fi
  printf '{%s}' "$body"
}

# ── HTTP ─────────────────────────────────────────────────────────────────────

RESPONSE_BODY=""
API_STATUS="000"

# The key is read by curl from the private config file, never passed on the command line.
api_request() {
  local method="$1" path="$2" body="${3:-}" tmp status proto="=https"
  case "$API_URL" in http://*) proto="=http,https" ;; esac
  tmp="$(mktemp)"
  local args=(-sS --proto "$proto" --max-time 30 --connect-timeout 10 -K "$AUTH_FILE"
    -H "Accept: application/json" -H "User-Agent: alfred-agent/$AGENT_VERSION ($PLATFORM)"
    -o "$tmp" -w '%{http_code}' -X "$method")
  if [ -n "$body" ]; then
    status="$(printf '%s' "$body" | curl "${args[@]}" -H "Content-Type: application/json" \
      --data-binary @- "$API_URL$path")" || status="000"
  else
    status="$(curl "${args[@]}" "$API_URL$path")" || status="000"
  fi
  RESPONSE_BODY="$(head -c 4096 "$tmp")"
  rm -f "$tmp"
  API_STATUS="$status"
}

describe_failure() {
  case "$1" in
    000) echo "could not reach $API_URL" ;;
    401) echo "the agent key was rejected (revoked or invalid); reinstall with a new key" ;;
    429) echo "rate limited by the Alfred API; will retry on the next run" ;;
    *) echo "Alfred API returned HTTP $1: $RESPONSE_BODY" ;;
  esac
}

cmd_enroll() {
  require_root
  load_config
  local status
  api_request POST /v1/agent/enroll "$(device_report 1)"
  status="$API_STATUS"
  case "$status" in
    200 | 201) log "device enrolled ($RESPONSE_BODY)" ;;
    *) die "enroll failed: $(describe_failure "$status")" ;;
  esac
}

cmd_checkin() {
  require_root
  load_config
  local status
  api_request POST /v1/agent/checkin "$(device_report 0)"
  status="$API_STATUS"
  case "$status" in
    200) log "check-in ok" ;;
    404)
      case "$RESPONSE_BODY" in
        *device_not_enrolled*)
          log "device not enrolled; enrolling"
          cmd_enroll
          ;;
        *) die "check-in failed: $(describe_failure "$status")" ;;
      esac
      ;;
    *) die "check-in failed: $(describe_failure "$status")" ;;
  esac
}

cmd_check_registration() {
  require_root
  load_config
  local uuid status
  uuid="$(hardware_uuid)" || die "no unique hardware UUID found"
  api_request GET "/v1/agent/registration?hardware_uuid=$uuid"
  status="$API_STATUS"
  [ "$status" = "200" ] || die "registration lookup failed: $(describe_failure "$status")"
  printf '%s\n' "$RESPONSE_BODY"
  if printf '%s' "$RESPONSE_BODY" | grep -Eq '"registered"[[:space:]]*:[[:space:]]*true'; then return 0; fi
  return 3
}

cmd_status() {
  require_root
  load_config
  echo "Alfred Device Monitor $AGENT_VERSION ($PLATFORM)"
  echo "API:          $API_URL"
  echo "Region:       $REGION"
  echo "Owner:        $OWNER_EMAIL"
  echo "Hardware:     $(hardware_uuid || echo unsupported)"
  echo "Encrypted:    $(disk_encrypted | grep . || echo unknown)"
  if [ "$PLATFORM" = "macos" ]; then
    if launchctl print system/com.alfred.devicemonitor >/dev/null 2>&1; then
      echo "Scheduler:    launchd (loaded)"
    else
      echo "Scheduler:    launchd (not loaded)"
    fi
  else
    echo "Scheduler:    systemd timer $(systemctl is-active alfred-agent.timer 2>/dev/null || true)"
  fi
  printf 'Registration: '
  cmd_check_registration
}

cmd_report() {
  require_root
  load_config
  device_report 1
  echo
}

cmd_uninstall() {
  [ "$(id -u)" -eq 0 ] || die "uninstall must run as root (use sudo)"
  if [ "$PLATFORM" = "macos" ]; then
    launchctl bootout system/com.alfred.devicemonitor 2>/dev/null || true
    rm -f /Library/LaunchDaemons/com.alfred.devicemonitor.plist /var/log/alfred-agent.log
    rm -f /usr/local/bin/alfred-agent
    rm -rf "$DEFAULT_CONFIG_DIR"
  else
    systemctl disable --now alfred-agent.timer 2>/dev/null || true
    rm -f /etc/systemd/system/alfred-agent.service /etc/systemd/system/alfred-agent.timer
    systemctl daemon-reload 2>/dev/null || true
    rm -f /usr/local/bin/alfred-agent
    rm -rf /opt/alfred-agent "$DEFAULT_CONFIG_DIR"
  fi
  echo "Alfred Device Monitor removed from this device."
}

usage() {
  cat <<EOF
Alfred Device Monitor $AGENT_VERSION

Usage: sudo alfred-agent <command>

  checkin             Report device posture (enrolls automatically if needed)
  enroll              Register this device with Alfred
  status              Show local configuration and registration state
  check-registration  Ask Alfred whether this device is registered (exit 3 if not)
  report              Print the JSON report without sending it
  uninstall           Remove the agent, its scheduler, and its configuration
  version             Print the agent version
EOF
}

case "${1:-}" in
  checkin) cmd_checkin ;;
  enroll) cmd_enroll ;;
  status) cmd_status ;;
  check-registration) cmd_check_registration ;;
  report) cmd_report ;;
  uninstall) cmd_uninstall ;;
  version | --version) echo "$AGENT_VERSION" ;;
  help | --help | -h | "") usage ;;
  *)
    usage >&2
    exit 2
    ;;
esac
