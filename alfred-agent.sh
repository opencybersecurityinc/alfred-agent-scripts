#!/usr/bin/env bash
# Alfred Device Monitor agent for macOS and Linux.
# Reports device posture (hardware UUID, OS, serial, disk encryption) and the AI clients
# and MCP servers configured on the device to the Alfred API.
set -euo pipefail
umask 077
export LC_ALL=C
export PATH="/usr/bin:/bin:/usr/sbin:/sbin"

readonly AGENT_VERSION="1.1.0"
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
  # The opt-in can come from the environment or from the root-only config,
  # where the installer records it because sudo and schedulers drop the env.
  if { [ "${ALFRED_ALLOW_INSECURE_LOCALHOST:-}" = "1" ] ||
    [ "$(conf_get ALLOW_INSECURE_LOCALHOST || true)" = "1" ]; } &&
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
  ACTIVATION_NONCE="$(conf_get ACTIVATION_NONCE || true)"
  [[ "$ACTIVATION_NONCE" =~ ^[0-9]{13}$ ]] || ACTIVATION_NONCE=""
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
  [ -z "${ACTIVATION_NONCE:-}" ] || body+=",\"activationNonce\":$ACTIVATION_NONCE"
  if [ "$include_owner" = "1" ]; then
    body+=",\"ownerEmail\":$(json_string "$OWNER_EMAIL" 320)"
  fi
  printf '{%s}' "$body"
}

# ── AI clients and MCP servers ───────────────────────────────────────────────

# The collector is Perl with the core JSON::PP module so it runs on a stock
# macOS or Linux install without Python or Node. It reads AI client configs
# from each local user's home, masks secrets, and prints the report JSON.
ai_scan_program() {
  cat <<'PERL'
use strict;
use warnings;
use JSON::PP ();

# Discovers AI clients and their configured MCP servers. Only client ids,
# server names, transports, masked launch identities and declared tool names
# leave this process; env values, headers and query strings never do.

my $PLATFORM = $ENV{ALFRED_AI_SCAN_PLATFORM} || ($^O eq 'darwin' ? 'macos' : 'linux');
my $SYS = $ENV{ALFRED_AI_SCAN_ROOT} // '';
my $MAX_FILE = 1_048_576;
my $MAX_PROJECTS = 200;
my $MAX_SERVERS = 300;
my $MAX_TOOLS = 200;
my $PH = '{secret}';
my $JSON = JSON::PP->new->utf8->relaxed->allow_nonref;

my @SECRET_PREFIXES = qw(sk- sk_live_ sk_test_ pk_live_ rk_live_ ghp_ gho_ ghu_ ghs_ ghr_
  github_pat_ glpat- xoxa- xoxb- xoxp- xoxr- xoxs- xapp- AKIA AIza eyJ npm_ hf_ pypi- dop_v1_ sq0atp-);
my %SENSITIVE_WORDS = map { $_ => 1 }
  qw(key token secret password passwd pwd pass auth credential credentials bearer signature sig apikey);
my %NON_SECRET_FLAGS = map { $_ => 1 } qw(-y --yes -n --no --verbose --debug --quiet -q --version
  -v --help -h --port -p --host --name --config -c --output -o --input -i --dir --cwd --format
  --level --log-level --timeout --retry --max-retries --transport --stdio);

# ── Secret templating ───────────────────────────────────────────────────────

sub sensitive_name {
  my ($name) = @_;
  $name = lc $name;
  $name =~ s/^-+//;
  return 0 if $NON_SECRET_FLAGS{"--$name"} || $NON_SECRET_FLAGS{"-$name"};
  for my $part (split /[-_.]+/, $name) {
    return 1 if $SENSITIVE_WORDS{$part} || $part =~ /(?:apikey|token|secret|password)$/;
  }
  return 0;
}

sub high_entropy {
  my ($v) = @_;
  return 0 if length($v) < 32 || $v !~ m{^[A-Za-z0-9+/_=.-]+$} || $v =~ m{^[./~]};
  my $classes = ($v =~ /[a-z]/ ? 1 : 0) + ($v =~ /[A-Z]/ ? 1 : 0) + ($v =~ /[0-9]/ ? 1 : 0);
  return 0 if $classes < 3;
  my %freq;
  $freq{$_}++ for split //, $v;
  my $bits = 0;
  for my $n (values %freq) { my $p = $n / length $v; $bits -= $p * log($p) / log(2); }
  return $bits >= 4.0;
}

sub secret_value {
  my ($v) = @_;
  return 0 unless defined $v && length $v >= 8;
  return 0 if $v =~ /^\$\{?[A-Za-z_][A-Za-z0-9_:-]*\}?$/;    # an env reference, not a value
  for my $prefix (@SECRET_PREFIXES) {
    return 1 if index($v, $prefix) == 0 && length($v) >= length($prefix) + 8;
  }
  return high_entropy($v);
}

sub template_url {
  my ($url) = @_;
  $url =~ s/[?#].*\z//s;
  $url =~ s{^([A-Za-z][A-Za-z0-9+.-]*://)[^/\@]*\@}{$1};
  my ($head, $path) = $url =~ m{^([A-Za-z][A-Za-z0-9+.-]*://[^/]*)(.*)\z}s ? ($1, $2) : ('', $url);
  $path = join '/', map { secret_value($_) ? $PH : $_ } split m{/}, $path, -1;
  return $head . $path;
}

sub template_token {
  my ($v) = @_;
  return template_url($v) if $v =~ m{^[A-Za-z][A-Za-z0-9+.-]*://};
  if ($v =~ /^((?:authorization|x-api-key|api-key|cookie)\s*:\s*)(.+)\z/si) {
    return "$1$PH";
  }
  return "$1 $PH" if $v =~ /^(bearer|basic|token)\s+\S{8,}\z/i;
  if ($v =~ /^([A-Za-z_][A-Za-z0-9_.-]*)=(.*)\z/s) {
    my ($k, $val) = ($1, $2);
    return "$k=$PH" if length $val && (sensitive_name($k) || secret_value($val));
    return "$k=" . template_url($val) if $val =~ m{^[A-Za-z][A-Za-z0-9+.-]*://};
    return $v;
  }
  return secret_value($v) ? $PH : $v;
}

sub template_args {
  my @out;
  my $mask_next = 0;
  for my $arg (@_) {
    next unless defined $arg && !ref $arg;
    if ($mask_next && $arg !~ /^-/) {
      push @out, $PH;
      $mask_next = 0;
      next;
    }
    $mask_next = 0;
    if ($arg =~ /^(--?[A-Za-z0-9][A-Za-z0-9_.-]*)=(.*)\z/s) {
      my ($flag, $val) = ($1, $2);
      if (!$NON_SECRET_FLAGS{lc $flag} && length $val && (sensitive_name($flag) || secret_value($val))) {
        push @out, "$flag=$PH";
      } else {
        push @out, "$flag=" . template_token($val);
      }
    } elsif ($arg =~ /^--?[A-Za-z0-9]/) {
      push @out, $arg;
      $mask_next = sensitive_name($arg) && !$NON_SECRET_FLAGS{lc $arg};
    } else {
      push @out, template_token($arg);
    }
  }
  return @out;
}

# ── Safe file reading and parsing ───────────────────────────────────────────

# Reads a regular file of at most 1 MB whose link and target are owned by the
# home's owner (root for system scope), so a link planted in a home cannot make
# a root scan read files that belong to someone else.
sub read_owned {
  my ($path, $uid) = @_;
  my @l = lstat $path or return undef;
  my @s = -l _ ? (stat $path) : @l;
  return undef unless @s && -f _;
  return undef if $s[7] > $MAX_FILE;
  my %trusted = ($uid => 1);
  $trusted{$>} = 1 if $> != 0;    # unprivileged runs (tests, ai-scan by a user) read their own files
  return undef unless $trusted{ $s[4] } && $trusted{ $l[4] };
  open my $fh, '<:raw', $path or return undef;
  local $/;
  my $data = <$fh>;
  close $fh;
  return $data;
}

# Removes // and /* */ comments outside strings plus trailing commas (JSONC).
sub strip_jsonc {
  my ($text) = @_;
  my $out = '';
  my $len = length $text;
  my ($i, $in_str) = (0, 0);
  while ($i < $len) {
    my $c = substr $text, $i, 1;
    if ($in_str) {
      $out .= $c;
      if ($c eq '\\' && $i + 1 < $len) { $out .= substr $text, $i + 1, 1; $i += 2; next; }
      $in_str = 0 if $c eq '"';
      $i++;
      next;
    }
    my $two = substr $text, $i, 2;
    if ($two eq '//') { my $nl = index $text, "\n", $i; $i = $nl < 0 ? $len : $nl; next; }
    if ($two eq '/*') { my $end = index $text, '*/', $i + 2; $i = $end < 0 ? $len : $end + 2; next; }
    $in_str = 1 if $c eq '"';
    $out .= $c;
    $i++;
  }
  $out =~ s/,(\s*[}\]])/$1/g;
  return $out;
}

sub read_json {
  my ($path, $uid) = @_;
  my $data = read_owned($path, $uid);
  return undef unless defined $data;
  $data =~ s/^\xEF\xBB\xBF//;
  my $doc = eval { $JSON->decode(strip_jsonc($data)) };
  return ref $doc eq 'HASH' ? $doc : undef;
}

sub toml_string {
  my ($s) = @_;
  if ($$s =~ /\G"((?:[^"\\]|\\.)*)"/gc) {
    my $v = $1;
    my %esc = (n => "\n", t => "\t", r => "\r", '"' => '"', '\\' => '\\', b => "\b", f => "\f");
    $v =~ s/\\u([0-9A-Fa-f]{4})/chr hex $1/ge;
    $v =~ s/\\(.)/exists $esc{$1} ? $esc{$1} : $1/ge;
    return $v;
  }
  return $1 if $$s =~ /\G'([^']*)'/gc;
  return undef;
}

sub toml_value {
  my ($s) = @_;
  $$s =~ /\G\s*/gc;
  my $str = toml_string($s);
  return $str if defined $str;
  if ($$s =~ /\G\[/gc) {
    my @items;
    while (1) {
      $$s =~ /\G(?:\s|,|#[^\n]*)*/gc;
      last if $$s =~ /\G\]/gc;
      my $v = toml_value($s);
      return \@items unless defined $v;
      push @items, $v;
    }
    return \@items;
  }
  return $1 eq 'true' ? JSON::PP::true : JSON::PP::false if $$s =~ /\G(true|false)\b/gc;
  return $1 if $$s =~ /\G([-+0-9.eE_:TZ]+)/gc;
  return undef;
}

# Parses the `[mcp_servers.<name>]` tables of a TOML document; other tables
# and nested `.env` / `.http_headers` tables are skipped.
sub read_toml_servers {
  my ($path, $uid) = @_;
  my $text = read_owned($path, $uid);
  return {} unless defined $text;
  my (%servers, $current);
  while ($text =~ /\G[ \t]*([^\n]*)(?:\n|\z)/gc) {
    my $line = $1;
    last if $line eq '' && pos($text) >= length $text;
    next if $line =~ /^\s*(?:#|$)/;
    if ($line =~ /^\[\s*([^\]]+?)\s*\]\s*(?:#.*)?$/) {
      my @parts = map { s/^\s+|\s+$//gr } ($1 =~ /("(?:[^"\\]|\\.)*"|'[^']*'|[^.]+)/g);
      s/^["']|["']$//g for @parts;
      $current = (@parts == 2 && $parts[0] eq 'mcp_servers') ? ($servers{$parts[1]} //= {}) : undef;
      next;
    }
    next unless $current && $line =~ /^([A-Za-z0-9_-]+|"[^"]+")\s*=\s*/;
    my $key = $1 =~ s/"//gr;
    my $rest = substr($line, $+[0]);
    my $buffer = $rest;
    if ($rest =~ /^\s*\[/ && ($rest =~ tr/[//) > ($rest =~ tr/]//)) {
      while ($text =~ /\G([^\n]*)(?:\n|\z)/gc) {
        $buffer .= "\n$1";
        last if ($buffer =~ tr/[//) <= ($buffer =~ tr/]//) || pos($text) >= length $text;
      }
    }
    my $value = toml_value(\$buffer);
    $current->{$key} = $value if defined $value;
  }
  return \%servers;
}

# ── Server normalization ────────────────────────────────────────────────────

sub clean_text {
  my ($v, $max) = @_;
  return undef unless defined $v && !ref $v;
  $v =~ s/[\x00-\x1f\x7f]+/ /g;
  $v =~ s/^\s+|\s+$//g;
  return length $v ? substr($v, 0, $max) : undef;
}

sub tool_names {
  my %seen;
  my @names = grep { defined && $_ ne '*' && !$seen{$_}++ } map { clean_text($_, 200) } @_;
  @names = sort @names;
  splice @names, $MAX_TOOLS if @names > $MAX_TOOLS;
  return \@names;
}

sub string_list {
  my ($v) = @_;
  return ref $v eq 'ARRAY' ? grep { defined && !ref } @$v : ();
}

sub server_entry {
  my ($client, $scope, $name, $cfg, $home, @extra_tools) = @_;
  $name = clean_text($name, 200);
  return undef unless defined $name && ref $cfg eq 'HASH';
  my $command = $cfg->{command};
  my @args = string_list($cfg->{args});
  if (ref $command eq 'HASH') {    # older nested form: {command: {path, args}}
    @args = string_list($command->{args});
    $command = $command->{path};
  }
  my ($url) = grep { defined && !ref && length } @{$cfg}{qw(url serverUrl httpUrl uri)};
  my ($transport, $identity);
  if (defined $url) {
    my $type = lc($cfg->{type} // $cfg->{transport} // '');
    $type = '' if ref $type;
    $transport = ($type =~ /sse/ || ($type eq '' && $url =~ m{/sse/?(?:[?#].*)?\z})) ? 'sse' : 'http';
    $identity = template_url($url);
  } elsif (defined $command && !ref $command && length $command) {
    $transport = 'stdio';
    $identity = join ' ', template_token($command), template_args(@args);
  } else {
    return undef;
  }
  if (defined $home && length $home > 1) {
    $identity =~ s{\Q$home\E(?=/|\s|\z)}{~}g;
  }
  $identity = clean_text($identity, 1000);
  return undef unless defined $identity;
  my @tools = (string_list($cfg->{tools}), string_list($cfg->{enabled_tools}),
    string_list($cfg->{alwaysAllow}), string_list($cfg->{autoApprove}), @extra_tools);
  return {
    client => $client,
    scope => $scope,
    name => $name,
    transport => $transport,
    identity => $identity,
    tools => tool_names(@tools),
  };
}

sub dig {
  my ($doc, $path) = @_;
  my $node = $doc;
  for my $key (split /\./, $path) {
    return undef unless ref $node eq 'HASH' && exists $node->{$key};
    $node = $node->{$key};
  }
  return $node;
}

# Claude Code grants tools as `mcp__<server>__<tool>`; map them back to servers.
sub granted_tools {
  my %by_server;
  for my $rule (@_) {
    next unless defined $rule && !ref $rule && $rule =~ /^mcp__(.+?)__(.+)\z/;
    push @{ $by_server{$1} }, $2;
  }
  return \%by_server;
}

sub servers_from {
  my ($client, $scope, $map, $home, $grants) = @_;
  return () unless ref $map eq 'HASH';
  $grants ||= {};
  my @out;
  for my $name (sort keys %$map) {
    my $entry = server_entry($client, $scope, $name, $map->{$name}, $home, @{ $grants->{$name} || [] });
    push @out, $entry if $entry;
  }
  return @out;
}

# ── Client catalog ──────────────────────────────────────────────────────────

use File::Glob qw(bsd_glob);

my $AS = $PLATFORM eq 'macos' ? 'Library/Application Support' : '.config';
my $CLINE = 'globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json';
my $MANAGED = $PLATFORM eq 'macos'
  ? '/Library/Application Support/ClaudeCode/managed-mcp.json'
  : '/etc/claude-code/managed-mcp.json';

# Each config is [path, format, key paths separated by |, scope]. Paths are
# home-relative unless they start with `/`, and may contain globs.
my @CATALOG = (
  { id => 'claude_code', name => 'Claude Code', detect => ['.claude.json', '.claude'],
    configs => [['.claude.json', 'json', 'mcpServers', 'user'],
      ['.claude/mcp_servers.json', 'json', 'mcpServers', 'user'],
      [$MANAGED, 'json', 'mcpServers', 'system']] },
  { id => 'claude_desktop', name => 'Claude Desktop', app => 'Claude', detect => ["$AS/Claude"],
    configs => [["$AS/Claude/claude_desktop_config.json", 'json', 'mcpServers', 'user']] },
  { id => 'codex', name => 'Codex', detect => ['.codex'],
    configs => [['.codex/config.toml', 'toml', 'mcp_servers', 'user']] },
  { id => 'cursor', name => 'Cursor', app => 'Cursor', detect => ['.cursor', "$AS/Cursor"],
    configs => [['.cursor/mcp.json', 'json', 'mcpServers', 'user']] },
  { id => 'vscode', name => 'Visual Studio Code', app => 'Visual Studio Code', detect => ["$AS/Code/User"],
    configs => [["$AS/Code/User/mcp.json", 'json', 'servers', 'user'],
      ["$AS/Code/User/profiles/*/mcp.json", 'json', 'servers', 'user'],
      ["$AS/Code/User/settings.json", 'json', 'mcp.servers', 'user']] },
  { id => 'vscode_insiders', name => 'Visual Studio Code - Insiders', app => 'Visual Studio Code - Insiders',
    detect => ["$AS/Code - Insiders/User"],
    configs => [["$AS/Code - Insiders/User/mcp.json", 'json', 'servers', 'user'],
      ["$AS/Code - Insiders/User/settings.json", 'json', 'mcp.servers', 'user']] },
  { id => 'cline', name => 'Cline', detect => ["$AS/Code/User/$CLINE"],
    configs => [["$AS/Code/User/$CLINE", 'json', 'mcpServers', 'user']] },
  { id => 'windsurf', name => 'Windsurf', app => 'Windsurf', detect => ['.codeium/windsurf'],
    configs => [['.codeium/windsurf/mcp_config.json', 'json', 'mcpServers', 'user']] },
  { id => 'zed', name => 'Zed', app => 'Zed', detect => ['.config/zed'],
    configs => [['.config/zed/settings.json', 'json', 'context_servers|assistant.mcp_servers', 'user']] },
  { id => 'jetbrains', name => 'JetBrains IDEs', detect => ["$AS/JetBrains/*/mcp"],
    configs => [["$AS/JetBrains/*/mcp/servers.json", 'json', 'mcpServers', 'user']] },
  { id => 'junie', name => 'Junie', detect => ['.junie'],
    configs => [['.junie/mcp/mcp.json', 'json', 'mcpServers', 'user']] },
  { id => 'copilot_cli', name => 'GitHub Copilot CLI', detect => ['.copilot'],
    configs => [['.copilot/mcp-config.json', 'json', 'mcpServers', 'user']] },
  { id => 'gemini_cli', name => 'Gemini CLI', detect => ['.gemini'],
    configs => [['.gemini/settings.json', 'json', 'mcpServers', 'user']] },
  { id => 'amazon_q', name => 'Amazon Q Developer', detect => ['.aws/amazonq'],
    configs => [['.aws/amazonq/mcp.json', 'json', 'mcpServers', 'user']] },
);

sub expand {
  my ($path, $home) = @_;
  my $full = $path =~ m{^/} ? "$SYS$path" : "$home/$path";
  return $full =~ /[*?\[]/ ? bsd_glob($full, File::Glob::GLOB_NOSORT() | File::Glob::GLOB_QUOTE()) : ($full);
}

sub app_version {
  my ($app, $home) = @_;
  for my $plist ("$SYS/Applications/$app.app/Contents/Info.plist", "$home/Applications/$app.app/Contents/Info.plist") {
    my @s = stat $plist or next;
    next unless -f _ && $s[7] <= $MAX_FILE && open my $fh, '<:raw', $plist;
    local $/;
    my $xml = <$fh>;
    close $fh;
    return ['installed', clean_text($1, 50)]
      if $xml =~ m{<key>CFBundleShortVersionString</key>\s*<string>([^<]{1,50})</string>};
    return ['installed', undef];
  }
  return undef;
}

sub claude_code_extras {
  my ($home, $uid, $user_grants) = @_;
  my @out;
  my $doc = read_json("$home/.claude.json", $uid) or return ();
  my $projects = $doc->{projects};
  return () unless ref $projects eq 'HASH';
  my $count = 0;
  for my $dir (sort keys %$projects) {
    last if ++$count > $MAX_PROJECTS;
    my $project = $projects->{$dir};
    next unless ref $project eq 'HASH' && $dir =~ m{^/};
    my $root = "$SYS$dir";
    my %grants = %{ granted_tools(string_list($project->{allowedTools})) };
    for my $file ("$root/.claude/settings.json", "$root/.claude/settings.local.json") {
      my $settings = read_json($file, $uid) or next;
      my $more = granted_tools(string_list(dig($settings, 'permissions.allow')));
      push @{ $grants{$_} }, @{ $more->{$_} } for keys %$more;
    }
    push @out, servers_from('claude_code', 'project', $project->{mcpServers}, $home, \%grants);
    my $mcp = read_json("$root/.mcp.json", $uid);
    push @out, servers_from('claude_code', 'project', $mcp->{mcpServers}, $home, \%grants) if $mcp;
  }
  return @out;
}

sub user_grants {
  my ($home, $uid) = @_;
  my %grants;
  for my $file ("$home/.claude/settings.json", "$home/.claude/settings.local.json") {
    my $settings = read_json($file, $uid) or next;
    my $more = granted_tools(string_list(dig($settings, 'permissions.allow')));
    push @{ $grants{$_} }, @{ $more->{$_} } for keys %$more;
  }
  return \%grants;
}

# ── Scan ────────────────────────────────────────────────────────────────────

sub homes {
  if (defined $ENV{ALFRED_AI_SCAN_HOMES}) {
    return map { [$_, (stat $_)[4]] } grep { length && -d } split /\n/, $ENV{ALFRED_AI_SCAN_HOMES};
  }
  if ($> != 0) {
    my @pw = getpwuid $>;
    my $dir = $pw[7] // $ENV{HOME};
    return defined $dir && -d $dir ? ([$dir, $>]) : ();
  }
  my $min = $PLATFORM eq 'macos' ? 500 : 1000;
  my (%seen, @homes);
  while (my @pw = getpwent) {
    my ($uid, $dir, $shell) = @pw[2, 7, 8];
    next unless $uid == 0 || ($uid >= $min && $uid < 65534);
    next if !defined $dir || $dir eq '/' || $dir =~ m{^/(?:var/empty|nonexistent|dev/null)} || !-d $dir;
    next if $uid != 0 && defined $shell && $shell =~ m{/(?:nologin|false)\z};
    next if $seen{$dir}++;
    push @homes, [$dir, $uid];
  }
  endpwent();
  if ($PLATFORM eq 'macos') {
    for my $dir (bsd_glob('/Users/*')) {
      next if $seen{$dir} || $dir =~ m{/(?:Shared|Guest)\z} || !-d $dir;
      my $uid = (stat $dir)[4];
      next if $uid < $min;
      $seen{$dir}++;
      push @homes, [$dir, $uid];
    }
  }
  return @homes;
}

my (%clients, %servers, %system_done);
for my $entry (homes()) {
  my ($home, $uid) = @$entry;
  for my $client (@CATALOG) {
    my $id = $client->{id};
    my @found;
    my $grants = $id eq 'claude_code' ? user_grants($home, $uid) : {};
    for my $config (@{ $client->{configs} }) {
      my ($path, $format, $keys, $scope) = @$config;
      if ($scope eq 'system') {
        next if $system_done{"$id:$path"}++;
      }
      for my $file (expand($path, $home)) {
        my $owner = $scope eq 'system' ? 0 : $uid;
        my $base = $scope eq 'system' ? undef : $home;
        if ($format eq 'toml') {
          push @found, servers_from($id, $scope, read_toml_servers($file, $owner), $base, $grants);
          next;
        }
        my $doc = read_json($file, $owner) or next;
        for my $key (split /\|/, $keys) {
          push @found, servers_from($id, $scope, dig($doc, $key), $base, $grants);
        }
      }
    }
    push @found, claude_code_extras($home, $uid) if $id eq 'claude_code';
    my $app = $client->{app} && $PLATFORM eq 'macos' ? app_version($client->{app}, $home) : undef;
    my $present = @found || $app || grep { -e $_ } map { expand($_, $home) } @{ $client->{detect} };
    next unless $present;
    my $record = $clients{$id} //= { client => $id, name => $client->{name} };
    $record->{version} //= $app->[1] if $app && defined $app->[1];
    for my $server (@found) {
      my $key = join "\0", @{$server}{qw(client scope name identity)};
      if (my $prev = $servers{$key}) {
        $prev->{tools} = tool_names(@{ $prev->{tools} }, @{ $server->{tools} });
      } else {
        $servers{$key} = $server;
      }
    }
  }
}

my @clients = map { $clients{$_} } sort keys %clients;
splice @clients, 32 if @clients > 32;
my %kept = map { $_->{client} => 1 } @clients;
my @servers = grep { $kept{ $_->{client} } } map { $servers{$_} } sort keys %servers;
if (@servers > $MAX_SERVERS) {
  warn sprintf "alfred-agent: %d MCP servers found; reporting the first %d\n", scalar @servers, $MAX_SERVERS;
  splice @servers, $MAX_SERVERS;
}
my %report = (clients => \@clients, servers => \@servers);
$report{hardwareUuid} = $ENV{ALFRED_AI_SCAN_UUID} if $ENV{ALFRED_AI_SCAN_UUID};
my $out = JSON::PP->new->utf8->canonical;
$out->pretty if $ENV{ALFRED_AI_SCAN_PRETTY};
print $out->encode(\%report), ($ENV{ALFRED_AI_SCAN_PRETTY} ? '' : "\n");
PERL
}

ai_scan_available() {
  command -v perl >/dev/null 2>&1 && perl -MJSON::PP -e 1 >/dev/null 2>&1
}

ai_scan_json() {
  ai_scan_program | ALFRED_AI_SCAN_PLATFORM="${ALFRED_AI_SCAN_PLATFORM:-$PLATFORM}" ALFRED_AI_SCAN_UUID="${1:-}" \
    ALFRED_AI_SCAN_PRETTY="${2:-}" perl -
}

ai_inventory_enabled() {
  case "$(conf_get AI_INVENTORY || true)" in off | false | 0) return 1 ;; esac
  return 0
}

send_ai_inventory() {
  local uuid body
  if ! ai_inventory_enabled; then
    log "AI inventory disabled in $CONFIG_FILE"
    return 0
  fi
  if ! ai_scan_available; then
    log "AI inventory skipped: perl with JSON::PP is not installed"
    return 0
  fi
  uuid="$(hardware_uuid)" || return 0
  body="$(ai_scan_json "$uuid")" || {
    log "AI inventory scan failed"
    return 0
  }
  api_request POST /v1/agent/ai-inventory "$body"
  case "$API_STATUS" in
    200) log "AI inventory ok ($RESPONSE_BODY)" ;;
    403) log "AI inventory is not enabled for this workspace" ;;
    *) log "AI inventory not sent: $(describe_failure "$API_STATUS")" ;;
  esac
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
          send_ai_inventory
          return 0
          ;;
        *) die "check-in failed: $(describe_failure "$status")" ;;
      esac
      ;;
    *) die "check-in failed: $(describe_failure "$status")" ;;
  esac
  send_ai_inventory
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

scheduler_running() {
  if [ "$PLATFORM" = "macos" ]; then
    launchctl print system/com.alfred.devicemonitor >/dev/null 2>&1
  else
    systemctl is-active --quiet alfred-agent.timer 2>/dev/null
  fi
}

# Exit 0 when the schedule runs and Alfred knows the device, 2 when it runs
# but the device is not (or not yet) registered, and 1 when it is not running.
cmd_status() {
  require_root
  load_config
  local running=0 registration=0
  echo "Alfred Device Monitor $AGENT_VERSION ($PLATFORM)"
  echo "API:          $API_URL"
  echo "Region:       $REGION"
  echo "Owner:        $OWNER_EMAIL"
  echo "Hardware:     $(hardware_uuid || echo unsupported)"
  echo "Encrypted:    $(disk_encrypted | grep . || echo unknown)"
  if ai_inventory_enabled; then
    if ai_scan_available; then echo "AI inventory: on"; else echo "AI inventory: unavailable (needs perl with JSON::PP)"; fi
  else
    echo "AI inventory: off"
  fi
  if scheduler_running; then
    running=1
    echo "Scheduler:    running"
  else
    echo "Scheduler:    not running"
  fi
  printf 'Registration: '
  (cmd_check_registration) || registration=$?
  if [ "$running" -eq 0 ]; then return 1; fi
  if [ "$registration" -ne 0 ]; then return 2; fi
  return 0
}

cmd_report() {
  require_root
  load_config
  device_report 1
  echo
}

cmd_ai_scan() {
  ai_scan_available || die "the AI inventory needs perl with the JSON::PP module"
  ai_scan_json "" 1
}

cmd_ai_report() {
  require_root
  load_config
  send_ai_inventory
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
  status              Show configuration and state (exit 0 running, 2 not registered, 1 stopped)
  check-registration  Ask Alfred whether this device is registered (exit 3 if not)
  report              Print the JSON report without sending it
  ai-scan             Print the AI clients and MCP servers found, secrets masked
  ai-report           Send the AI inventory now
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
  ai-scan) cmd_ai_scan ;;
  ai-report) cmd_ai_report ;;
  uninstall) cmd_uninstall ;;
  version | --version) echo "$AGENT_VERSION" ;;
  help | --help | -h | "") usage ;;
  *)
    usage >&2
    exit 2
    ;;
esac
