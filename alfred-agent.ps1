<#
.SYNOPSIS
  Alfred Device Monitor agent for Windows.
.DESCRIPTION
  Reports this computer's posture to Alfred. Installed by install-windows.ps1 and run hourly
  by the "Alfred Device Monitor" scheduled task as SYSTEM.

  Commands: checkin, enroll, status, check-registration, report, ai-scan, ai-report, uninstall,
  version, help
#>
[CmdletBinding()]
param([Parameter(Position = 0)][string]$Command = 'help')

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$AgentVersion = '1.1.0'
$TaskName = 'Alfred Device Monitor'
$ConfigDir = if ($env:ALFRED_CONFIG_DIR) { $env:ALFRED_CONFIG_DIR } else { Join-Path $env:ProgramData 'Alfred Device Monitor' }
$ConfigFile = Join-Path $ConfigDir 'agent.conf'
$KeyFile = Join-Path $ConfigDir 'agent.key'
$LogFile = Join-Path $ConfigDir 'alfred-agent.log'

$KeyPattern = '^alfa_[A-Za-z0-9_-]{32,64}$'
$EmailPattern = '^[^\s@"\\]{1,64}@[^\s@"\\]{1,255}$'
$UuidPattern = '^[A-Za-z0-9-]{8,64}$'
$BadUuids = @(
  'FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF',
  'AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA',
  '00000000-0000-0000-0000-000000000000',
  '11111111-1111-1111-1111-111111111111',
  '03000200-0400-0500-0006-000700080009',
  '03020100-0504-0706-0809-0A0B0C0D0E0F',
  '10000000-0000-8000-0040-000000000000',
  '01234567-8910-1112-1314-151617181920'
)

function Stop-Agent([string]$Message) { throw $Message }

function Write-AgentLog([string]$Message) {
  $line = '{0} alfred-agent: {1}' -f (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'), $Message
  Write-Output $line
  try {
    if ((Test-Path -LiteralPath $LogFile) -and (Get-Item -LiteralPath $LogFile).Length -gt 1MB) {
      Move-Item -LiteralPath $LogFile -Destination "$LogFile.1" -Force
    }
    Add-Content -LiteralPath $LogFile -Value $line -Encoding UTF8
  } catch { Write-Verbose "log write failed: $_" }
}

function Assert-Admin {
  if ($env:ALFRED_CONFIG_DIR) { return }
  $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Stop-Agent 'this command must run as Administrator'
  }
}

# The config directory must only be accessible to SYSTEM and Administrators.
function Assert-PrivateConfig {
  if ($env:ALFRED_CONFIG_DIR) { return }
  $allowed = @('S-1-5-18', 'S-1-5-32-544')
  $acl = Get-Acl -LiteralPath $ConfigDir
  foreach ($rule in $acl.Access) {
    $sid = try { $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { '' }
    if ($rule.AccessControlType -eq 'Allow' -and $allowed -notcontains $sid) {
      Stop-Agent "$ConfigDir grants access to $($rule.IdentityReference); reinstall the Alfred Device Monitor"
    }
  }
}

function Test-ApiUrl([string]$Url) {
  if ($Url -match '^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$') { return $true }
  return ($env:ALFRED_ALLOW_INSECURE_LOCALHOST -eq '1' -and
    $Url -match '^http://(localhost|127\.0\.0\.1)(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$')
}

function Read-AgentConfig {
  foreach ($file in @($ConfigFile, $KeyFile)) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
      Stop-Agent "missing $file; reinstall the Alfred Device Monitor"
    }
  }
  Assert-PrivateConfig
  $values = @{}
  foreach ($line in Get-Content -LiteralPath $ConfigFile -Encoding UTF8) {
    if ($line -match '^\s*(#|$)') { continue }
    $index = $line.IndexOf('=')
    if ($index -gt 0) { $values[$line.Substring(0, $index)] = $line.Substring($index + 1) }
  }
  $config = [pscustomobject]@{
    ApiUrl     = ([string]$values['API_URL']).TrimEnd('/')
    OwnerEmail = [string]$values['OWNER_EMAIL']
    Region     = if ($values['REGION']) { [string]$values['REGION'] } else { 'us' }
    Key        = (Get-Content -LiteralPath $KeyFile -Raw -Encoding UTF8).Trim()
    Nonce      = [string]$values['ACTIVATION_NONCE']
    AiInventory = [string]$values['AI_INVENTORY']
  }
  if ($config.Nonce -and $config.Nonce -notmatch '^\d{13}$') { Stop-Agent 'ACTIVATION_NONCE must be epoch milliseconds' }
  if (-not (Test-ApiUrl $config.ApiUrl)) { Stop-Agent 'API_URL must be an https:// URL' }
  if ($config.OwnerEmail -notmatch $EmailPattern) { Stop-Agent 'OWNER_EMAIL is not a valid email address' }
  if ($config.Key -notmatch $KeyPattern) { Stop-Agent "$KeyFile does not contain a valid agent key" }
  return $config
}

# ── Device facts ─────────────────────────────────────────────────────────────

function Get-CimValue([string]$Class, [string]$Property) {
  try { return [string](Get-CimInstance -ClassName $Class -ErrorAction Stop | Select-Object -First 1).$Property }
  catch { return '' }
}

function Get-HardwareUuid {
  $uuid = (Get-CimValue 'Win32_ComputerSystemProduct' 'UUID').Trim().ToUpperInvariant()
  if (-not $uuid -and $env:ALFRED_CONFIG_DIR -and $env:ALFRED_TEST_HARDWARE_UUID) { $uuid = $env:ALFRED_TEST_HARDWARE_UUID }
  if ($uuid -notmatch $UuidPattern -or $BadUuids -contains $uuid) { return $null }
  return $uuid
}

# Returns $true, $false, or $null when BitLocker state cannot be determined.
function Get-DiskEncrypted {
  try {
    $volume = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
    return ([string]$volume.ProtectionStatus -eq 'On')
  } catch {
    try {
      $volume = Get-CimInstance -Namespace 'root/cimv2/Security/MicrosoftVolumeEncryption' `
        -ClassName 'Win32_EncryptableVolume' -Filter "DriveLetter='$($env:SystemDrive)'" -ErrorAction Stop
      if ($null -eq $volume) { return $null }
      return ([int]$volume.ProtectionStatus -eq 1)
    } catch { return $null }
  }
}

function Limit-Text([string]$Value, [int]$Max) {
  $clean = ($Value -replace '[\x00-\x1F\x7F]', '').Trim()
  if ($clean.Length -gt $Max) { $clean = $clean.Substring(0, $Max) }
  return $clean
}

function New-DeviceReport($Config, [bool]$IncludeOwner) {
  $uuid = Get-HardwareUuid
  if (-not $uuid) { Stop-Agent 'no unique hardware UUID found; this device is not supported' }
  $report = [ordered]@{ hardwareUuid = $uuid; agentVersion = $AgentVersion }
  $facts = @(
    @('hostname', $env:COMPUTERNAME, 200),
    @('os', (Get-CimValue 'Win32_OperatingSystem' 'Caption'), 100),
    @('osVersion', (Get-CimValue 'Win32_OperatingSystem' 'Version'), 50),
    @('serial', (Get-CimValue 'Win32_BIOS' 'SerialNumber'), 100)
  )
  foreach ($fact in $facts) {
    $value = Limit-Text $fact[1] $fact[2]
    if ($value) { $report[$fact[0]] = $value }
  }
  $encrypted = Get-DiskEncrypted
  if ($null -ne $encrypted) { $report['isEncrypted'] = [bool]$encrypted }
  if ($IncludeOwner) { $report['ownerEmail'] = Limit-Text $Config.OwnerEmail 320 }
  if ($Config.Nonce) { $report['activationNonce'] = [long]$Config.Nonce }
  return $report
}

# ── AI clients and MCP servers ───────────────────────────────────────────────

# Discovers AI clients and their configured MCP servers in each local profile.
# Only client ids, server names, transports, masked launch identities and
# declared tool names are reported; env values, headers and query strings never are.

$AiSecret = '{secret}'
$AiMaxFile = 1MB
$AiMaxProjects = 200
$AiMaxServers = 300
$AiMaxTools = 200
$SecretPrefixes = @('sk-', 'sk_live_', 'sk_test_', 'pk_live_', 'rk_live_', 'ghp_', 'gho_', 'ghu_', 'ghs_', 'ghr_',
  'github_pat_', 'glpat-', 'xoxa-', 'xoxb-', 'xoxp-', 'xoxr-', 'xoxs-', 'xapp-', 'AKIA', 'AIza', 'eyJ', 'npm_', 'hf_',
  'pypi-', 'dop_v1_', 'sq0atp-')
$SensitiveWords = @('key', 'token', 'secret', 'password', 'passwd', 'pwd', 'pass', 'auth', 'credential', 'credentials',
  'bearer', 'signature', 'sig', 'apikey')
$NonSecretFlags = @('-y', '--yes', '-n', '--no', '--verbose', '--debug', '--quiet', '-q', '--version', '-v', '--help', '-h',
  '--port', '-p', '--host', '--name', '--config', '-c', '--output', '-o', '--input', '-i', '--dir', '--cwd', '--format',
  '--level', '--log-level', '--timeout', '--retry', '--max-retries', '--transport', '--stdio')
$UrlPattern = '^[A-Za-z][A-Za-z0-9+.-]*://'

function Test-SensitiveName([string]$Name) {
  $n = $Name.ToLowerInvariant().TrimStart('-')
  if ($NonSecretFlags -contains "--$n" -or $NonSecretFlags -contains "-$n") { return $false }
  foreach ($part in ($n -split '[-_.]+')) {
    if ($SensitiveWords -contains $part -or $part -match '(apikey|token|secret|password)$') { return $true }
  }
  return $false
}

function Test-HighEntropy([string]$Value) {
  if ($Value.Length -lt 32 -or $Value -cnotmatch '^[A-Za-z0-9+/_=.-]+$' -or $Value -match '^[./~]') { return $false }
  $classes = 0
  foreach ($class in '[a-z]', '[A-Z]', '[0-9]') { if ($Value -cmatch $class) { $classes++ } }
  if ($classes -lt 3) { return $false }
  $freq = New-Object 'System.Collections.Generic.Dictionary[char,int]'
  foreach ($c in $Value.ToCharArray()) { $freq[$c] = 1 + $(if ($freq.ContainsKey($c)) { $freq[$c] } else { 0 }) }
  $bits = 0.0
  foreach ($n in $freq.Values) { $p = $n / $Value.Length; $bits -= $p * [Math]::Log($p, 2) }
  return $bits -ge 4.0
}

function Test-SecretValue($Value) {
  if ($null -eq $Value) { return $false }
  $v = [string]$Value
  if ($v.Length -lt 8 -or $v -match '^\$\{?[A-Za-z_][A-Za-z0-9_:-]*\}?$') { return $false }
  foreach ($prefix in $SecretPrefixes) {
    if ($v.StartsWith($prefix, [StringComparison]::Ordinal) -and $v.Length -ge $prefix.Length + 8) { return $true }
  }
  return Test-HighEntropy $v
}

function Format-SecretUrl([string]$Url) {
  $u = $Url -replace '(?s)[?#].*\z', ''
  $u = $u -replace '^([A-Za-z][A-Za-z0-9+.-]*://)[^/@]*@', '$1'
  $head = ''
  $path = $u
  if ($u -match '(?s)^([A-Za-z][A-Za-z0-9+.-]*://[^/]*)(.*)\z') { $head = $Matches[1]; $path = $Matches[2] }
  $parts = foreach ($segment in ($path -split '/')) { if (Test-SecretValue $segment) { $AiSecret } else { $segment } }
  return $head + (@($parts) -join '/')
}

function Format-SecretToken([string]$Value) {
  if ($Value -match $UrlPattern) { return Format-SecretUrl $Value }
  if ($Value -match '(?si)^((?:authorization|x-api-key|api-key|cookie)\s*:\s*).+\z') { return $Matches[1] + $AiSecret }
  if ($Value -match '(?i)^(bearer|basic|token)\s+\S{8,}\z') { return "$($Matches[1]) $AiSecret" }
  if ($Value -match '(?s)^([A-Za-z_][A-Za-z0-9_.-]*)=(.*)\z') {
    $key = $Matches[1]
    $val = $Matches[2]
    if ($val.Length -and ((Test-SensitiveName $key) -or (Test-SecretValue $val))) { return "$key=$AiSecret" }
    if ($val -match $UrlPattern) { return "$key=$(Format-SecretUrl $val)" }
    return $Value
  }
  if (Test-SecretValue $Value) { return $AiSecret }
  return $Value
}

# A sensitive flag such as --api-key masks the value that follows it.
function Format-SecretArgs($Items) {
  $out = New-Object 'System.Collections.Generic.List[string]'
  $maskNext = $false
  foreach ($arg in $Items) {
    if ($maskNext -and $arg -notmatch '^-') { $out.Add($AiSecret); $maskNext = $false; continue }
    $maskNext = $false
    if ($arg -match '(?s)^(--?[A-Za-z0-9][A-Za-z0-9_.-]*)=(.*)\z') {
      $flag = $Matches[1]
      $val = $Matches[2]
      if ($NonSecretFlags -notcontains $flag.ToLowerInvariant() -and $val.Length -and
        ((Test-SensitiveName $flag) -or (Test-SecretValue $val))) { $out.Add("$flag=$AiSecret") }
      else { $out.Add("$flag=$(Format-SecretToken $val)") }
    } elseif ($arg -match '^--?[A-Za-z0-9]') {
      $out.Add($arg)
      $maskNext = (Test-SensitiveName $arg) -and $NonSecretFlags -notcontains $arg.ToLowerInvariant()
    } else {
      $out.Add((Format-SecretToken $arg))
    }
  }
  return , $out.ToArray()
}

# Removes // and /* */ comments outside strings plus trailing commas (JSONC).
function Remove-JsonComments([string]$Text) {
  $sb = New-Object Text.StringBuilder
  $len = $Text.Length
  $i = 0
  $inStr = $false
  while ($i -lt $len) {
    $c = $Text[$i]
    if ($inStr) {
      [void]$sb.Append($c)
      if ($c -eq [char]'\' -and $i + 1 -lt $len) { [void]$sb.Append($Text[$i + 1]); $i += 2; continue }
      if ($c -eq [char]'"') { $inStr = $false }
      $i++
      continue
    }
    if ($c -eq [char]'/' -and $i + 1 -lt $len -and $Text[$i + 1] -eq [char]'/') {
      $nl = $Text.IndexOf("`n", $i)
      $i = if ($nl -lt 0) { $len } else { $nl }
      continue
    }
    if ($c -eq [char]'/' -and $i + 1 -lt $len -and $Text[$i + 1] -eq [char]'*') {
      $end = $Text.IndexOf('*/', $i + 2)
      $i = if ($end -lt 0) { $len } else { $end + 2 }
      continue
    }
    if ($c -eq [char]'"') { $inStr = $true }
    [void]$sb.Append($c)
    $i++
  }
  return ($sb.ToString() -replace ',(\s*[}\]])', '$1')
}

function Read-AiJson([string]$Path) {
  try {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or $item.Length -gt $AiMaxFile) { return $null }
    $text = [IO.File]::ReadAllText($item.FullName, [Text.Encoding]::UTF8).TrimStart([char]0xFEFF)
    $doc = (Remove-JsonComments $text) | ConvertFrom-Json -ErrorAction Stop
    if ($doc -is [Management.Automation.PSCustomObject]) { return $doc }
  } catch { Write-Verbose "skipped $Path" }
  return $null
}

function Get-AiProp($Node, [string]$Name) {
  if ($Node -isnot [Management.Automation.PSCustomObject]) { return $null }
  $prop = $Node.PSObject.Properties[$Name]
  if ($prop) {
    if ($prop.Value -is [Array]) { return , $prop.Value }
    return $prop.Value
  }
  return $null
}

function Get-AiPath($Doc, [string]$Path) {
  $node = $Doc
  foreach ($key in $Path.Split('.')) {
    $node = Get-AiProp $node $key
    if ($null -eq $node) { return $null }
  }
  if ($node -is [Array]) { return , $node }
  return $node
}

function Get-StringList($Value) {
  if ($Value -isnot [Array]) { return , @() }
  return , @($Value | Where-Object { $_ -is [string] })
}

function Get-CleanText($Value, [int]$Max) {
  if ($Value -isnot [string]) { return $null }
  $v = ($Value -replace '[\x00-\x1F\x7F]+', ' ').Trim()
  if (-not $v) { return $null }
  if ($v.Length -gt $Max) { $v = $v.Substring(0, $Max) }
  return $v
}

function Get-ToolNames($Items) {
  $set = New-Object 'System.Collections.Generic.SortedSet[string]' ([StringComparer]::Ordinal)
  foreach ($item in $Items) {
    $name = Get-CleanText $item 200
    if ($name -and $name -ne '*') { [void]$set.Add($name) }
  }
  return , @($set | Select-Object -First $AiMaxTools)
}

function New-ServerEntry([string]$Client, [string]$Scope, [string]$Name, $Cfg, [string]$HomeDir, $ExtraTools) {
  $Name = Get-CleanText $Name 200
  if (-not $Name -or $Cfg -isnot [Management.Automation.PSCustomObject]) { return $null }
  $command = Get-AiProp $Cfg 'command'
  $argv = Get-StringList (Get-AiProp $Cfg 'args')
  if ($command -is [Management.Automation.PSCustomObject]) {
    $argv = Get-StringList (Get-AiProp $command 'args')
    $command = Get-AiProp $command 'path'
  }
  $url = $null
  foreach ($key in 'url', 'serverUrl', 'httpUrl', 'uri') {
    $candidate = Get-AiProp $Cfg $key
    if ($candidate -is [string] -and $candidate) { $url = $candidate; break }
  }
  if ($url) {
    $type = Get-AiProp $Cfg 'type'
    if ($null -eq $type) { $type = Get-AiProp $Cfg 'transport' }
    $type = if ($type -is [string]) { $type.ToLowerInvariant() } else { '' }
    $transport = if ($type -match 'sse' -or (-not $type -and $url -match '/sse/?([?#].*)?$')) { 'sse' } else { 'http' }
    $identity = Format-SecretUrl $url
  } elseif ($command -is [string] -and $command) {
    $transport = 'stdio'
    $identity = (@(Format-SecretToken $command) + (Format-SecretArgs $argv)) -join ' '
  } else {
    return $null
  }
  if ($HomeDir -and $HomeDir.Length -gt 3) {
    $identity = [regex]::Replace($identity, [regex]::Escape($HomeDir) + '(?=[\\/\s]|$)', '~',
      [Text.RegularExpressions.RegexOptions]::IgnoreCase)
  }
  $identity = Get-CleanText $identity 1000
  if (-not $identity) { return $null }
  $tools = @()
  foreach ($key in 'tools', 'enabled_tools', 'alwaysAllow', 'autoApprove') { $tools += Get-StringList (Get-AiProp $Cfg $key) }
  if ($ExtraTools) { $tools += @($ExtraTools) }
  return [ordered]@{
    client = $Client; scope = $Scope; name = $Name; transport = $transport; identity = $identity
    tools = (Get-ToolNames $tools)
  }
}

# Claude Code grants tools as mcp__<server>__<tool>; map them back to servers.
function Get-GrantedTools($Rules, [hashtable]$Into) {
  foreach ($rule in $Rules) {
    if ($rule -match '^mcp__(.+?)__(.+)$') {
      if (-not $Into.ContainsKey($Matches[1])) { $Into[$Matches[1]] = @() }
      $Into[$Matches[1]] += $Matches[2]
    }
  }
}

function Get-ServersFrom([string]$Client, [string]$Scope, $Map, [string]$HomeDir, [hashtable]$Grants) {
  if ($Map -isnot [Management.Automation.PSCustomObject]) { return }
  foreach ($prop in @($Map.PSObject.Properties | Sort-Object Name)) {
    $extra = if ($Grants -and $Grants.ContainsKey($prop.Name)) { $Grants[$prop.Name] } else { $null }
    $entry = New-ServerEntry $Client $Scope $prop.Name $prop.Value $HomeDir $extra
    if ($entry) { $entry }
  }
}
# Parses the [mcp_servers.<name>] tables of a Codex TOML file: string, boolean
# and string-array values only; other tables and nested tables are skipped.
function Read-AiToml([string]$Path) {
  $servers = [ordered]@{}
  try {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or $item.Length -gt $AiMaxFile -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { return $null }
    $lines = [IO.File]::ReadAllText($item.FullName, [Text.Encoding]::UTF8).TrimStart([char]0xFEFF) -split "`r?`n"
  } catch { return $null }
  $current = $null
  $str = '"((?:[^"\\]|\\.)*)"|''([^'']*)'''
  for ($n = 0; $n -lt $lines.Count; $n++) {
    $line = $lines[$n].Trim()
    if (-not $line -or $line.StartsWith('#')) { continue }
    if ($line -match '^\[\s*([^\]]+?)\s*\]\s*(#.*)?$') {
      $parts = @([regex]::Matches($Matches[1], '"(?:[^"\\]|\\.)*"|''[^'']*''|[^.]+') | ForEach-Object { $_.Value.Trim().Trim('"', "'") })
      $current = $null
      if ($parts.Count -eq 2 -and $parts[0] -eq 'mcp_servers') {
        if (-not $servers.Contains($parts[1])) { $servers[$parts[1]] = [pscustomobject]@{} }
        $current = $servers[$parts[1]]
      }
      continue
    }
    if (-not $current -or $line -notmatch '^([A-Za-z0-9_-]+|"[^"]+")\s*=\s*(.*)$') { continue }
    $key = $Matches[1].Trim('"')
    $rest = $Matches[2]
    while ($rest.TrimStart().StartsWith('[') -and ($rest.Split('[').Count -gt $rest.Split(']').Count) -and $n + 1 -lt $lines.Count) {
      $n++
      $rest += "`n" + $lines[$n]
    }
    $value = $null
    if ($rest -match "^\s*\[") {
      $value = @([regex]::Matches($rest, $str) | ForEach-Object {
          if ($_.Groups[1].Success) { [regex]::Unescape($_.Groups[1].Value) } else { $_.Groups[2].Value } })
    } elseif ($rest -match "^\s*(?:$str)") {
      $value = if ($null -ne $Matches[1] -and $rest.TrimStart().StartsWith('"')) { [regex]::Unescape($Matches[1]) } else { $Matches[2] }
    } elseif ($rest -match '^\s*(true|false)\b') {
      $value = $Matches[1] -eq 'true'
    }
    if ($null -ne $value) { $current | Add-Member -NotePropertyName $key -NotePropertyValue $value -Force }
  }
  return [pscustomobject]$servers
}

function Get-AiCatalog {
  $as = 'AppData\Roaming'
  $cline = 'globalStorage\saoudrizwan.claude-dev\settings\cline_mcp_settings.json'
  $managed = if ($env:ALFRED_AI_SCAN_SYSTEM) { $env:ALFRED_AI_SCAN_SYSTEM } elseif ($env:ProgramFiles) { Join-Path $env:ProgramFiles 'ClaudeCode\managed-mcp.json' } else { $null }
  # Each config is @(path, format, keys separated by |, scope); paths are home-relative unless rooted.
  return @(
    @{ id = 'claude_code'; name = 'Claude Code'; detect = @('.claude.json', '.claude')
      configs = @(@('.claude.json', 'json', 'mcpServers', 'user'), @('.claude\mcp_servers.json', 'json', 'mcpServers', 'user'),
        @($managed, 'json', 'mcpServers', 'system')) },
    @{ id = 'claude_desktop'; name = 'Claude Desktop'; detect = @("$as\Claude")
      configs = @(, @("$as\Claude\claude_desktop_config.json", 'json', 'mcpServers', 'user')) },
    @{ id = 'codex'; name = 'Codex'; detect = @('.codex'); configs = @(, @('.codex\config.toml', 'toml', 'mcp_servers', 'user')) },
    @{ id = 'cursor'; name = 'Cursor'; detect = @('.cursor', "$as\Cursor"); configs = @(, @('.cursor\mcp.json', 'json', 'mcpServers', 'user')) },
    @{ id = 'vscode'; name = 'Visual Studio Code'; detect = @("$as\Code\User")
      configs = @(@("$as\Code\User\mcp.json", 'json', 'servers', 'user'), @("$as\Code\User\profiles\*\mcp.json", 'json', 'servers', 'user'),
        @("$as\Code\User\settings.json", 'json', 'mcp.servers', 'user')) },
    @{ id = 'vscode_insiders'; name = 'Visual Studio Code - Insiders'; detect = @("$as\Code - Insiders\User")
      configs = @(@("$as\Code - Insiders\User\mcp.json", 'json', 'servers', 'user'), @("$as\Code - Insiders\User\settings.json", 'json', 'mcp.servers', 'user')) },
    @{ id = 'cline'; name = 'Cline'; detect = @("$as\Code\User\$cline"); configs = @(, @("$as\Code\User\$cline", 'json', 'mcpServers', 'user')) },
    @{ id = 'windsurf'; name = 'Windsurf'; detect = @('.codeium\windsurf'); configs = @(, @('.codeium\windsurf\mcp_config.json', 'json', 'mcpServers', 'user')) },
    @{ id = 'zed'; name = 'Zed'; detect = @("$as\Zed"); configs = @(, @("$as\Zed\settings.json", 'json', 'context_servers|assistant.mcp_servers', 'user')) },
    @{ id = 'jetbrains'; name = 'JetBrains IDEs'; detect = @("$as\JetBrains\*\mcp"); configs = @(, @("$as\JetBrains\*\mcp\servers.json", 'json', 'mcpServers', 'user')) },
    @{ id = 'junie'; name = 'Junie'; detect = @('.junie'); configs = @(, @('.junie\mcp\mcp.json', 'json', 'mcpServers', 'user')) },
    @{ id = 'copilot_cli'; name = 'GitHub Copilot CLI'; detect = @('.copilot'); configs = @(, @('.copilot\mcp-config.json', 'json', 'mcpServers', 'user')) },
    @{ id = 'gemini_cli'; name = 'Gemini CLI'; detect = @('.gemini'); configs = @(, @('.gemini\settings.json', 'json', 'mcpServers', 'user')) },
    @{ id = 'amazon_q'; name = 'Amazon Q Developer'; detect = @('.aws\amazonq'); configs = @(, @('.aws\amazonq\mcp.json', 'json', 'mcpServers', 'user')) }
  )
}

# Expands a catalog path; reparse points (links, junctions) are skipped so a
# link planted in a profile cannot make a SYSTEM scan read someone else's files.
function Resolve-AiPath([string]$Path, [string]$HomeDir) {
  if (-not $Path) { return }
  $rel = $Path -replace '[\\/]', [IO.Path]::DirectorySeparatorChar
  $full = if ([IO.Path]::IsPathRooted($rel)) { $rel } else { Join-Path $HomeDir $rel }
  if ($full -match '[*?]') {
    Get-Item -Path $full -Force -ErrorAction SilentlyContinue |
      Where-Object { -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) } | ForEach-Object { $_.FullName }
  } else {
    $item = Get-Item -LiteralPath $full -Force -ErrorAction SilentlyContinue
    if ($item -and -not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { $item.FullName }
  }
}

function Get-ClaudeGrants([string]$HomeDir) {
  $grants = @{}
  foreach ($file in (Resolve-AiPath '.claude\settings.json' $HomeDir), (Resolve-AiPath '.claude\settings.local.json' $HomeDir)) {
    if ($file -and ($doc = Read-AiJson $file)) { Get-GrantedTools (Get-StringList (Get-AiPath $doc 'permissions.allow')) $grants }
  }
  return $grants
}

function Get-ClaudeProjectServers([string]$HomeDir) {
  $file = Resolve-AiPath '.claude.json' $HomeDir
  if (-not $file) { return }
  $projects = Get-AiProp (Read-AiJson $file) 'projects'
  if ($projects -isnot [Management.Automation.PSCustomObject]) { return }
  foreach ($prop in @($projects.PSObject.Properties | Sort-Object Name | Select-Object -First $AiMaxProjects)) {
    $project = $prop.Value
    if ($project -isnot [Management.Automation.PSCustomObject] -or -not [IO.Path]::IsPathRooted($prop.Name)) { continue }
    $grants = @{}
    Get-GrantedTools (Get-StringList (Get-AiProp $project 'allowedTools')) $grants
    foreach ($name in '.claude\settings.json', '.claude\settings.local.json') {
      $settings = Resolve-AiPath (Join-Path $prop.Name $name) $HomeDir
      if ($settings -and ($doc = Read-AiJson $settings)) { Get-GrantedTools (Get-StringList (Get-AiPath $doc 'permissions.allow')) $grants }
    }
    Get-ServersFrom 'claude_code' 'project' (Get-AiProp $project 'mcpServers') $HomeDir $grants
    $mcp = Resolve-AiPath (Join-Path $prop.Name '.mcp.json') $HomeDir
    if ($mcp -and ($doc = Read-AiJson $mcp)) { Get-ServersFrom 'claude_code' 'project' (Get-AiProp $doc 'mcpServers') $HomeDir $grants }
  }
}

function Get-AiHomes {
  if ($null -ne $env:ALFRED_AI_SCAN_HOMES) {
    return @($env:ALFRED_AI_SCAN_HOMES -split "`n" | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Container) })
  }
  $principal = [Security.Principal.WindowsIdentity]::GetCurrent()
  if (-not $principal.IsSystem -and -not ([Security.Principal.WindowsPrincipal]$principal).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    return @($env:USERPROFILE)
  }
  $homes = @()
  try {
    $homes = @(Get-CimInstance -ClassName Win32_UserProfile -ErrorAction Stop |
        Where-Object { -not $_.Special -and $_.LocalPath } | ForEach-Object { $_.LocalPath })
  } catch { Write-Verbose 'profile list unavailable' }
  if (-not $homes) {
    $homes = @(Get-ChildItem -LiteralPath (Join-Path $env:SystemDrive 'Users') -Directory -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin 'Public', 'Default', 'Default User', 'All Users' } | ForEach-Object { $_.FullName })
  }
  return @($homes | Where-Object { Test-Path -LiteralPath $_ -PathType Container } | Sort-Object -Unique)
}

function Get-AiInventory {
  $clients = [ordered]@{}
  $servers = @{}
  $systemDone = @{}
  $catalog = Get-AiCatalog
  foreach ($homeDir in Get-AiHomes) {
    foreach ($client in $catalog) {
      $found = @()
      $grants = if ($client.id -eq 'claude_code') { Get-ClaudeGrants $homeDir } else { @{} }
      foreach ($config in $client.configs) {
        $path, $format, $keys, $scope = $config
        if (-not $path) { continue }
        if ($scope -eq 'system') {
          if ($systemDone.ContainsKey("$($client.id):$path")) { continue }
          $systemDone["$($client.id):$path"] = $true
        }
        $base = if ($scope -eq 'system') { $null } else { $homeDir }
        foreach ($file in Resolve-AiPath $path $homeDir) {
          if ($format -eq 'toml') { $found += @(Get-ServersFrom $client.id $scope (Read-AiToml $file) $base $grants); continue }
          $doc = Read-AiJson $file
          if (-not $doc) { continue }
          foreach ($key in $keys.Split('|')) { $found += @(Get-ServersFrom $client.id $scope (Get-AiPath $doc $key) $base $grants) }
        }
      }
      if ($client.id -eq 'claude_code') { $found += @(Get-ClaudeProjectServers $homeDir) }
      $present = $found.Count -gt 0 -or @($client.detect | ForEach-Object { Resolve-AiPath $_ $homeDir }).Count -gt 0
      if (-not $present) { continue }
      if (-not $clients.Contains($client.id)) { $clients[$client.id] = [ordered]@{ client = $client.id; name = $client.name } }
      foreach ($server in $found) {
        $key = "{0}`0{1}`0{2}`0{3}" -f $server.client, $server.scope, $server.name, $server.identity
        if ($servers.ContainsKey($key)) { $servers[$key].tools = Get-ToolNames (@($servers[$key].tools) + @($server.tools)) }
        else { $servers[$key] = $server }
      }
    }
  }
  $clientIds = [string[]]@($clients.Keys)
  $serverKeys = [string[]]@($servers.Keys)
  [Array]::Sort($clientIds, [StringComparer]::Ordinal)
  [Array]::Sort($serverKeys, [StringComparer]::Ordinal)
  $clientList = @($clientIds | Select-Object -First 32 | ForEach-Object { $clients[$_] })
  $kept = @($clientList | ForEach-Object { $_.client })
  $serverList = @($serverKeys | ForEach-Object { $servers[$_] } | Where-Object { $kept -contains $_.client })
  if ($serverList.Count -gt $AiMaxServers) {
    Write-Warning "$($serverList.Count) MCP servers found; reporting the first $AiMaxServers"
    $serverList = @($serverList | Select-Object -First $AiMaxServers)
  }
  return [ordered]@{ clients = $clientList; servers = $serverList }
}

# ── HTTP ─────────────────────────────────────────────────────────────────────

function Invoke-AlfredApi($Config, [string]$Method, [string]$Path, $Body) {
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
  $request = [Net.HttpWebRequest]::Create("$($Config.ApiUrl)$Path")
  $request.Method = $Method
  $request.Timeout = 30000
  $request.ReadWriteTimeout = 30000
  $request.AllowAutoRedirect = $false
  $request.Accept = 'application/json'
  $request.UserAgent = "alfred-agent/$AgentVersion (windows)"
  $request.Headers['Authorization'] = "Bearer $($Config.Key)"
  $response = $null
  try {
    if ($null -ne $Body) {
      $bytes = [Text.Encoding]::UTF8.GetBytes(($Body | ConvertTo-Json -Compress -Depth 8))
      $request.ContentType = 'application/json'
      $request.ContentLength = $bytes.Length
      $stream = $request.GetRequestStream()
      try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
    }
    $response = $request.GetResponse()
  } catch {
    $webError = $_.Exception
    while ($webError -and -not ($webError -is [Net.WebException])) { $webError = $webError.InnerException }
    if ($webError -and $webError.Response) { $response = $webError.Response }
    else { return [pscustomobject]@{ Status = 0; Body = [string]$_.Exception.Message } }
  }
  try {
    $reader = New-Object IO.StreamReader($response.GetResponseStream(), [Text.Encoding]::UTF8)
    $text = $reader.ReadToEnd()
    $reader.Dispose()
    if ($text.Length -gt 4096) { $text = $text.Substring(0, 4096) }
    return [pscustomobject]@{ Status = [int]$response.StatusCode; Body = $text }
  } finally { $response.Dispose() }
}

function Get-FailureText($Config, $Result) {
  switch ($Result.Status) {
    0 { return "could not reach $($Config.ApiUrl): $($Result.Body)" }
    401 { return 'the agent key was rejected (revoked or invalid); reinstall with a new key' }
    429 { return 'rate limited by the Alfred API; will retry on the next run' }
    default { return "Alfred API returned HTTP $($Result.Status): $($Result.Body)" }
  }
}

# ── Commands ─────────────────────────────────────────────────────────────────

function Invoke-Enroll {
  Assert-Admin
  $config = Read-AgentConfig
  $result = Invoke-AlfredApi $config 'POST' '/v1/agent/enroll' (New-DeviceReport $config $true)
  if ($result.Status -ne 200 -and $result.Status -ne 201) { Stop-Agent "enroll failed: $(Get-FailureText $config $result)" }
  Write-AgentLog "device enrolled ($($result.Body))"
}

function Invoke-Checkin {
  Assert-Admin
  $config = Read-AgentConfig
  $result = Invoke-AlfredApi $config 'POST' '/v1/agent/checkin' (New-DeviceReport $config $false)
  if ($result.Status -eq 200) { Write-AgentLog 'check-in ok' }
  elseif ($result.Status -eq 404 -and $result.Body -match 'device_not_enrolled') {
    Write-AgentLog 'device not enrolled; enrolling'
    Invoke-Enroll
  } else {
    Stop-Agent "check-in failed: $(Get-FailureText $config $result)"
  }
  Send-AiInventory $config
}

function Send-AiInventory($Config) {
  if ($Config.AiInventory -in 'off', 'false', '0') { Write-AgentLog "AI inventory disabled in $ConfigFile"; return }
  try {
    $body = Get-AiInventory
    $body['hardwareUuid'] = Get-HardwareUuid
    $result = Invoke-AlfredApi $Config 'POST' '/v1/agent/ai-inventory' $body
    if ($result.Status -eq 200) { Write-AgentLog "AI inventory ok ($($result.Body))" }
    elseif ($result.Status -eq 403) { Write-AgentLog 'AI inventory is not enabled for this workspace' }
    else { Write-AgentLog "AI inventory not sent: $(Get-FailureText $Config $result)" }
  } catch {
    Write-AgentLog "AI inventory scan failed: $($_.Exception.Message)"
  }
}

function Invoke-CheckRegistration {
  Assert-Admin
  $config = Read-AgentConfig
  $uuid = Get-HardwareUuid
  if (-not $uuid) { Stop-Agent 'no unique hardware UUID found' }
  $result = Invoke-AlfredApi $config 'GET' "/v1/agent/registration?hardware_uuid=$uuid" $null
  if ($result.Status -ne 200) { Stop-Agent "registration lookup failed: $(Get-FailureText $config $result)" }
  Write-Output $result.Body
  if ($result.Body -notmatch '"registered"\s*:\s*true') { $script:ExitCode = 3 }
}

# Exit codes: 0 scheduled and registered, 2 scheduled but not registered, 1 task missing or error.
function Show-Status {
  Assert-Admin
  $config = Read-AgentConfig
  $encrypted = Get-DiskEncrypted
  $task = $null
  if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  }
  Write-Output "Alfred Device Monitor $AgentVersion (windows)"
  Write-Output "API:          $($config.ApiUrl)"
  Write-Output "Region:       $($config.Region)"
  Write-Output "Owner:        $($config.OwnerEmail)"
  Write-Output "Hardware:     $(if ($uuid = Get-HardwareUuid) { $uuid } else { 'unsupported' })"
  Write-Output "Encrypted:    $(if ($null -eq $encrypted) { 'unknown' } else { $encrypted.ToString().ToLowerInvariant() })"
  Write-Output "Scheduler:    $(if ($task) { "scheduled task ($($task.State))" } else { 'scheduled task (missing)' })"
  Write-Output "AI inventory: $(if ($config.AiInventory -in 'off', 'false', '0') { 'off' } else { 'on' })"
  Write-Output 'Registration:'
  Invoke-CheckRegistration
  if (-not $task) { $script:ExitCode = 1 }
  elseif ($script:ExitCode -eq 3) { $script:ExitCode = 2 }
}

function Invoke-Uninstall {
  Assert-Admin
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath (Join-Path $env:ProgramData 'Alfred Device Monitor') -Recurse -Force -ErrorAction SilentlyContinue
  Write-Output 'Alfred Device Monitor removed from this device.'
}

function Show-Usage {
  Write-Output @"
Alfred Device Monitor $AgentVersion

Usage (as Administrator): alfred-agent.ps1 <command>

  checkin             Report device posture (enrolls automatically if needed)
  enroll              Register this device with Alfred
  status              Show local configuration and registration state
  check-registration  Ask Alfred whether this device is registered (exit 3 if not)
  report              Print the JSON report without sending it
  ai-scan             Print the AI clients and MCP servers found, with secrets masked
  ai-report           Send the AI inventory now
  uninstall           Remove the agent, its scheduled task, and its configuration
  version             Print the agent version
"@
}

$script:ExitCode = 0
try {
  switch ($Command) {
    'checkin' { Invoke-Checkin }
    'enroll' { Invoke-Enroll }
    'status' { Show-Status }
    'check-registration' { Invoke-CheckRegistration }
    'report' { New-DeviceReport (Read-AgentConfig) $false | ConvertTo-Json }
    'ai-scan' { Get-AiInventory | ConvertTo-Json -Depth 8 }
    'ai-report' { Assert-Admin; Send-AiInventory (Read-AgentConfig) }
    'uninstall' { Invoke-Uninstall }
    { $_ -in 'version', '--version' } { Write-Output $AgentVersion }
    { $_ -in 'help', '--help', '-h' } { Show-Usage }
    default { Show-Usage; $script:ExitCode = 64 }
  }
} catch {
  Write-AgentLog "error: $($_.Exception.Message)"
  $script:ExitCode = 1
}
exit $script:ExitCode
