<#
.SYNOPSIS
  Alfred Device Monitor agent for Windows.
.DESCRIPTION
  Reports this computer's posture to Alfred. Installed by install-windows.ps1 and run hourly
  by the "Alfred Device Monitor" scheduled task as SYSTEM.

  Commands: checkin, enroll, status, check-registration, report, uninstall, version, help
#>
[CmdletBinding()]
param([Parameter(Position = 0)][string]$Command = 'help')

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$AgentVersion = '1.0.0'
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
  }
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
  return $report
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
      $bytes = [Text.Encoding]::UTF8.GetBytes(($Body | ConvertTo-Json -Compress))
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
  if ($result.Status -eq 200) { Write-AgentLog 'check-in ok'; return }
  if ($result.Status -eq 404 -and $result.Body -match 'device_not_enrolled') {
    Write-AgentLog 'device not enrolled; enrolling'
    Invoke-Enroll
    return
  }
  Stop-Agent "check-in failed: $(Get-FailureText $config $result)"
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
  Write-Output 'Registration:'
  Invoke-CheckRegistration
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
    'uninstall' { Invoke-Uninstall }
    { $_ -in 'version', '--version' } { Write-Output $AgentVersion }
    { $_ -in 'help', '--help', '-h' } { Show-Usage }
    default { Show-Usage; $script:ExitCode = 2 }
  }
} catch {
  Write-AgentLog "error: $($_.Exception.Message)"
  $script:ExitCode = 1
}
exit $script:ExitCode
