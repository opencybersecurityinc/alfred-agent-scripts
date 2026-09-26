<#
.SYNOPSIS
  Installs the Alfred Device Monitor agent on Windows.
.DESCRIPTION
  Run from an elevated PowerShell (Windows PowerShell 5.1 or PowerShell 7):

    $env:ALFRED_KEY = 'alfa_...'
    $env:ALFRED_OWNER_EMAIL = 'person@example.com'
    $env:ALFRED_REGION = 'us'
    $env:ALFRED_API_URL = 'https://alfred.example.com'
    irm https://raw.githubusercontent.com/opencybersecurityinc/alfred-agent-scripts/main/install-windows.ps1 | iex

  Optional: $env:ALFRED_NOSTART = 'true' installs without enrolling or running the first check-in.
#>

& {
  Set-StrictMode -Version 2.0
  $ErrorActionPreference = 'Stop'

  $AgentUrl = 'https://raw.githubusercontent.com/opencybersecurityinc/alfred-agent-scripts/main/alfred-agent.ps1'
  $AgentSha256 = '05feeb908bb40f7e82643b9ae57cc0d1386f72d2c833d211b8403884bf278405'
  $TaskName = 'Alfred Device Monitor'
  $InstallDir = Join-Path $env:ProgramData 'Alfred Device Monitor'
  $AgentPath = Join-Path $InstallDir 'alfred-agent.ps1'

  function Fail([string]$Message) { throw "Alfred Device Monitor install failed: $Message" }

  $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Fail 'run this installer from an elevated (Administrator) PowerShell'
  }

  $key = [string]$env:ALFRED_KEY
  $owner = [string]$env:ALFRED_OWNER_EMAIL
  $region = [string]$env:ALFRED_REGION
  $apiUrl = ([string]$env:ALFRED_API_URL).TrimEnd('/')

  if ($key -notmatch '^alfa_[A-Za-z0-9_-]{32,64}$') { Fail 'ALFRED_KEY is missing or invalid (expected alfa_...)' }
  if ($owner -notmatch '^[^\s@"\\]{1,64}@[^\s@"\\]{1,255}$') { Fail 'ALFRED_OWNER_EMAIL is missing or invalid' }
  if ($region -notin @('us', 'eu', 'aus')) { Fail 'set ALFRED_REGION to us, eu or aus' }
  if ($apiUrl -notmatch '^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$') {
    Fail 'ALFRED_API_URL must be an https:// URL'
  }
  if ($AgentSha256 -notmatch '^[0-9a-f]{64}$') { Fail 'installer is not pinned to an agent checksum' }

  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

  # Private directory: inheritance off, only SYSTEM and Administrators have access.
  if (-not (Test-Path -LiteralPath $InstallDir)) { New-Item -ItemType Directory -Path $InstallDir | Out-Null }
  $acl = New-Object Security.AccessControl.DirectorySecurity
  $acl.SetAccessRuleProtection($true, $false)
  $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
  foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
    $identity = New-Object Security.Principal.SecurityIdentifier($sid)
    $rule = New-Object Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', $inherit, 'None', 'Allow')
    $acl.AddAccessRule($rule)
  }
  $acl.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
  Set-Acl -LiteralPath $InstallDir -AclObject $acl

  $download = Join-Path $InstallDir 'alfred-agent.ps1.download'
  try {
    Invoke-WebRequest -Uri $AgentUrl -OutFile $download -UseBasicParsing -MaximumRedirection 0
    $actual = (Get-FileHash -LiteralPath $download -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $AgentSha256) { Fail "agent checksum mismatch (expected $AgentSha256, got $actual)" }
    Move-Item -LiteralPath $download -Destination $AgentPath -Force
  } finally {
    Remove-Item -LiteralPath $download -Force -ErrorAction SilentlyContinue
  }

  $utf8 = New-Object Text.UTF8Encoding($false)
  [IO.File]::WriteAllText((Join-Path $InstallDir 'agent.conf'), "API_URL=$apiUrl`r`nOWNER_EMAIL=$owner`r`nREGION=$region`r`n", $utf8)
  [IO.File]::WriteAllText((Join-Path $InstallDir 'agent.key'), $key, $utf8)

  $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$AgentPath`" checkin"
  $hourly = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) -RepetitionInterval (New-TimeSpan -Hours 1)
  $startup = New-ScheduledTaskTrigger -AtStartup
  $taskPrincipal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
  $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
  Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger @($hourly, $startup) `
    -Principal $taskPrincipal -Settings $settings -Description 'Reports device posture to Alfred.' -Force | Out-Null

  if ([string]$env:ALFRED_NOSTART -eq 'true') {
    Write-Output "Alfred Device Monitor installed (not started). Run: powershell -File `"$AgentPath`" enroll"
    return
  }

  & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $AgentPath enroll
  if ($LASTEXITCODE -ne 0) { Fail "enrollment failed; see $(Join-Path $InstallDir 'alfred-agent.log')" }
  Write-Output 'Alfred Device Monitor installed and enrolled. It checks in every hour.'
}
