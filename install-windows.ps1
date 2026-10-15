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

  Optional:
    $env:ALFRED_NOSTART = 'true'                  install without enrolling or running the first check-in
    $env:ALFRED_SKIP_REGISTRATION_CHECK = 'true'  do not wait for Alfred to confirm the registration
    $env:ALFRED_AGENT_DIR = 'C:\path'             install from a local copy (the pins still apply)
    $env:ALFRED_REGISTRATION_ATTEMPTS / ALFRED_REGISTRATION_DELAY  retries (1-99) and delay in seconds (0-999)
#>

& {
  Set-StrictMode -Version 2.0
  $ErrorActionPreference = 'Stop'

  $AgentUrl = 'https://raw.githubusercontent.com/opencybersecurityinc/alfred-agent-scripts/main/alfred-agent.ps1'
  $AgentSha256 = 'c61f42c88727d3528495ea5843ade05fd84b449172358cabfd2cb70b9d52169f'
  # Optional Authenticode pin. Once SigningThumbprint is set, the agent must carry
  # a valid signature whose certificate matches both the subject and the thumbprint.
  $SigningSubject = ''
  $SigningThumbprint = ''
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
  $switches = @{}
  foreach ($name in 'ALFRED_NOSTART', 'ALFRED_SKIP_REGISTRATION_CHECK') {
    $value = [string][Environment]::GetEnvironmentVariable($name)
    if ($value -notin @('', 'true', 'false')) { Fail "$name must be true or false" }
    $switches[$name] = $value -eq 'true'
  }
  $attempts = if ($env:ALFRED_REGISTRATION_ATTEMPTS) { [string]$env:ALFRED_REGISTRATION_ATTEMPTS } else { '6' }
  $delay = if ($env:ALFRED_REGISTRATION_DELAY) { [string]$env:ALFRED_REGISTRATION_DELAY } else { '10' }
  if ($attempts -notmatch '^[1-9][0-9]?$' -or $delay -notmatch '^[0-9]{1,3}$') {
    Fail 'ALFRED_REGISTRATION_ATTEMPTS must be 1-99 and ALFRED_REGISTRATION_DELAY 0-999 seconds'
  }
  if (-not (Get-Command Get-FileHash -ErrorAction SilentlyContinue)) { Fail 'Get-FileHash is required to verify the agent' }

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
    if ($env:ALFRED_AGENT_DIR) {
      Copy-Item -LiteralPath (Join-Path $env:ALFRED_AGENT_DIR 'alfred-agent.ps1') -Destination $download -Force
    } else {
      Invoke-WebRequest -Uri $AgentUrl -OutFile $download -UseBasicParsing -MaximumRedirection 0
    }
    $actual = [string](Get-FileHash -LiteralPath $download -Algorithm SHA256).Hash
    if ($actual -notmatch '^[0-9A-Fa-f]{64}$') { Fail 'could not compute the agent checksum' }
    if ($actual.ToLowerInvariant() -ne $AgentSha256) { Fail "agent checksum mismatch (expected $AgentSha256, got $actual)" }
    if ($SigningThumbprint) {
      $signature = Get-AuthenticodeSignature -LiteralPath $download
      $cert = $signature.SignerCertificate
      if ($signature.Status -ne 'Valid' -or -not $cert) { Fail "agent signature is not valid ($($signature.Status))" }
      if ($cert.Thumbprint -ne $SigningThumbprint.Replace(':', '').ToUpperInvariant()) { Fail 'signing certificate thumbprint does not match' }
      if ($cert.Subject -notmatch "(^|,\s*)CN=$([regex]::Escape($SigningSubject))(,|$)") { Fail "signing certificate identity does not match '$SigningSubject'" }
      Write-Output "Signature by '$SigningSubject' verified."
    } else {
      Write-Output 'No signing certificate is pinned in this installer; relying on the SHA-256 pin.'
    }
    Move-Item -LiteralPath $download -Destination $AgentPath -Force
  } finally {
    Remove-Item -LiteralPath $download -Force -ErrorAction SilentlyContinue
  }

  $utf8 = New-Object Text.UTF8Encoding($false)
  # The activation nonce (install time in epoch ms) lets Alfred refuse replayed bootstrap configs.
  $nonce = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
  [IO.File]::WriteAllText((Join-Path $InstallDir 'agent.conf'),
    "API_URL=$apiUrl`r`nOWNER_EMAIL=$owner`r`nREGION=$region`r`nACTIVATION_NONCE=$nonce`r`n", $utf8)
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

  if ($switches['ALFRED_NOSTART']) {
    Disable-ScheduledTask -TaskName $TaskName | Out-Null
    Write-Output "Alfred Device Monitor installed (not started). Run: powershell -File `"$AgentPath`" enroll"
    Write-Output "Then start the schedule with: Enable-ScheduledTask -TaskName '$TaskName'"
    return
  }

  & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $AgentPath enroll
  if ($LASTEXITCODE -ne 0) { Fail "enrollment failed; see $(Join-Path $InstallDir 'alfred-agent.log')" }
  if ($switches['ALFRED_SKIP_REGISTRATION_CHECK']) {
    Write-Output 'Skipping the registration check (ALFRED_SKIP_REGISTRATION_CHECK=true).'
  } else {
    $registered = $false
    for ($i = 1; $i -le [int]$attempts; $i++) {
      & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $AgentPath check-registration | Out-Null
      if ($LASTEXITCODE -eq 0) { $registered = $true; break }
      if ($i -lt [int]$attempts) { Start-Sleep -Seconds ([int]$delay) }
    }
    if (-not $registered) { Fail "Alfred has not confirmed the registration after $attempts attempts; run the agent with 'status'" }
    Write-Output 'Alfred confirmed this device is registered.'
  }
  Write-Output 'Alfred Device Monitor installed and enrolled. It checks in every hour.'
  Write-Output "Status: powershell -File `"$AgentPath`" status   (exit 0 running, 2 not registered)"
}
