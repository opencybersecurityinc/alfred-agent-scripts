#!/usr/bin/env pwsh
# Golden tests for the Windows AI collector. Runs on any pwsh 7 host.
# Set UPDATE_GOLDEN=1 to rewrite expected.json.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$agent = Join-Path (Split-Path -Parent $root) 'alfred-agent.ps1'
$pwshExe = (Get-Process -Id $PID).Path
$failed = 0

function ConvertTo-Canonical($Node) {
  if ($Node -is [Management.Automation.PSCustomObject]) {
    $sorted = [ordered]@{}
    foreach ($name in ($Node.PSObject.Properties.Name | Sort-Object)) { $sorted[$name] = ConvertTo-Canonical $Node.$name }
    return $sorted
  }
  if ($Node -is [Array]) { return , @($Node | ForEach-Object { ConvertTo-Canonical $_ }) }
  return $Node
}
foreach ($case in Get-ChildItem -Directory (Join-Path $root 'ai-scan-windows')) {
  $tmp = Join-Path ([IO.Path]::GetTempPath()) ("alfred-ai-" + [guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $tmp | Out-Null
  try {
    $homeDir = Join-Path $tmp 'home'
    Copy-Item -Recurse -Force (Join-Path $case.FullName 'home') $homeDir
    $homeJson = ($homeDir | ConvertTo-Json).Trim('"')
    foreach ($file in Get-ChildItem -Recurse -File -Force $homeDir) {
      $text = [IO.File]::ReadAllText($file.FullName)
      if ($text.Contains('@HOME@')) { [IO.File]::WriteAllText($file.FullName, $text.Replace('@HOME@', $homeJson)) }
    }
    $env:ALFRED_CONFIG_DIR = Join-Path $tmp 'cfg'
    $env:ALFRED_AI_SCAN_HOMES = $homeDir
    $env:ALFRED_AI_SCAN_SYSTEM = Join-Path $case.FullName 'system/managed-mcp.json'
    $out = (& $pwshExe -NoProfile -File $agent ai-scan) -join "`n"
    if ($LASTEXITCODE -ne 0) { throw "ai-scan exited $LASTEXITCODE" }
    if ($out -match 'CANARY') { throw 'secret canary leaked into output' }
    if ($out.Contains($homeDir) -or $out.Contains($homeJson)) { throw 'home path leaked into output' }
    $expectedFile = Join-Path $case.FullName 'expected.json'
    if (-not (Test-Path $expectedFile)) { $expectedFile = Join-Path $root "ai-scan/$($case.Name)/expected.json" }
    $actual = ConvertTo-Canonical ($out | ConvertFrom-Json) | ConvertTo-Json -Depth 8 -Compress
    if ($env:UPDATE_GOLDEN -eq '1') {
      [IO.File]::WriteAllText((Join-Path $case.FullName 'expected.json'), $out + "`n")
      Write-Output "updated $($case.Name)"
      continue
    }
    $expected = ConvertTo-Canonical (Get-Content -Raw $expectedFile | ConvertFrom-Json) | ConvertTo-Json -Depth 8 -Compress
    if ($actual -ne $expected) { throw "output differs from $expectedFile`n$out" }
    Write-Output "ok $($case.Name)"
  } catch {
    $failed++
    Write-Output "FAIL $($case.Name): $_"
  } finally {
    Remove-Item Env:ALFRED_CONFIG_DIR, Env:ALFRED_AI_SCAN_HOMES, Env:ALFRED_AI_SCAN_SYSTEM -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
  }
}
exit $failed
