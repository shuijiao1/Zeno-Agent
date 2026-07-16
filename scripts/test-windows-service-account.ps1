$ErrorActionPreference = 'Stop'

$installerPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'install.ps1'
# Windows PowerShell 5.1 otherwise reads UTF-8-without-BOM as the active ANSI
# code page, corrupting the installer's Chinese diagnostics before AST parsing.
$source = Get-Content -Raw -Encoding UTF8 -LiteralPath $installerPath
$tokens = $null
$parseErrors = $null
$ast = [Management.Automation.Language.Parser]::ParseInput($source, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) {
  throw "install.ps1 parse failed: $($parseErrors[0].Message)"
}
$functionAst = $ast.Find({
  param($node)
  $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $node.Name -eq 'Set-ServiceLogonAccount'
}, $true)
if (-not $functionAst) { throw 'Set-ServiceLogonAccount not found in install.ps1' }
Invoke-Expression $functionAst.Extent.Text

$suffix = [Guid]::NewGuid().ToString('N').Substring(0, 12)
$serviceName = "zeno-agent-ci-$suffix"
$virtualAccount = "NT SERVICE\$serviceName"
$created = $false
try {
  New-Service -Name $serviceName -BinaryPathName "$env:SystemRoot\System32\cmd.exe /c exit 0" -StartupType Manual | Out-Null
  $created = $true

  $before = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction Stop
  if (-not ([string]$before.StartName).Equals('LocalSystem', [StringComparison]::OrdinalIgnoreCase)) {
    throw "unexpected initial service account: $($before.StartName)"
  }

  if (-not (Set-ServiceLogonAccount -Name $serviceName -AccountName $virtualAccount)) {
    throw 'LocalSystem to virtual-account migration returned failure'
  }
  $migrated = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction Stop
  if (-not ([string]$migrated.StartName).Equals($virtualAccount, [StringComparison]::OrdinalIgnoreCase)) {
    throw "virtual service account did not persist: $($migrated.StartName)"
  }

  if (-not (Set-ServiceLogonAccount -Name $serviceName -AccountName 'LocalSystem')) {
    throw 'virtual-account rollback to LocalSystem returned failure'
  }
  $restored = Get-CimInstance Win32_Service -Filter "Name='$serviceName'" -ErrorAction Stop
  if (-not ([string]$restored.StartName).Equals('LocalSystem', [StringComparison]::OrdinalIgnoreCase)) {
    throw "LocalSystem rollback did not persist: $($restored.StartName)"
  }
} finally {
  if ($created) {
    & sc.exe delete $serviceName | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Warning "failed to delete test service: $serviceName" }
  }
}
