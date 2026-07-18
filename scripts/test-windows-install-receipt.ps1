$ErrorActionPreference = 'Stop'
$required = $env:ZENO_REQUIRE_WINDOWS_SERVICE_TEST -eq '1'
if ($env:OS -ne 'Windows_NT') {
  if ($required) { throw 'native Windows service receipt test was required on a non-Windows host' }
  Write-Host 'SKIP: Windows only'
  exit 0
}
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
  if ($required) { throw 'native Windows service receipt test requires Administrator' }
  Write-Host 'SKIP: requires Administrator'
  exit 0
}

function New-HarnessAccessRule($Identity, [Security.AccessControl.FileSystemRights]$Rights) {
  $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
  return New-Object -TypeName Security.AccessControl.FileSystemAccessRule -ArgumentList @(
    $Identity, $Rights, $inherit, [Security.AccessControl.PropagationFlags]::None,
    [Security.AccessControl.AccessControlType]::Allow
  )
}

function Set-LegacyDataDirectoryAcl($Path, $Identity) {
  $acl = New-Object Security.AccessControl.DirectorySecurity
  $acl.SetAccessRuleProtection($true, $false)
  $acl.SetOwner((New-Object Security.Principal.NTAccount('BUILTIN\Administrators')))
  $acl.AddAccessRule((New-HarnessAccessRule 'NT AUTHORITY\SYSTEM' ([Security.AccessControl.FileSystemRights]::FullControl)))
  $acl.AddAccessRule((New-HarnessAccessRule 'BUILTIN\Administrators' ([Security.AccessControl.FileSystemRights]::FullControl)))
  $acl.AddAccessRule((New-HarnessAccessRule $Identity ([Security.AccessControl.FileSystemRights]::Modify)))
  Set-Acl -LiteralPath $Path -AclObject $acl
}

function Get-Sid($Identity) {
  return (New-Object Security.Principal.NTAccount($Identity)).Translate([Security.Principal.SecurityIdentifier]).Value
}

function Get-SingleExplicitAllowRule($Acl, $Sid) {
  $rules = @($Acl.GetAccessRules($true, $false, [Security.Principal.SecurityIdentifier]) | Where-Object {
    $_.IdentityReference.Value -eq $Sid -and
    $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow
  })
  if ($rules.Count -ne 1) { throw "expected one explicit allow rule for SID $Sid, got $($rules.Count)" }
  return $rules[0]
}

function Assert-ClosedFinalDataDirectoryAcl($Path, $AdministratorSid, $ServiceSid) {
  $acl = Get-Acl -LiteralPath $Path
  if (-not $acl.AreAccessRulesProtected) { throw 'final data-directory DACL is not protected' }
  if ((Get-Sid $acl.Owner) -ne $AdministratorSid) { throw 'final data-directory owner is not Administrators' }
  $allowed = @{}
  foreach ($sid in @((Get-Sid 'NT AUTHORITY\SYSTEM'), $AdministratorSid, $ServiceSid)) { $allowed[$sid] = $true }
  $seen = @{}
  foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
    $sid = $rule.IdentityReference.Value
    if ($rule.IsInherited) { throw "final data-directory ACL contains inherited rule for $sid" }
    if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) { throw "final data-directory ACL contains deny rule for $sid" }
    if (-not $allowed.ContainsKey($sid)) { throw "final data-directory ACL contains unexpected SID $sid" }
    $seen[$sid] = $true
  }
  foreach ($sid in $allowed.Keys) {
    if (-not $seen.ContainsKey($sid)) { throw "final data-directory ACL is missing SID $sid" }
  }
  $serviceRule = Get-SingleExplicitAllowRule $acl $ServiceSid
  $changePermissions = [int64][Security.AccessControl.FileSystemRights]::ChangePermissions
  if (([int64]$serviceRule.FileSystemRights -band $changePermissions) -ne $changePermissions) {
    throw 'final data-directory ACL does not let the service protect its DACL'
  }
}

$repo = Split-Path -Parent $PSScriptRoot
Push-Location $repo
$name = 'zeno-agent-receipt'
if (Get-Service -Name $name -ErrorAction SilentlyContinue) { throw "refusing to replace existing service $name" }
$tmp = Join-Path $env:ProgramData ("ZenoReceiptHarness-" + [Guid]::NewGuid().ToString('N'))
$dataDir = Join-Path $tmp 'administrator-owned-agent-data'
$bin = Join-Path $tmp 'zeno-agent.exe'
$tokenFile = Join-Path $tmp 'token'
$receipt = Join-Path $tmp 'receipt'
$heartbeatMarker = Join-Path $tmp 'heartbeat-accepted'
$stateMarker = Join-Path $tmp 'state-accepted'
$nonce = [Guid]::NewGuid().ToString('N') + [Guid]::NewGuid().ToString('N')
$fixtureToken = 'fixture-only-token'
$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
$listener.Start()
$port = ([Net.IPEndPoint]$listener.LocalEndpoint).Port
$listener.Stop()
$job = $null
$created = $false
try {
  New-Item -ItemType Directory -Force -Path $tmp, $dataDir | Out-Null
  & go build -o $bin ./cmd/zeno-agent
  if ($LASTEXITCODE -ne 0) { throw 'go build failed' }
  [IO.File]::WriteAllText($tokenFile, $fixtureToken + "`n")

  $job = Start-Job -ArgumentList $port,$fixtureToken,$heartbeatMarker,$stateMarker -ScriptBlock {
    param($p,$tok,$heartbeatPath,$statePath)
    $h = [Net.HttpListener]::new()
    $h.Prefixes.Add("http://127.0.0.1:$p/")
    $h.Start()
    while ($true) {
      $c = $h.GetContext()
      $authorized = $c.Request.Headers['X-Node-ID'] -eq 'receipt-harness' -and $c.Request.Headers['Authorization'] -eq "Bearer $tok"
      if (-not $authorized) {
        $c.Response.StatusCode = 401
      } elseif ($c.Request.Url.AbsolutePath -eq '/api/agent/v1/heartbeat') {
        [IO.File]::WriteAllText($heartbeatPath, 'accepted')
        $c.Response.StatusCode = 204
      } elseif ($c.Request.Url.AbsolutePath -eq '/api/agent/v1/state') {
        [IO.File]::WriteAllText($statePath, 'accepted')
        $c.Response.StatusCode = 204
      } elseif ($c.Request.Url.AbsolutePath -eq '/api/agent/v1/probe-targets') {
        $body = [Text.Encoding]::UTF8.GetBytes('{"config_version":0,"targets":[]}')
        $c.Response.StatusCode = 200
        $c.Response.ContentType = 'application/json'
        $c.Response.ContentLength64 = $body.Length
        $c.Response.OutputStream.Write($body, 0, $body.Length)
      } else {
        $c.Response.StatusCode = 204
      }
      $c.Response.Close()
    }
  }
  Start-Sleep -Milliseconds 500

  $serviceArguments = "-controller-url http://127.0.0.1:$port -node-id receipt-harness -token-file `"$tokenFile`" -state-interval 1s -heartbeat-interval 1s -data-dir `"$dataDir`" -install-receipt-file `"$receipt`" -install-receipt-nonce $nonce"
  New-Service -Name $name -BinaryPathName "`"$bin`" $serviceArguments" -StartupType Manual | Out-Null
  $created = $true
  & sc.exe sidtype $name unrestricted | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'sidtype failed' }
  & sc.exe config $name obj= "NT SERVICE\$name" | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'virtual account config failed' }

  # The harness directory carries only ordinary runtime access. The data
  # directory below is independently protected to model an old installation.
  & icacls.exe $tmp /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' "NT SERVICE\${name}:(OI)(CI)M" | Out-Null
  if ($LASTEXITCODE -ne 0) { throw 'harness directory ACL setup failed' }

  $serviceAccount = "NT SERVICE\$name"
  $serviceSid = Get-Sid $serviceAccount
  $administratorSid = Get-Sid 'BUILTIN\Administrators'
  Set-LegacyDataDirectoryAcl -Path $dataDir -Identity $serviceAccount
  $legacyAcl = Get-Acl -LiteralPath $dataDir
  if (-not $legacyAcl.AreAccessRulesProtected) { throw 'legacy data-directory DACL is not protected' }
  if ((Get-Sid $legacyAcl.Owner) -ne $administratorSid) { throw 'legacy data-directory is not owned by Administrators' }
  if ((Get-Sid $legacyAcl.Owner) -eq $serviceSid) { throw 'legacy data-directory unexpectedly belongs to the service' }
  $legacyRule = Get-SingleExplicitAllowRule $legacyAcl $serviceSid
  $changePermissions = [int64][Security.AccessControl.FileSystemRights]::ChangePermissions
  if (([int64]$legacyRule.FileSystemRights -band $changePermissions) -ne 0) { throw 'legacy Modify ACL unexpectedly includes ChangePermissions/WRITE_DAC' }

  # Execute the production installer function so this native regression and
  # the shipped ACL implementation cannot silently diverge.
  $installerSource = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $repo 'install.ps1')
  $tokens = $null
  $parseErrors = $null
  $ast = [Management.Automation.Language.Parser]::ParseInput($installerSource, [ref]$tokens, [ref]$parseErrors)
  if ($parseErrors.Count -ne 0) { throw "install.ps1 parse failed: $($parseErrors[0].Message)" }
  $functionAst = $ast.Find({
    param($node)
    $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Set-ServiceDataDirectoryAcl'
  }, $true)
  if (-not $functionAst) { throw 'Set-ServiceDataDirectoryAcl not found in install.ps1' }
  Invoke-Expression $functionAst.Extent.Text
  Set-ServiceDataDirectoryAcl -Path $dataDir -IdentityName $serviceAccount

  $installerAcl = Get-Acl -LiteralPath $dataDir
  if (-not $installerAcl.AreAccessRulesProtected) { throw 'installer data-directory DACL is not protected' }
  if ((Get-Sid $installerAcl.Owner) -ne $administratorSid) { throw 'installer changed data-directory owner' }
  $installerRule = Get-SingleExplicitAllowRule $installerAcl $serviceSid
  $modify = [int64][Security.AccessControl.FileSystemRights]::Modify
  $takeOwnership = [int64][Security.AccessControl.FileSystemRights]::TakeOwnership
  if (([int64]$installerRule.FileSystemRights -band $modify) -ne $modify -or
      ([int64]$installerRule.FileSystemRights -band $changePermissions) -ne $changePermissions) {
    throw 'installer did not grant Modify plus ChangePermissions/WRITE_DAC'
  }
  if (([int64]$installerRule.FileSystemRights -band $takeOwnership) -ne 0) { throw 'installer unnecessarily granted TakeOwnership' }

  Start-Service $name
  for ($i = 0; $i -lt 45 -and -not (Test-Path -LiteralPath $receipt -PathType Leaf); $i++) { Start-Sleep 1 }
  if (-not (Test-Path -LiteralPath $receipt -PathType Leaf)) { throw 'service receipt was not created' }
  if (-not (Test-Path -LiteralPath $heartbeatMarker -PathType Leaf) -or -not (Test-Path -LiteralPath $stateMarker -PathType Leaf)) {
    throw 'mock Controller did not accept both heartbeat and state'
  }
  if ([IO.File]::ReadAllText($receipt).Trim() -ne "zeno-agent-install-receipt-v1 $nonce") { throw 'invalid receipt' }
  $owner = Get-Sid (Get-Acl -LiteralPath $receipt).Owner
  if ($owner -ne $serviceSid) { throw 'receipt owner is not the virtual service account' }
  $svc = Get-CimInstance Win32_Service -Filter "Name='$name'"
  if ($svc.State -ne 'Running' -or $svc.ProcessId -eq 0) { throw 'SCM process is not running' }
  $process = Get-CimInstance Win32_Process -Filter "ProcessId=$($svc.ProcessId)"
  $processOwner = Invoke-CimMethod -InputObject $process -MethodName GetOwner
  if ($processOwner.ReturnValue -ne 0) { throw 'cannot read SCM process identity' }
  $processAccount = if ($processOwner.Domain) { "$($processOwner.Domain)\$($processOwner.User)" } else { [string]$processOwner.User }
  if ((Get-Sid $processAccount) -ne $serviceSid) { throw 'SCM process is not the virtual service account' }
  Assert-ClosedFinalDataDirectoryAcl -Path $dataDir -AdministratorSid $administratorSid -ServiceSid $serviceSid
  foreach ($path in @((Join-Path $dataDir 'probe-spool'), (Join-Path $dataDir 'probe-spool\pending'), (Join-Path $dataDir 'probe-spool\quarantine'))) {
    if (-not (Test-Path -LiteralPath $path -PathType Container)) { throw "probe spool directory missing: $path" }
    if (-not (Get-Acl -LiteralPath $path).AreAccessRulesProtected) { throw "probe spool directory DACL is not protected: $path" }
  }
  Write-Host 'PASS: real Windows SCM virtual-account administrator-owned data-directory upgrade receipt verified'
} finally {
  if ($created) {
    Stop-Service $name -ErrorAction SilentlyContinue
    & sc.exe delete $name | Out-Null
  }
  if ($job) {
    Stop-Job $job -ErrorAction SilentlyContinue
    Remove-Job $job -Force -ErrorAction SilentlyContinue
  }
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
  Pop-Location
}
