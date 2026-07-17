$ErrorActionPreference = 'Stop'

try {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.ServicePointManager]::SecurityProtocol
} catch {}

$Repo = if ($env:ZENO_AGENT_REPO) { $env:ZENO_AGENT_REPO } else { 'shuijiao1/Zeno-Agent' }
$Version = if ($env:ZENO_AGENT_VERSION) { $env:ZENO_AGENT_VERSION } else { 'latest' }
$InstallDir = if ($env:ZENO_AGENT_INSTALL_DIR) { $env:ZENO_AGENT_INSTALL_DIR } else { Join-Path $env:ProgramFiles 'Zeno Agent' }
$Bin = if ($env:ZENO_AGENT_BIN) { $env:ZENO_AGENT_BIN } else { Join-Path $InstallDir 'zeno-agent.exe' }
$TokenFile = if ($env:ZENO_AGENT_TOKEN_FILE) { $env:ZENO_AGENT_TOKEN_FILE } else { Join-Path $env:ProgramData 'Zeno\agent-token' }
$ControllerURL = $env:ZENO_CONTROLLER_URL
$NodeID = $env:ZENO_NODE_ID
$Token = $env:ZENO_AGENT_TOKEN
$EnrollmentToken = $env:ZENO_ENROLLMENT_TOKEN
$VerifyAttestation = if ($env:ZENO_VERIFY_ATTESTATION) { $env:ZENO_VERIFY_ATTESTATION.ToLowerInvariant() } else { 'true' }
# Keep credentials out of every subsequently spawned process environment.
$env:ZENO_AGENT_TOKEN = $null
$env:ZENO_ENROLLMENT_TOKEN = $null
$StateInterval = if ($env:ZENO_AGENT_STATE_INTERVAL) { $env:ZENO_AGENT_STATE_INTERVAL } elseif ($env:ZENO_AGENT_INTERVAL) { $env:ZENO_AGENT_INTERVAL } else { '3s' }
$HeartbeatInterval = if ($env:ZENO_AGENT_HEARTBEAT_INTERVAL) { $env:ZENO_AGENT_HEARTBEAT_INTERVAL } else { '15s' }
$HostInterval = if ($env:ZENO_AGENT_HOST_INTERVAL) { $env:ZENO_AGENT_HOST_INTERVAL } else { '30m' }
$IdentityRefreshInterval = if ($env:ZENO_AGENT_IDENTITY_REFRESH_INTERVAL) { $env:ZENO_AGENT_IDENTITY_REFRESH_INTERVAL } else { '12h' }
$NetworkInterfaces = $env:ZENO_AGENT_NETWORK_INTERFACES
$DiskMounts = $env:ZENO_AGENT_DISK_MOUNTS
# The Windows binary registers this exact SCM service name in svc.Run.
$ServiceName = 'zeno-agent'
$AllowInsecureHTTPRequested = $env:ZENO_ALLOW_INSECURE_HTTP -eq '1'
$AllowInsecureHTTP = $false
$InstallReceiptTimeout = if ($env:ZENO_AGENT_INSTALL_RECEIPT_TIMEOUT) { [int]$env:ZENO_AGENT_INSTALL_RECEIPT_TIMEOUT } else { 45 }
$InstallReceiptPrefix = 'zeno-agent-install-receipt-v1'

function Fail($Message) {
  throw "错误: $Message"
}

function Invoke-DownloadFile($Uri, $OutFile) {
  $lastError = $null
  for ($attempt = 1; $attempt -le 3; $attempt++) {
    try {
      Invoke-WebRequest -UseBasicParsing -Uri $Uri -OutFile $OutFile
      return
    } catch {
      $lastError = $_
      if ($attempt -lt 3) { Start-Sleep -Seconds ([Math]::Min(5, $attempt * 2)) }
    }
  }
  throw $lastError
}

function Invoke-DownloadJson($Uri) {
  $lastError = $null
  for ($attempt = 1; $attempt -le 3; $attempt++) {
    try {
      return Invoke-RestMethod -UseBasicParsing -Uri $Uri
    } catch {
      $lastError = $_
      if ($attempt -lt 3) { Start-Sleep -Seconds ([Math]::Min(5, $attempt * 2)) }
    }
  }
  throw $lastError
}

function New-AgentRuntimeToken() {
  $bytes = New-Object byte[] 32
  $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
  try {
    $generator.GetBytes($bytes)
  } finally {
    $generator.Dispose()
  }
  return ([BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
}

function Invoke-AgentEnrollment($RuntimeToken) {
  $endpoint = $ControllerURL.TrimEnd('/') + '/api/agent/v1/enroll'
  $body = @{
    node_id = $NodeID
    enrollment_token = $EnrollmentToken
    runtime_token = $RuntimeToken
  } | ConvertTo-Json -Compress
  try {
    # No automatic retry: enrollment has first-successful-exchange semantics.
    # Redirects are rejected so the one-time credential cannot be forwarded to
    # a different origin by a misconfigured controller.
    Invoke-RestMethod -UseBasicParsing -Method Post -Uri $endpoint -ContentType 'application/json' -Body $body -TimeoutSec 30 -MaximumRedirection 0 | Out-Null
  } catch {
    Fail '一次性 enrollment token 兑换失败；请重新生成安装命令'
  }
}

function Get-ExpectedSha256($SumsFile, $AssetName) {
  foreach ($line in Get-Content -Path $SumsFile) {
    $trimmed = $line.Trim()
    if (-not $trimmed) { continue }
    $parts = $trimmed -split '\s+', 2
    if ($parts.Count -eq 2 -and $parts[1].TrimStart('*') -eq $AssetName) {
      return $parts[0].ToLowerInvariant()
    }
  }
  Fail "SHA256SUMS 中未找到 $AssetName 的校验值"
}

function Assert-ArchiveChecksum($Archive, $SumsFile, $AssetName) {
  $expected = Get-ExpectedSha256 -SumsFile $SumsFile -AssetName $AssetName
  $actual = (Get-FileHash -Algorithm SHA256 -Path $Archive).Hash.ToLowerInvariant()
  if ($actual -ne $expected) {
    Fail "下载完整性校验失败: $AssetName"
  }
}

function Assert-ReleaseProvenance($Archive, $Bundle, $TempDir) {
  if ($VerifyAttestation -eq 'false') {
    Write-Warning '已显式关闭 Agent provenance 验证。'
    return
  }
  if ($VerifyAttestation -ne 'true') { Fail 'ZENO_VERIFY_ATTESTATION 必须是 true 或 false' }
  $ghVersion = '2.65.0'
  if ($GoArch -eq 'amd64') {
    $verifierSha = '7f0d84ff2dcc2c9e83664c23e619cfe020964584520fcf2f503dda3d298fb6ea'
  } elseif ($GoArch -eq 'arm64') {
    $verifierSha = '5050e0e1844cc7192b90411d897677303f7f728b94d6dce0819002a4ef53757b'
  } else {
    Fail "当前平台不支持 provenance 验证: windows/$GoArch"
  }
  $verifierArchiveName = "gh_${ghVersion}_windows_${GoArch}.zip"
  $verifierArchive = Join-Path $TempDir $verifierArchiveName
  $verifierUrl = "https://github.com/cli/cli/releases/download/v$ghVersion/$verifierArchiveName"
  Invoke-DownloadFile -Uri $verifierUrl -OutFile $verifierArchive
  $actualVerifierSha = (Get-FileHash -Algorithm SHA256 -Path $verifierArchive).Hash.ToLowerInvariant()
  if ($actualVerifierSha -ne $verifierSha) { Fail 'provenance verifier 校验失败' }
  $verifierDir = Join-Path $TempDir 'provenance-verifier'
  Expand-Archive -Force -Path $verifierArchive -DestinationPath $verifierDir
  $verifier = Get-ChildItem -Path $verifierDir -Recurse -Filter 'gh.exe' | Where-Object { $_.FullName -match '[\\/]bin[\\/]gh\.exe$' } | Select-Object -First 1
  if (-not $verifier) { Fail 'provenance verifier 缺少可执行文件' }
  $certificateIdentity = "https://github.com/$Repo/.github/workflows/release.yml@refs/tags/$Version"
  $verifyArgs = @('attestation', 'verify', $Archive, '--repo', $Repo, '--cert-identity', $certificateIdentity, '--deny-self-hosted-runners')
  if ($Bundle -and (Test-Path -LiteralPath $Bundle -PathType Leaf) -and (Get-Item -LiteralPath $Bundle).Length -gt 0) {
    & $verifier.FullName @verifyArgs --bundle $Bundle *> $null
    if ($LASTEXITCODE -eq 0) { return }
    # The bundle is a transport for GitHub's signed attestation. Falling back
    # to GitHub's attestation API still requires the same digest and workflow
    # identity, and therefore remains fail closed.
    Write-Warning 'Release provenance bundle 验证失败，改用 GitHub attestation API 重试。'
  }
  & $verifier.FullName @verifyArgs *> $null
  if ($LASTEXITCODE -ne 0) { Fail 'Agent provenance 验证失败' }
}

function Convert-ToSidString($IdentityName) {
  $account = New-Object Security.Principal.NTAccount($IdentityName)
  return $account.Translate([Security.Principal.SecurityIdentifier]).Value
}

function New-TokenAccessRule($IdentityName, [System.Security.AccessControl.FileSystemRights]$Rights) {
  $account = New-Object Security.Principal.NTAccount($IdentityName)
  return New-Object -TypeName Security.AccessControl.FileSystemAccessRule -ArgumentList @(
    $account,
    $Rights,
    [System.Security.AccessControl.AccessControlType]::Allow
  )
}

function New-TokenBootstrapAcl() {
  $acl = New-Object Security.AccessControl.FileSecurity
  $acl.SetAccessRuleProtection($true, $false)
  $acl.SetOwner((New-Object Security.Principal.NTAccount('BUILTIN\Administrators')))
  $acl.AddAccessRule((New-TokenAccessRule 'NT AUTHORITY\SYSTEM' ([System.Security.AccessControl.FileSystemRights]::FullControl)))
  $acl.AddAccessRule((New-TokenAccessRule 'BUILTIN\Administrators' ([System.Security.AccessControl.FileSystemRights]::FullControl)))
  return $acl
}

function Set-TokenBootstrapAcl($Path) {
  Set-Acl -Path $Path -AclObject (New-TokenBootstrapAcl)
}

function Assert-TokenBootstrapAcl($Path) {
  $allowed = @{}
  foreach ($identityName in @('NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators')) {
    $allowed[(Convert-ToSidString $identityName)] = $true
  }
  $acl = Get-Acl -Path $Path
  if (-not $acl.AreAccessRulesProtected) {
    Fail '临时 token 文件 ACL 仍继承父目录权限'
  }
  $seen = @{}
  foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
    $sid = $rule.IdentityReference.Value
    if ($rule.IsInherited) { Fail "临时 token 文件存在继承权限: $sid" }
    if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { Fail "临时 token 文件存在非 Allow 权限: $sid" }
    if (-not $allowed.ContainsKey($sid)) { Fail "临时 token 文件存在未授权主体: $sid" }
    $seen[$sid] = $true
  }
  foreach ($sid in $allowed.Keys) {
    if (-not $seen.ContainsKey($sid)) { Fail "临时 token 文件缺少必要 ACL: $sid" }
  }
}

function Write-StrictTemporaryTokenFile($Path, $TokenValue) {
  $acl = New-TokenBootstrapAcl
  $bytes = [Text.Encoding]::ASCII.GetBytes($TokenValue + [Environment]::NewLine)
  $stream = $null
  try {
    $stream = New-Object -TypeName System.IO.FileStream -ArgumentList @(
      $Path,
      [IO.FileMode]::CreateNew,
      [System.Security.AccessControl.FileSystemRights]::Write,
      [IO.FileShare]::None,
      4096,
      [IO.FileOptions]::WriteThrough,
      $acl
    )
    $stream.Write($bytes, 0, $bytes.Length)
  } finally {
    if ($stream) { $stream.Dispose() }
  }
  Set-TokenBootstrapAcl -Path $Path
  Assert-TokenBootstrapAcl -Path $Path
}

function Move-TokenIntoPlaceAtomically($Source, $Destination) {
  if (Test-Path -LiteralPath $Destination -PathType Leaf) {
    # Windows PowerShell 5.1/.NET Framework rejects a null backup path in the
    # four-argument File.Replace overload. Use a real same-directory backup so
    # replacement remains atomic, then remove the transient backup.
    $replaceBackup = Join-Path (Split-Path -Parent $Destination) ('.agent-token.replace-backup-' + [Guid]::NewGuid().ToString('N'))
    try {
      [IO.File]::Replace($Source, $Destination, $replaceBackup, $false)
    } finally {
      Remove-Item -Force -LiteralPath $replaceBackup -ErrorAction SilentlyContinue
    }
  } else {
    Move-Item -Force -LiteralPath $Source -Destination $Destination
  }
}

function Restore-TokenBackup($Backup, $Destination, $OldAcl) {
  if (-not $Backup -or -not (Test-Path -LiteralPath $Backup -PathType Leaf)) {
    throw "token 备份不存在，无法恢复: $Backup"
  }
  $restoreTmp = Join-Path (Split-Path -Parent $Destination) ('.agent-token.restore-' + [Guid]::NewGuid().ToString('N'))
  Copy-Item -LiteralPath $Backup -Destination $restoreTmp -ErrorAction Stop
  try {
    Move-TokenIntoPlaceAtomically -Source $restoreTmp -Destination $Destination
    if ($OldAcl) { Set-Acl -Path $Destination -AclObject $OldAcl -ErrorAction Stop }
  } finally {
    Remove-Item -Force -LiteralPath $restoreTmp -ErrorAction SilentlyContinue
  }
}

function Set-StrictTokenAcl($Path, $ServiceName) {
  $acl = New-Object Security.AccessControl.FileSecurity
  $acl.SetAccessRuleProtection($true, $false)
  $acl.SetOwner((New-Object Security.Principal.NTAccount('BUILTIN\Administrators')))
  $acl.AddAccessRule((New-TokenAccessRule 'NT AUTHORITY\SYSTEM' ([System.Security.AccessControl.FileSystemRights]::FullControl)))
  $acl.AddAccessRule((New-TokenAccessRule 'BUILTIN\Administrators' ([System.Security.AccessControl.FileSystemRights]::FullControl)))
  $acl.AddAccessRule((New-TokenAccessRule "NT SERVICE\$ServiceName" ([System.Security.AccessControl.FileSystemRights]::ReadAndExecute)))
  Set-Acl -Path $Path -AclObject $acl
}

function Assert-StrictTokenAcl($Path, $ServiceName) {
  $allowed = @{}
  foreach ($identityName in @('NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators', "NT SERVICE\$ServiceName")) {
    $allowed[(Convert-ToSidString $identityName)] = $true
  }
  $acl = Get-Acl -Path $Path
  if (-not $acl.AreAccessRulesProtected) {
    Fail 'token 文件 ACL 仍继承父目录权限'
  }
  $seen = @{}
  foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
    $sid = $rule.IdentityReference.Value
    if ($rule.IsInherited) { Fail "token 文件存在继承权限: $sid" }
    if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { Fail "token 文件存在非 Allow 权限: $sid" }
    if (-not $allowed.ContainsKey($sid)) { Fail "token 文件存在未授权读取主体: $sid" }
    $seen[$sid] = $true
  }
  foreach ($sid in $allowed.Keys) {
    if (-not $seen.ContainsKey($sid)) { Fail "token 文件缺少必要 ACL: $sid" }
  }
}

function ConvertTo-WindowsCommandLineArgument([string]$Value) {
  if ($Value -match "[`r`n]") { Fail '服务参数不能包含换行符' }
  # Follow CommandLineToArgvW rules: backslashes before a quote, and trailing
  # backslashes before the closing quote, must be doubled.
  $escaped = [Regex]::Replace($Value, '(\\*)"', '$1$1\"')
  $escaped = [Regex]::Replace($escaped, '(\\+)$', '$1$1')
  return '"' + $escaped + '"'
}

function Join-WindowsCommandLine($FilePath, [string[]]$Arguments) {
  $items = @((ConvertTo-WindowsCommandLineArgument $FilePath))
  foreach ($arg in $Arguments) { $items += (ConvertTo-WindowsCommandLineArgument $arg) }
  return ($items -join ' ')
}

function Wait-ServiceRunning($Name) {
  for ($i = 0; $i -lt 30; $i++) {
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') { return $true }
    Start-Sleep -Milliseconds 500
  }
  return $false
}

function Set-ServiceReceiptDirectoryAcl($Path, $Name) {
  New-Item -ItemType Directory -Force -Path $Path | Out-Null
  $acl = New-Object Security.AccessControl.DirectorySecurity
  $acl.SetAccessRuleProtection($true, $false)
  $inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
  $none = [Security.AccessControl.PropagationFlags]::None
  foreach ($entry in @(
    @{ Identity = 'NT AUTHORITY\SYSTEM'; Rights = [Security.AccessControl.FileSystemRights]::FullControl },
    @{ Identity = 'BUILTIN\Administrators'; Rights = [Security.AccessControl.FileSystemRights]::FullControl },
    @{ Identity = "NT SERVICE\$Name"; Rights = [Security.AccessControl.FileSystemRights]::Modify }
  )) {
    $rule = New-Object -TypeName Security.AccessControl.FileSystemAccessRule -ArgumentList @(
      $entry.Identity, $entry.Rights, $inherit, $none, [Security.AccessControl.AccessControlType]::Allow
    )
    $acl.AddAccessRule($rule)
  }
  $acl.SetOwner((New-Object Security.Principal.NTAccount('BUILTIN\Administrators')))
  Set-Acl -LiteralPath $Path -AclObject $acl
}

function Wait-ServiceInstallReceipt($Name, $Path, $Nonce, $ExpectedAccount, $TimeoutSeconds) {
  $expectedSid = Convert-ToSidString $ExpectedAccount
  $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
  while ([DateTime]::UtcNow -lt $deadline) {
    $service = Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction Stop
    if (-not $service -or $service.State -ne 'Running' -or [uint32]$service.ProcessId -eq 0) {
      Fail 'Zeno Agent SCM 服务在回执前退出，准备回滚'
    }
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
      $content = [IO.File]::ReadAllText($Path).TrimEnd([char[]]"`r`n")
      if ($content -ne "$InstallReceiptPrefix $Nonce") { Fail '安装回执内容无效，准备回滚' }
      $ownerSid = (New-Object Security.Principal.NTAccount((Get-Acl -LiteralPath $Path).Owner)).Translate([Security.Principal.SecurityIdentifier]).Value
      if ($ownerSid -ne $expectedSid) { Fail '安装回执并非由实际服务账户创建，准备回滚' }
      $process = Get-CimInstance Win32_Process -Filter "ProcessId=$($service.ProcessId)" -ErrorAction Stop
      $owner = Invoke-CimMethod -InputObject $process -MethodName GetOwner -ErrorAction Stop
      if ($owner.ReturnValue -ne 0) { Fail '无法读取 SCM 服务进程身份，准备回滚' }
      $processAccount = if ($owner.Domain) { "$($owner.Domain)\$($owner.User)" } else { [string]$owner.User }
      if ((Convert-ToSidString $processAccount) -ne $expectedSid) { Fail 'SCM 服务进程未以预期低权限身份运行，准备回滚' }
      Remove-Item -Force -LiteralPath $Path
      return
    }
    Start-Sleep -Seconds 1
  }
  Fail '等待低权限 SCM 服务 heartbeat/state 回执超时，准备回滚'
}

function Stop-ServiceAndWait($Name) {
  $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
  if (-not $svc) { return $true }
  if ($svc.Status -ne 'Stopped') {
    Stop-Service -Name $Name -ErrorAction Stop
  }
  for ($i = 0; $i -lt 30; $i++) {
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $svc -or $svc.Status -eq 'Stopped') { return $true }
    Start-Sleep -Milliseconds 500
  }
  return $false
}

function Restore-PreviousBinary($Backup, $Destination, $ServiceName) {
  if (-not $Backup -or -not (Test-Path -LiteralPath $Backup -PathType Leaf)) {
    return $false
  }
  try {
    if (-not (Stop-ServiceAndWait -Name $ServiceName)) { return $false }
    Copy-Item -Force -LiteralPath $Backup -Destination $Destination -ErrorAction Stop
    if (-not (Test-Path -LiteralPath $Destination -PathType Leaf)) { return $false }
    $backupHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Backup).Hash
    $destinationHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $Destination).Hash
    return $backupHash -eq $destinationHash
  } catch {
    return $false
  }
}

function Remove-OldBinaryBackups($Destination, [int]$Keep = 3) {
  $directory = Split-Path -Parent $Destination
  $leaf = Split-Path -Leaf $Destination
  Get-ChildItem -LiteralPath $directory -File -ErrorAction Stop |
    Where-Object { $_.Name.StartsWith($leaf + '.bak-', [StringComparison]::Ordinal) } |
    Sort-Object LastWriteTimeUtc, Name -Descending |
    Select-Object -Skip $Keep |
    Remove-Item -Force -ErrorAction Stop
}

function Assert-RegularFileOrAbsent($Path, $Label) {
  if (-not (Test-Path -LiteralPath $Path)) { return }
  $item = Get-Item -Force -LiteralPath $Path
  if (-not ($item -is [IO.FileInfo]) -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
    Fail "$Label 必须是非重解析点的普通文件: $Path"
  }
}

function Get-ServiceRegistryPolicy($Name) {
  $path = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\$Name"
  $item = Get-ItemProperty -LiteralPath $path -ErrorAction Stop
  $start = [int]$item.Start
  $delayedProperty = $item.PSObject.Properties['DelayedAutostart']
  $sidProperty = $item.PSObject.Properties['ServiceSidType']
  $privilegesProperty = $item.PSObject.Properties['RequiredPrivileges']
  $delayed = if ($delayedProperty) { [int]$delayedProperty.Value } else { 0 }
  $sidType = if ($sidProperty) { [int]$sidProperty.Value } else { 0 }
  $requiredPrivileges = if ($privilegesProperty) { @($privilegesProperty.Value) } else { @() }
  if ($start -notin @(2, 3, 4)) { Fail "现有服务启动策略不受支持，拒绝修改: Start=$start" }
  if ($sidType -notin @(0, 1, 3)) { Fail "现有服务 SID 策略不受支持，拒绝修改: ServiceSidType=$sidType" }
  return [PSCustomObject]@{
    Start = $start
    DelayedAutoStart = $delayed
    SidType = $sidType
    RequiredPrivileges = @($requiredPrivileges)
  }
}

function Set-ServiceBinaryPath($Name, $BinaryPathName) {
  $service = Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction Stop
  if (-not $service) { return $false }
  $result = Invoke-CimMethod -InputObject $service -MethodName Change -Arguments @{ PathName = $BinaryPathName } -ErrorAction Stop
  return $result -and ([int]$result.ReturnValue -eq 0)
}

function Set-ServiceLogonAccount($Name, $AccountName) {
  # Virtual service accounts are configured without a password argument.
  # Passing password= "" can be rejected with ERROR_INVALID_SERVICE_ACCOUNT
  # (1057), even though the account itself is valid. ProcessStartInfo keeps the
  # remaining quoted account name independent of PowerShell 5.1 native parsing.
  if ($Name -notmatch '^[A-Za-z0-9_.-]+$') { throw "invalid service name: $Name" }
  $virtualAccount = "NT SERVICE\$Name"
  if (-not $AccountName.Equals('LocalSystem', [StringComparison]::OrdinalIgnoreCase) -and
      -not $AccountName.Equals($virtualAccount, [StringComparison]::OrdinalIgnoreCase)) {
    throw "unsupported service account: $AccountName"
  }
  $startInfo = New-Object Diagnostics.ProcessStartInfo
  $startInfo.FileName = Join-Path $env:SystemRoot 'System32\sc.exe'
  $startInfo.Arguments = 'config "{0}" obj= "{1}"' -f $Name, $AccountName
  $startInfo.UseShellExecute = $false
  $startInfo.CreateNoWindow = $true
  $startInfo.RedirectStandardOutput = $true
  $startInfo.RedirectStandardError = $true
  $process = [Diagnostics.Process]::Start($startInfo)
  $standardOutput = $process.StandardOutput.ReadToEnd()
  $standardError = $process.StandardError.ReadToEnd()
  $process.WaitForExit()
  $exitCode = $process.ExitCode
  if ($exitCode -ne 0) {
    [Console]::Error.WriteLine("sc.exe 服务账户更新失败 (exit=$exitCode): $standardOutput $standardError")
  }
  return $exitCode -eq 0
}

function Test-ServiceLogonAccount($Name, $AccountName) {
  $service = Get-CimInstance Win32_Service -Filter "Name='$Name'" -ErrorAction Stop
  return $service -and ([string]$service.StartName).Equals($AccountName, [StringComparison]::OrdinalIgnoreCase)
}

function Assert-ServiceLogonAccount($Name, $AccountName) {
  if (-not (Test-ServiceLogonAccount -Name $Name -AccountName $AccountName)) {
    Fail "Zeno Agent 服务账户未生效: $AccountName"
  }
}

function Set-ServiceRequiredPrivileges($Name, [string[]]$Privileges) {
  $privilegeList = (@($Privileges) -join '/')
  # Windows PowerShell 5.1 can drop a native empty-string argument. Preserve
  # the quoted empty value explicitly so rollback can clear an originally
  # absent RequiredPrivileges list instead of accidentally querying it.
  $privilegeListArgument = if ($privilegeList) { $privilegeList } else { '""' }
  & sc.exe privs $Name $privilegeListArgument | Out-Null
  return $LASTEXITCODE -eq 0
}

function Convert-ServiceStartPolicyToScValue($Start, $DelayedAutoStart) {
  switch ([int]$Start) {
    2 { if ([int]$DelayedAutoStart -ne 0) { return 'delayed-auto' }; return 'auto' }
    3 { return 'demand' }
    4 { return 'disabled' }
    default { throw "unsupported service Start value: $Start" }
  }
}

function Convert-ServiceSidTypeToScValue($SidType) {
  switch ([int]$SidType) {
    0 { return 'none' }
    1 { return 'unrestricted' }
    3 { return 'restricted' }
    default { throw "unsupported service SID type: $SidType" }
  }
}

function Assert-ControllerURL($Value) {
  $script:AllowInsecureHTTP = $false
  $parsed = $null
  if (-not [Uri]::TryCreate($Value, [UriKind]::Absolute, [ref]$parsed)) {
    Fail 'ZENO_CONTROLLER_URL 不是有效的绝对 URL'
  }
  if ($parsed.UserInfo -or $parsed.Query -or $parsed.Fragment) {
    Fail 'ZENO_CONTROLLER_URL 不能包含凭据、查询参数或片段'
  }
  if ($parsed.Scheme -eq 'https') { return }
  if ($parsed.Scheme -eq 'http') {
    $address = $null
    $isIPAddress = [Net.IPAddress]::TryParse($parsed.DnsSafeHost, [ref]$address)
    $isLoopbackAddress = $isIPAddress -and [Net.IPAddress]::IsLoopback($address)
    if ($parsed.DnsSafeHost -eq 'localhost' -or $isLoopbackAddress) { return }
    $authorityMatch = [Text.RegularExpressions.Regex]::Match($Value, '^[A-Za-z][A-Za-z0-9+.-]*://([^/]+)')
    $authority = if ($authorityMatch.Success) { $authorityMatch.Groups[1].Value } else { '' }
    $hasExplicitPort = ($authority -match '^\[[^]]+\]:[0-9]+$') -or ($authority -match '^[^:]+:[0-9]+$')
    if ($isIPAddress -and $hasExplicitPort -and $parsed.Port -ge 1 -and $parsed.Port -le 65535) {
      if (-not $AllowInsecureHTTPRequested) { Fail '远程 HTTP 需要显式设置 ZENO_ALLOW_INSECURE_HTTP=1；token 将以明文传输' }
      $script:AllowInsecureHTTP = $true
      return
    }
  }
  if ($parsed.Scheme -eq 'http') { Fail '远程 ZENO_CONTROLLER_URL 必须使用 https' }
  Fail 'ZENO_CONTROLLER_URL 必须使用 http 或 https'
}

if (-not $ControllerURL) { Fail '必须设置 ZENO_CONTROLLER_URL' }
if (-not $NodeID) { Fail '必须设置 ZENO_NODE_ID' }
if ($Token -and $EnrollmentToken) { Fail 'ZENO_AGENT_TOKEN 与 ZENO_ENROLLMENT_TOKEN 不能同时设置' }
Assert-ControllerURL $ControllerURL
if ($AllowInsecureHTTP) {
  Write-Warning '远程 Controller 使用 HTTP；enrollment/runtime bearer token 将以明文传输，并会在服务配置中持久化显式 opt-in。'
}
$ExistingTokenUsable = (Test-Path -LiteralPath $TokenFile -PathType Leaf) -and ((Get-Item -LiteralPath $TokenFile).Length -gt 0)
if (-not $Token -and -not $EnrollmentToken -and -not $ExistingTokenUsable) { Fail '必须设置 ZENO_ENROLLMENT_TOKEN、ZENO_AGENT_TOKEN 或提供已有非空 token 文件' }

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Fail '请使用管理员身份运行 PowerShell'
}
Assert-RegularFileOrAbsent -Path $Bin -Label 'Agent 二进制'
Assert-RegularFileOrAbsent -Path $TokenFile -Label 'token 文件'

$archName = $env:PROCESSOR_ARCHITECTURE
if ($archName -eq 'AMD64') {
  $GoArch = 'amd64'
} elseif ($archName -eq 'ARM64') {
  $GoArch = 'arm64'
} else {
  Fail "暂不支持架构: $archName"
}

if ($Version -eq 'latest') {
  $release = Invoke-DownloadJson "https://api.github.com/repos/$Repo/releases/latest"
  $Version = $release.tag_name
  if (-not $Version) { Fail '无法获取最新版本' }
}
if ($Version -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9][A-Za-z0-9.-]*)?$') { Fail "版本标签格式无效: $Version" }

$Asset = "zeno-agent_windows_$GoArch.zip"
$Url = "https://github.com/$Repo/releases/download/$Version/$Asset"
$SumsUrl = "https://github.com/$Repo/releases/download/$Version/SHA256SUMS"
$ProvenanceAsset = 'zeno-agent_provenance.sigstore.json'
$ProvenanceUrl = "https://github.com/$Repo/releases/download/$Version/$ProvenanceAsset"
$Temp = Join-Path ([IO.Path]::GetTempPath()) ("zeno-agent-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $Temp | Out-Null
$BackupBin = $null
$OldBinaryPathName = $null
$OldServiceStart = $null
$OldDelayedAutoStart = 0
$OldServiceSidType = $null
$OldServiceStartName = $null
$OldServiceRequiredPrivileges = @()
$ServiceSidTypeChanged = $false
$ServiceAccountChanged = $false
$ServiceRequiredPrivilegesChanged = $false
$ManagedServiceAccount = $false
$ServiceBinPathChanged = $false
$OldServiceWasRunning = $false
$Existing = $null
$CreatedService = $false
$HadExistingBinary = Test-Path -LiteralPath $Bin -PathType Leaf
$HadExistingToken = Test-Path -LiteralPath $TokenFile -PathType Leaf
$BackupToken = $null
$OldTokenAcl = $null
$RestoredPreviousBinary = $false
$RecoveryBackupPath = $null
$InstallSucceeded = $false
$EnrollmentExchangeSucceeded = $false
$EnrollmentTokenInstalled = $false
$InstallReceiptNonce = $null
$InstallReceiptDir = $null
$InstallReceiptFile = $null
try {
  $Archive = Join-Path $Temp $Asset
  $Sums = Join-Path $Temp 'SHA256SUMS'
  Write-Host "下载 Zeno Agent $Version (windows/$GoArch)..."
  Invoke-DownloadFile -Uri $Url -OutFile $Archive
  Invoke-DownloadFile -Uri $SumsUrl -OutFile $Sums
  Assert-ArchiveChecksum -Archive $Archive -SumsFile $Sums -AssetName $Asset
  $ProvenanceBundle = Join-Path $Temp $ProvenanceAsset
  if ($VerifyAttestation -eq 'true') {
    try {
      Invoke-DownloadFile -Uri $ProvenanceUrl -OutFile $ProvenanceBundle
    } catch {
      Remove-Item -Force -LiteralPath $ProvenanceBundle -ErrorAction SilentlyContinue
      Write-Warning 'Release 未提供 provenance bundle，改用 GitHub attestation API 验证。'
    }
  }
  Assert-ReleaseProvenance -Archive $Archive -Bundle $ProvenanceBundle -TempDir $Temp

  Expand-Archive -Force -Path $Archive -DestinationPath $Temp
  $Found = Get-ChildItem -Path $Temp -Recurse -Filter 'zeno-agent.exe' | Select-Object -First 1
  if (-not $Found) { Fail '压缩包内未找到 zeno-agent.exe' }

  $Existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
  if ($Existing) {
    if ($Existing.Status -notin @('Running', 'Stopped')) {
      Fail "旧 zeno-agent 服务状态不稳定，拒绝修改: $($Existing.Status)"
    }
    $OldServiceWasRunning = $Existing.Status -eq 'Running'
    $oldService = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
    if (-not $oldService -or -not $oldService.PathName) { Fail '无法读取旧 zeno-agent 服务配置，拒绝修改' }
    $oldPolicy = Get-ServiceRegistryPolicy -Name $ServiceName
    $OldBinaryPathName = $oldService.PathName
    $OldServiceStart = $oldPolicy.Start
    $OldDelayedAutoStart = $oldPolicy.DelayedAutoStart
    $OldServiceSidType = $oldPolicy.SidType
    $OldServiceStartName = [string]$oldService.StartName
    if (-not $OldServiceStartName) { Fail '无法读取旧 zeno-agent 服务账户，拒绝修改' }
    $OldServiceRequiredPrivileges = @($oldPolicy.RequiredPrivileges)
    if (-not (Stop-ServiceAndWait -Name $ServiceName)) { Fail '旧 zeno-agent 服务停止超时，拒绝覆盖现有二进制' }
  }

  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Bin), (Split-Path -Parent $TokenFile) | Out-Null
  $NewBin = Join-Path (Split-Path -Parent $Bin) ('.' + (Split-Path -Leaf $Bin) + '.new-' + [Guid]::NewGuid().ToString('N'))
  Copy-Item -Force -Path $Found.FullName -Destination $NewBin
  if (Test-Path $Bin) {
    $BackupBin = "$Bin.bak-$(Get-Date -Format 'yyyyMMddHHmmss')-$([Guid]::NewGuid().ToString('N'))"
    [IO.File]::Replace($NewBin, $Bin, $BackupBin, $false)
  } else {
    Move-Item -Force -Path $NewBin -Destination $Bin
  }

  if ($HadExistingToken) {
    $OldTokenAcl = Get-Acl -Path $TokenFile
    $BackupToken = Join-Path (Split-Path -Parent $TokenFile) ('.agent-token.backup-' + (Get-Date -Format 'yyyyMMddHHmmss') + '-' + [Guid]::NewGuid().ToString('N'))
    Copy-Item -Force -Path $TokenFile -Destination $BackupToken
    Set-TokenBootstrapAcl -Path $BackupToken
    Assert-TokenBootstrapAcl -Path $BackupToken
  }
  if ($EnrollmentToken) {
    $Token = New-AgentRuntimeToken
  }
  if ($Token) {
    $TokenTmp = Join-Path (Split-Path -Parent $TokenFile) ('.agent-token.tmp-' + [Guid]::NewGuid().ToString('N'))
    try {
      Write-StrictTemporaryTokenFile -Path $TokenTmp -TokenValue $Token
      if (Test-Path -LiteralPath $TokenFile -PathType Leaf) {
        Set-TokenBootstrapAcl -Path $TokenFile
        Assert-TokenBootstrapAcl -Path $TokenFile
      }
      Move-TokenIntoPlaceAtomically -Source $TokenTmp -Destination $TokenFile
      Assert-TokenBootstrapAcl -Path $TokenFile
    } finally {
      Remove-Item -Force -LiteralPath $TokenTmp -ErrorAction SilentlyContinue
    }
  }
  if ($EnrollmentToken) {
    try {
      # Persist the generated runtime token before consuming the one-time
      # enrollment credential. Once exchange succeeds this token is the only
      # recoverable credential on a fresh install, so every later rollback must
      # preserve its contents even if SCM/ACL setup subsequently fails.
      Invoke-AgentEnrollment -RuntimeToken $Token
      $EnrollmentExchangeSucceeded = $true
      $EnrollmentTokenInstalled = $true
      $EnrollmentToken = $null
    } catch {
      $enrollmentError = $_
      if (-not ($HadExistingToken -and $BackupToken -and (Test-Path -LiteralPath $BackupToken -PathType Leaf))) {
        throw
      }
      try {
        # A prior attempt can successfully exchange the one-time credential,
        # then fail during a later transactional SCM/ACL step. In that case the
        # protected existing token is already authoritative and the same copied
        # install command must be safely retryable without another enrollment.
        Restore-TokenBackup -Backup $BackupToken -Destination $TokenFile -OldAcl $OldTokenAcl
        $Token = $null
        $EnrollmentToken = $null
        Write-Warning '一次性 enrollment token 已失效；将验证并复用现有 runtime token 继续升级。'
      } catch {
        throw $enrollmentError
      }
    }
  }

  $Args = @(
    '-controller-url', $ControllerURL,
    '-node-id', $NodeID,
    '-token-file', $TokenFile,
    '-state-interval', $StateInterval,
    '-heartbeat-interval', $HeartbeatInterval,
    '-host-interval', $HostInterval,
    '-identity-refresh-interval', $IdentityRefreshInterval,
    '-version', $Version
  )
  if ($NetworkInterfaces) { $Args += @('-network-interfaces', $NetworkInterfaces) }
  if ($DiskMounts) { $Args += @('-disk-mounts', $DiskMounts) }
  if ($AllowInsecureHTTP) { $Args += '-allow-insecure-http' }

  # Verify the downloaded binary, runtime token, Controller URL, and TLS path
  # before mutating SCM. The token itself remains in the protected token file
  # and is never placed in argv or inherited process environment.
  $CheckArgs = @($Args) + @('-install-check')
  & $Bin @CheckArgs
  if ($LASTEXITCODE -ne 0) {
    Fail 'Agent 本地安装预检失败，准备回滚'
  }
  if ($InstallReceiptTimeout -le 0) { Fail 'ZENO_AGENT_INSTALL_RECEIPT_TIMEOUT 必须为正整数秒' }
  $InstallReceiptNonce = ([Guid]::NewGuid().ToString('N') + [Guid]::NewGuid().ToString('N'))
  $InstallReceiptDir = Join-Path $env:ProgramData 'Zeno\install-receipts'
  $InstallReceiptFile = Join-Path $InstallReceiptDir ("install-receipt-$InstallReceiptNonce")
  Remove-Item -Force -LiteralPath $InstallReceiptFile -ErrorAction SilentlyContinue
  $Args += @('-install-receipt-file', $InstallReceiptFile, '-install-receipt-nonce', $InstallReceiptNonce)
  $BinPath = Join-WindowsCommandLine -FilePath $Bin -Arguments $Args

  if ($Existing) {
    if (-not (Set-ServiceBinaryPath -Name $ServiceName -BinaryPathName $BinPath)) { Fail 'Zeno Agent 服务配置更新失败' }
    $ServiceBinPathChanged = $true
    & sc.exe config $ServiceName start= auto | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail 'Zeno Agent 服务启动策略更新失败' }
  } else {
    New-Service -Name $ServiceName -BinaryPathName $BinPath -DisplayName 'Zeno Agent' -StartupType Automatic | Out-Null
    $CreatedService = $true
  }
  if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) { Fail 'Zeno Agent 服务创建失败' }
  if ($CreatedService) {
    & sc.exe sidtype $ServiceName unrestricted | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail 'Zeno Agent 服务 SID 配置失败' }
    if (-not (Set-ServiceLogonAccount -Name $ServiceName -AccountName "NT SERVICE\$ServiceName")) { Fail 'Zeno Agent 虚拟服务账户配置失败' }
    $ManagedServiceAccount = $true
    Assert-ServiceLogonAccount -Name $ServiceName -AccountName "NT SERVICE\$ServiceName"
    if (-not (Set-ServiceRequiredPrivileges -Name $ServiceName -Privileges @('SeChangeNotifyPrivilege'))) { Fail 'Zeno Agent 服务权限收敛配置失败' }
    & sc.exe failure $ServiceName reset= 60 actions= restart/5000/restart/5000/restart/5000 | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail 'Zeno Agent 服务失败恢复策略配置失败' }
  } else {
    if ($OldServiceSidType -eq 0) {
      # The NT SERVICE\<name> virtual account is only resolvable after the
      # service has a SID. Configure it before migrating away from LocalSystem.
      & sc.exe sidtype $ServiceName unrestricted | Out-Null
      if ($LASTEXITCODE -ne 0) { Fail 'Zeno Agent 服务 SID 配置失败' }
      $ServiceSidTypeChanged = $true
    }
    if ($OldServiceStartName.Equals('LocalSystem', [StringComparison]::OrdinalIgnoreCase)) {
      # LocalSystem has no password to recover, so this legacy account can be
      # migrated transactionally. Unknown/custom accounts are deliberately
      # left untouched because their passwords cannot be reconstructed.
      if (-not (Set-ServiceLogonAccount -Name $ServiceName -AccountName "NT SERVICE\$ServiceName")) { Fail '旧 Zeno Agent 服务降权迁移失败' }
      $ServiceAccountChanged = $true
      $ManagedServiceAccount = $true
      Assert-ServiceLogonAccount -Name $ServiceName -AccountName "NT SERVICE\$ServiceName"
    } elseif ($OldServiceStartName.Equals("NT SERVICE\$ServiceName", [StringComparison]::OrdinalIgnoreCase)) {
      $ManagedServiceAccount = $true
      Assert-ServiceLogonAccount -Name $ServiceName -AccountName "NT SERVICE\$ServiceName"
    } else {
      Write-Warning "保留现有 zeno-agent 自定义服务账户: $OldServiceStartName"
    }
    if ($ManagedServiceAccount -and ((@($OldServiceRequiredPrivileges) -join '/') -ne 'SeChangeNotifyPrivilege')) {
      if (-not (Set-ServiceRequiredPrivileges -Name $ServiceName -Privileges @('SeChangeNotifyPrivilege'))) { Fail 'Zeno Agent 服务权限收敛配置失败' }
      $ServiceRequiredPrivilegesChanged = $true
    }
  }

  $effectivePolicy = Get-ServiceRegistryPolicy -Name $ServiceName
  if ($effectivePolicy.SidType -eq 0) { Fail 'Zeno Agent 服务 SID 未生效' }
  if ($ManagedServiceAccount -and ((@($effectivePolicy.RequiredPrivileges) -join '/') -ne 'SeChangeNotifyPrivilege')) {
    Fail 'Zeno Agent 服务最小权限列表未生效'
  }

  Set-ServiceReceiptDirectoryAcl -Path $InstallReceiptDir -Name $ServiceName

  Set-StrictTokenAcl -Path $TokenFile -ServiceName $ServiceName
  Assert-StrictTokenAcl -Path $TokenFile -ServiceName $ServiceName

  Start-Service -Name $ServiceName
  if (-not (Wait-ServiceRunning -Name $ServiceName)) { Fail 'Zeno Agent 服务未进入 Running 状态' }

  Assert-StrictTokenAcl -Path $TokenFile -ServiceName $ServiceName
  $EffectiveService = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction Stop
  Wait-ServiceInstallReceipt -Name $ServiceName -Path $InstallReceiptFile -Nonce $InstallReceiptNonce -ExpectedAccount ([string]$EffectiveService.StartName) -TimeoutSeconds $InstallReceiptTimeout
  if ($BackupBin) {
    try {
      Remove-OldBinaryBackups -Destination $Bin -Keep 3
    } catch {
      Write-Warning "旧二进制备份轮转失败；请手动仅保留最新 3 份: $Bin.bak-*"
    }
    Write-Host "已保留旧二进制: $BackupBin"
  }
  Write-Host "Zeno Agent 已安装并启动: node=$NodeID version=$Version"
  $InstallSucceeded = $true
} catch {
  $installError = $_
  if ($CreatedService) {
    Stop-Service -Name $ServiceName -ErrorAction SilentlyContinue
    & sc.exe delete $ServiceName | Out-Null
  }
  if ($BackupBin) {
    $RestoredPreviousBinary = Restore-PreviousBinary -Backup $BackupBin -Destination $Bin -ServiceName $ServiceName
    if (-not $RestoredPreviousBinary -and (Test-Path -LiteralPath $BackupBin -PathType Leaf)) {
      try {
        $candidateRecoveryPath = Join-Path $InstallDir ("zeno-agent.exe.rollback-" + (Get-Date -Format 'yyyyMMddHHmmss'))
        Copy-Item -Force -LiteralPath $BackupBin -Destination $candidateRecoveryPath -ErrorAction Stop
        $backupHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $BackupBin).Hash
        $recoveryHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $candidateRecoveryPath).Hash
        if ($backupHash -eq $recoveryHash) {
          $RecoveryBackupPath = $candidateRecoveryPath
        } else {
          Remove-Item -Force -LiteralPath $candidateRecoveryPath -ErrorAction SilentlyContinue
        }
      } catch {
        $RecoveryBackupPath = $null
      }
    }
  } elseif (-not $HadExistingBinary -and (Test-Path $Bin)) {
    Remove-Item -Force -Path $Bin -ErrorAction SilentlyContinue
  }
  if (-not $EnrollmentTokenInstalled) {
    if ($HadExistingToken -and $BackupToken -and (Test-Path $BackupToken)) {
      try {
        Restore-TokenBackup -Backup $BackupToken -Destination $TokenFile -OldAcl $OldTokenAcl
      } catch {
        [Console]::Error.WriteLine("token 文件恢复失败，备份仍保留在: $BackupToken；错误: $_")
      }
    } elseif (-not $HadExistingToken -and (Test-Path $TokenFile)) {
      Remove-Item -Force -Path $TokenFile -ErrorAction SilentlyContinue
    }
  } elseif ($HadExistingToken -and $OldTokenAcl -and (Test-Path -LiteralPath $TokenFile -PathType Leaf)) {
    # Keep the new token contents, but restore the prior service's ACL policy
    # before reverting its SCM SID configuration.
    try {
      Set-Acl -Path $TokenFile -AclObject $OldTokenAcl -ErrorAction Stop
    } catch {
      [Console]::Error.WriteLine("新 runtime token 的旧 ACL 策略恢复失败: $_")
    }
  }
  if ($ServiceBinPathChanged -and $OldBinaryPathName -and -not $CreatedService) {
    try {
      if (-not (Set-ServiceBinaryPath -Name $ServiceName -BinaryPathName $OldBinaryPathName)) {
        [Console]::Error.WriteLine('旧服务 binPath 恢复失败')
      }
    } catch {
      [Console]::Error.WriteLine("旧服务 binPath 恢复失败: $_")
    }
  }
  if ($ServiceRequiredPrivilegesChanged -and -not $CreatedService) {
    try {
      if (-not (Set-ServiceRequiredPrivileges -Name $ServiceName -Privileges $OldServiceRequiredPrivileges)) {
        [Console]::Error.WriteLine('旧服务最小权限列表恢复失败')
      } else {
        $restoredPrivileges = @((Get-ServiceRegistryPolicy -Name $ServiceName).RequiredPrivileges)
        if (($restoredPrivileges -join '/') -ne (@($OldServiceRequiredPrivileges) -join '/')) {
          [Console]::Error.WriteLine('旧服务最小权限列表恢复验证失败')
        }
      }
    } catch {
      [Console]::Error.WriteLine("旧服务最小权限列表恢复验证失败: $_")
    }
  }
  if ($ServiceAccountChanged -and $OldServiceStartName -and -not $CreatedService) {
    try {
      if (-not (Set-ServiceLogonAccount -Name $ServiceName -AccountName $OldServiceStartName) -or
          -not (Test-ServiceLogonAccount -Name $ServiceName -AccountName $OldServiceStartName)) {
        [Console]::Error.WriteLine("旧服务账户恢复失败: $OldServiceStartName")
      }
    } catch {
      [Console]::Error.WriteLine("旧服务账户恢复验证失败: $OldServiceStartName；错误: $_")
    }
  }
  if ($ServiceSidTypeChanged -and $null -ne $OldServiceSidType -and -not $CreatedService) {
    # Keep the service SID available until a migrated virtual account has been
    # restored to LocalSystem; disabling it first makes the virtual identity
    # unresolvable on Windows PowerShell 5.1 hosts.
    $restoreSidType = Convert-ServiceSidTypeToScValue -SidType $OldServiceSidType
    & sc.exe sidtype $ServiceName $restoreSidType | Out-Null
    if ($LASTEXITCODE -ne 0) { [Console]::Error.WriteLine("旧服务 SID 策略恢复失败: $restoreSidType") }
  }
  if ($Existing -and -not $CreatedService -and $null -ne $OldServiceStart) {
    $restoreStartMode = Convert-ServiceStartPolicyToScValue -Start $OldServiceStart -DelayedAutoStart $OldDelayedAutoStart
    $startModeBeforeStateRestore = if ($OldServiceWasRunning -and $restoreStartMode -eq 'disabled') { 'demand' } else { $restoreStartMode }
    & sc.exe config $ServiceName start= $startModeBeforeStateRestore | Out-Null
    if ($LASTEXITCODE -ne 0) {
      [Console]::Error.WriteLine("旧服务启动策略恢复失败: $startModeBeforeStateRestore")
    }
    if ($OldServiceWasRunning) {
      try {
        Start-Service -Name $ServiceName -ErrorAction Stop
        if (-not (Wait-ServiceRunning -Name $ServiceName)) { throw '服务未进入 Running 状态' }
      } catch {
        [Console]::Error.WriteLine("旧服务 active 状态恢复失败: $_")
      }
    } else {
      if (-not (Stop-ServiceAndWait -Name $ServiceName)) {
        [Console]::Error.WriteLine('旧服务 stopped 状态恢复失败')
      }
    }
    if ($startModeBeforeStateRestore -ne $restoreStartMode) {
      & sc.exe config $ServiceName start= $restoreStartMode | Out-Null
      if ($LASTEXITCODE -ne 0) { [Console]::Error.WriteLine("旧服务启动策略恢复失败: $restoreStartMode") }
    }
  }
  if ($HadExistingBinary -and -not $RestoredPreviousBinary) {
    if ($RecoveryBackupPath) {
      [Console]::Error.WriteLine("Zeno Agent 安装失败，旧二进制恢复未通过校验；原备份仍保留在: $BackupBin；恢复备份已保留在: $RecoveryBackupPath")
    } else {
      [Console]::Error.WriteLine("Zeno Agent 安装失败，旧二进制恢复未通过校验；原备份仍保留在: $BackupBin；且未能另存恢复备份。")
    }
  } elseif ($RestoredPreviousBinary) {
    [Console]::Error.WriteLine('Zeno Agent 安装失败，旧二进制已恢复并通过 SHA256 校验。')
  }
  [Console]::Error.WriteLine("原始错误: $installError")
  exit 1
} finally {
  if ($InstallReceiptFile) {
    Remove-Item -Force -LiteralPath $InstallReceiptFile -ErrorAction SilentlyContinue
  }
  if ($InstallSucceeded -and $BackupToken -and (Test-Path -LiteralPath $BackupToken -PathType Leaf)) {
    Remove-Item -Force -LiteralPath $BackupToken -ErrorAction SilentlyContinue
  }
  Remove-Item -Recurse -Force -Path $Temp -ErrorAction SilentlyContinue
}
