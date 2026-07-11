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
$StateInterval = if ($env:ZENO_AGENT_STATE_INTERVAL) { $env:ZENO_AGENT_STATE_INTERVAL } elseif ($env:ZENO_AGENT_INTERVAL) { $env:ZENO_AGENT_INTERVAL } else { '3s' }
$HeartbeatInterval = if ($env:ZENO_AGENT_HEARTBEAT_INTERVAL) { $env:ZENO_AGENT_HEARTBEAT_INTERVAL } else { '15s' }
$HostInterval = if ($env:ZENO_AGENT_HOST_INTERVAL) { $env:ZENO_AGENT_HOST_INTERVAL } else { '30m' }
$IdentityRefreshInterval = if ($env:ZENO_AGENT_IDENTITY_REFRESH_INTERVAL) { $env:ZENO_AGENT_IDENTITY_REFRESH_INTERVAL } else { '12h' }
$NetworkInterfaces = $env:ZENO_AGENT_NETWORK_INTERFACES
$DiskMounts = $env:ZENO_AGENT_DISK_MOUNTS
# The Windows binary registers this exact SCM service name in svc.Run.
$ServiceName = 'zeno-agent'

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
    $nullBackup = $null
    [IO.File]::Replace($Source, $Destination, $nullBackup, $false)
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

if (-not $ControllerURL) { Fail '必须设置 ZENO_CONTROLLER_URL' }
if (-not $NodeID) { Fail '必须设置 ZENO_NODE_ID' }
$ExistingTokenUsable = (Test-Path -LiteralPath $TokenFile -PathType Leaf) -and ((Get-Item -LiteralPath $TokenFile).Length -gt 0)
if (-not $Token -and -not $ExistingTokenUsable) { Fail '必须设置 ZENO_AGENT_TOKEN 或提供已有非空 token 文件' }

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Fail '请使用管理员身份运行 PowerShell'
}

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

$Asset = "zeno-agent_windows_$GoArch.zip"
$Url = "https://github.com/$Repo/releases/download/$Version/$Asset"
$SumsUrl = "https://github.com/$Repo/releases/download/$Version/SHA256SUMS"
$Temp = Join-Path ([IO.Path]::GetTempPath()) ("zeno-agent-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $Temp | Out-Null
$BackupBin = $null
$OldBinaryPathName = $null
$OldStartMode = $null
$OldDelayedAutoStart = $false
$OldServiceWasRunning = $false
$Existing = $null
$CreatedService = $false
$HadExistingBinary = Test-Path $Bin
$HadExistingToken = Test-Path $TokenFile
$BackupToken = $null
$OldTokenAcl = $null
$RestoredPreviousBinary = $false
$RecoveryBackupPath = $null
$InstallSucceeded = $false
try {
  $Archive = Join-Path $Temp $Asset
  $Sums = Join-Path $Temp 'SHA256SUMS'
  Write-Host "下载 Zeno Agent $Version (windows/$GoArch)..."
  Invoke-DownloadFile -Uri $Url -OutFile $Archive
  Invoke-DownloadFile -Uri $SumsUrl -OutFile $Sums
  Assert-ArchiveChecksum -Archive $Archive -SumsFile $Sums -AssetName $Asset

  Expand-Archive -Force -Path $Archive -DestinationPath $Temp
  $Found = Get-ChildItem -Path $Temp -Recurse -Filter 'zeno-agent.exe' | Select-Object -First 1
  if (-not $Found) { Fail '压缩包内未找到 zeno-agent.exe' }

  $Existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
  if ($Existing) {
    $OldServiceWasRunning = $Existing.Status -eq 'Running'
    $oldService = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
    if ($oldService) {
      $OldBinaryPathName = $oldService.PathName
      $OldStartMode = $oldService.StartMode
      $OldDelayedAutoStart = [bool]$oldService.DelayedAutoStart
      $OldServiceWasRunning = $oldService.State -eq 'Running'
    }
    if (-not (Stop-ServiceAndWait -Name $ServiceName)) { Fail '旧 zeno-agent 服务停止超时，拒绝覆盖现有二进制' }
  }

  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Bin), (Split-Path -Parent $TokenFile) | Out-Null
  $NewBin = Join-Path (Split-Path -Parent $Bin) ('.' + (Split-Path -Leaf $Bin) + '.new-' + [Guid]::NewGuid().ToString('N'))
  Copy-Item -Force -Path $Found.FullName -Destination $NewBin
  if (Test-Path $Bin) {
    $BackupBin = "$Bin.bak-$(Get-Date -Format 'yyyyMMddHHmmss')"
    [IO.File]::Replace($NewBin, $Bin, $BackupBin, $false)
  } else {
    Move-Item -Force -Path $NewBin -Destination $Bin
  }

  if ($HadExistingToken) {
    $BackupToken = Join-Path (Split-Path -Parent $TokenFile) ('.agent-token.backup-' + (Get-Date -Format 'yyyyMMddHHmmss') + '-' + [Guid]::NewGuid().ToString('N'))
    Copy-Item -Force -Path $TokenFile -Destination $BackupToken
    Set-TokenBootstrapAcl -Path $BackupToken
    Assert-TokenBootstrapAcl -Path $BackupToken
    $OldTokenAcl = Get-Acl -Path $TokenFile
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
  $BinPath = Join-WindowsCommandLine -FilePath $Bin -Arguments $Args

  if ($Existing) {
    & sc.exe config $ServiceName binPath= $BinPath start= auto | Out-Null
    if ($LASTEXITCODE -ne 0) { Fail 'Zeno Agent 服务配置更新失败' }
  } else {
    New-Service -Name $ServiceName -BinaryPathName $BinPath -DisplayName 'Zeno Agent' -StartupType Automatic | Out-Null
    $CreatedService = $true
  }
  if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) { Fail 'Zeno Agent 服务创建失败' }
  & sc.exe sidtype $ServiceName unrestricted | Out-Null
  if ($LASTEXITCODE -ne 0) { Fail 'Zeno Agent 服务 SID 配置失败' }
  & sc.exe failure $ServiceName reset= 60 actions= restart/5000/restart/5000/restart/5000 | Out-Null

  Set-StrictTokenAcl -Path $TokenFile -ServiceName $ServiceName
  Assert-StrictTokenAcl -Path $TokenFile -ServiceName $ServiceName

  Start-Service -Name $ServiceName
  if (-not (Wait-ServiceRunning -Name $ServiceName)) { Fail 'Zeno Agent 服务未进入 Running 状态' }

  Assert-StrictTokenAcl -Path $TokenFile -ServiceName $ServiceName
  if ($BackupBin) { Write-Host "已保留旧二进制: $BackupBin" }
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
  if ($HadExistingToken -and $BackupToken -and (Test-Path $BackupToken)) {
    try {
      Restore-TokenBackup -Backup $BackupToken -Destination $TokenFile -OldAcl $OldTokenAcl
    } catch {
      [Console]::Error.WriteLine("token 文件恢复失败，备份仍保留在: $BackupToken；错误: $_")
    }
  } elseif (-not $HadExistingToken -and (Test-Path $TokenFile)) {
    Remove-Item -Force -Path $TokenFile -ErrorAction SilentlyContinue
  }
  if ($OldBinaryPathName -and -not $CreatedService) {
    & sc.exe config $ServiceName binPath= $OldBinaryPathName | Out-Null
  }
  if ($OldStartMode -and -not $CreatedService) {
    $restoreStartMode = switch ($OldStartMode) {
      'Auto' { if ($OldDelayedAutoStart) { 'delayed-auto' } else { 'auto' } }
      'Manual' { 'demand' }
      'Disabled' { 'disabled' }
      default { $null }
    }
    if ($restoreStartMode) { & sc.exe config $ServiceName start= $restoreStartMode | Out-Null }
  }
  if ($Existing -and -not $CreatedService) {
    if ($OldServiceWasRunning) {
      Start-Service -Name $ServiceName -ErrorAction SilentlyContinue
    } else {
      Stop-Service -Name $ServiceName -ErrorAction SilentlyContinue
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
  if ($InstallSucceeded -and $BackupToken -and (Test-Path -LiteralPath $BackupToken -PathType Leaf)) {
    Remove-Item -Force -LiteralPath $BackupToken -ErrorAction SilentlyContinue
  }
  Remove-Item -Recurse -Force -Path $Temp -ErrorAction SilentlyContinue
}
