$ErrorActionPreference = 'Stop'

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
$ServiceName = if ($env:ZENO_AGENT_SERVICE_NAME) { $env:ZENO_AGENT_SERVICE_NAME } else { 'zeno-agent' }

function Fail($Message) {
  Write-Error "错误: $Message"
  exit 1
}

if (-not $ControllerURL) { Fail '必须设置 ZENO_CONTROLLER_URL' }
if (-not $NodeID) { Fail '必须设置 ZENO_NODE_ID' }
if (-not $Token -and -not (Test-Path $TokenFile)) { Fail '必须设置 ZENO_AGENT_TOKEN 或提供已有 token 文件' }

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
  $release = Invoke-RestMethod -UseBasicParsing -Uri "https://api.github.com/repos/$Repo/releases/latest"
  $Version = $release.tag_name
  if (-not $Version) { Fail '无法获取最新版本' }
}

$Asset = "zeno-agent_windows_$GoArch.zip"
$Url = "https://github.com/$Repo/releases/download/$Version/$Asset"
$Temp = Join-Path ([IO.Path]::GetTempPath()) ("zeno-agent-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $Temp | Out-Null
try {
  $Archive = Join-Path $Temp $Asset
  Write-Host "下载 Zeno Agent $Version (windows/$GoArch)..."
  Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $Archive
  Expand-Archive -Force -Path $Archive -DestinationPath $Temp
  $Found = Get-ChildItem -Path $Temp -Recurse -Filter 'zeno-agent.exe' | Select-Object -First 1
  if (-not $Found) { Fail '压缩包内未找到 zeno-agent.exe' }

  $Existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
  if ($Existing) {
    Stop-Service -Name $ServiceName -ErrorAction SilentlyContinue
    & sc.exe delete $ServiceName | Out-Null
    for ($i = 0; $i -lt 20; $i++) {
      Start-Sleep -Milliseconds 500
      if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) { break }
    }
    if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) { Fail '旧 zeno-agent 服务删除超时' }
  }

  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Bin), (Split-Path -Parent $TokenFile) | Out-Null
  Copy-Item -Force -Path $Found.FullName -Destination $Bin
  if ($Token) {
    Set-Content -Path $TokenFile -Value $Token -Encoding ASCII
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
  $QuotedArgs = $Args | ForEach-Object { '"' + ($_ -replace '"', '\"') + '"' }
  $BinPath = '"' + $Bin + '" ' + ($QuotedArgs -join ' ')
  New-Service -Name $ServiceName -BinaryPathName $BinPath -DisplayName 'Zeno Agent' -StartupType Automatic | Out-Null
  if (-not (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue)) { Fail 'Zeno Agent 服务创建失败' }
  & sc.exe failure $ServiceName reset= 60 actions= restart/5000/restart/5000/restart/5000 | Out-Null
  Start-Service -Name $ServiceName
  $Started = Get-Service -Name $ServiceName
  if ($Started.Status -ne 'Running') { Fail 'Zeno Agent 服务未启动' }
  Write-Host "Zeno Agent 已安装并启动: node=$NodeID version=$Version"
} finally {
  Remove-Item -Recurse -Force -Path $Temp -ErrorAction SilentlyContinue
}
