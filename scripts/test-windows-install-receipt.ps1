$ErrorActionPreference = 'Stop'
if (-not $IsWindows -and $PSVersionTable.PSEdition -ne 'Desktop') { Write-Host 'SKIP: Windows only'; exit 0 }
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Write-Host 'SKIP: requires Administrator'; exit 0 }
$repo = Split-Path -Parent $PSScriptRoot; Push-Location $repo
$name = 'zeno-agent'
if (Get-Service -Name $name -ErrorAction SilentlyContinue) { throw 'refusing to replace an existing production zeno-agent service' }
$tmp = Join-Path $env:ProgramData ("ZenoReceiptHarness-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force $tmp | Out-Null
$bin = Join-Path $tmp 'zeno-agent.exe'; $tokenFile = Join-Path $tmp 'token'; $receipt = Join-Path $tmp 'receipt'
$nonce = [Guid]::NewGuid().ToString('N') + [Guid]::NewGuid().ToString('N'); $fixtureToken = 'fixture-only-token'
$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0); $listener.Start(); $port = ([Net.IPEndPoint]$listener.LocalEndpoint).Port; $listener.Stop()
$job = $null; $created = $false
try {
  & go build -o $bin ./cmd/zeno-agent; if ($LASTEXITCODE -ne 0) { throw 'go build failed' }
  [IO.File]::WriteAllText($tokenFile, $fixtureToken + "`n")
  $job = Start-Job -ArgumentList $port,$fixtureToken -ScriptBlock {
    param($p,$tok); $h=[Net.HttpListener]::new(); $h.Prefixes.Add("http://127.0.0.1:$p/"); $h.Start()
    while ($true) { $c=$h.GetContext(); $ok=$c.Request.Headers['X-Node-ID'] -eq 'receipt-harness' -and $c.Request.Headers['Authorization'] -eq "Bearer $tok"; $c.Response.StatusCode=if($ok){204}else{401}; $c.Response.Close() }
  }
  Start-Sleep -Milliseconds 500
  $args = "-controller-url http://127.0.0.1:$port -node-id receipt-harness -token-file `"$tokenFile`" -state-interval 1s -heartbeat-interval 1s -install-receipt-file `"$receipt`" -install-receipt-nonce $nonce"
  New-Service -Name $name -BinaryPathName "`"$bin`" $args" -StartupType Manual | Out-Null; $created=$true
  & sc.exe sidtype $name unrestricted | Out-Null; if ($LASTEXITCODE -ne 0) { throw 'sidtype failed' }
  & sc.exe config $name obj= "NT SERVICE\$name" | Out-Null; if ($LASTEXITCODE -ne 0) { throw 'virtual account config failed' }
  & icacls.exe $tmp /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' "NT SERVICE\${name}:(OI)(CI)M" | Out-Null
  Start-Service $name
  for ($i=0; $i -lt 45 -and -not (Test-Path -LiteralPath $receipt -PathType Leaf); $i++) { Start-Sleep 1 }
  if ([IO.File]::ReadAllText($receipt).Trim() -ne "zeno-agent-install-receipt-v1 $nonce") { throw 'invalid receipt' }
  $expected=(New-Object Security.Principal.NTAccount("NT SERVICE\$name")).Translate([Security.Principal.SecurityIdentifier]).Value
  $owner=(New-Object Security.Principal.NTAccount((Get-Acl $receipt).Owner)).Translate([Security.Principal.SecurityIdentifier]).Value
  if ($owner -ne $expected) { throw 'receipt owner is not the virtual service account' }
  $svc=Get-CimInstance Win32_Service -Filter "Name='$name'"; if ($svc.State -ne 'Running' -or $svc.ProcessId -eq 0) { throw 'SCM process is not running' }
  Write-Host 'PASS: real Windows SCM virtual-account heartbeat/state receipt verified'
} finally {
  if ($created) { Stop-Service $name -ErrorAction SilentlyContinue; & sc.exe delete $name | Out-Null }
  if ($job) { Stop-Job $job -ErrorAction SilentlyContinue; Remove-Job $job -Force -ErrorAction SilentlyContinue }
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue; Pop-Location
}
