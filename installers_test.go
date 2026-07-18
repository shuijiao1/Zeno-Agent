package zenoagent_test

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

func TestUnixInstallerEnforcesChecksumsAtomicReplaceAndSystemdQuoting(t *testing.T) {
	content, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatalf("read install.sh: %v", err)
	}
	script := string(content)
	for _, want := range []string{
		"download_file \"$SUMS_URL\" \"$TMP/SHA256SUMS\"",
		"verify_asset_checksum \"$ASSET\" \"$TMP/$ASSET\" \"$TMP/SHA256SUMS\"",
		"systemd_escape_arg()",
		"value=${value//\\$/\\$\\$}",
		"ExecStart=$exec_start",
		"atomic_install_binary",
		"restore_binary_backup",
		"rotate_binary_backups",
		"restore_file_backup_atomic",
		".${dest_base}.restore.$$",
		"sha256_file \"$backup\"",
		"stop_linux_service_for_restore",
		"reject_symlink_path \"$TOKEN_FILE\" \"token 文件\"",
		"token_owner_group()",
		"ensure_linux_service_account()",
		"ensure_macos_service_account()",
		"validate_macos_service_account()",
		"find_available_macos_system_id()",
		`SERVICE_USER="_zeno-agent"`,
		`SERVICE_GROUP="_zeno-agent"`,
		`dscl . -create "$user_record"`,
		`dscl . -delete "/Users/$SERVICE_USER"`,
		`darwin|linux) printf '0:%s:640'`,
		`<key>UserName</key><string>$(xml_escape "$SERVICE_USER")</string>`,
		"prepare_macos_service",
		"restore_token_metadata_from_backup",
		"useradd --system --user-group --no-create-home",
		"service_account_created=1",
		"remove_created_linux_service_account",
		`userdel "$SERVICE_USER"`,
		`groupdel "$SERVICE_GROUP"`,
		"root:%s",
		"root:wheel",
		"set_token_owner_mode \"$tmp_token\"",
		"assert_token_file_secure",
		".agent-token.backup.",
		"restore_token_backup",
		"service_config_backup",
		"service_was_enabled",
		"service_was_active",
		"if [ \"$service_was_active\" -eq 1 ]; then",
		"$dest.bak-$(date -u +%Y%m%d%H%M%S)-$$",
		"chown root:root \"$unit\"",
		"chown root:wheel \"$plist_tmp\"",
		"plutil -lint \"$plist_tmp\"",
		"NoNewPrivileges=true",
		"User=$SERVICE_USER",
		"Group=$SERVICE_GROUP",
		"ProtectSystem=full",
		"ProtectHome=read-only",
		"ProtectKernelTunables=true",
		"PrivateDevices=true",
		"CapabilityBoundingSet=CAP_NET_RAW",
		"AmbientCapabilities=CAP_NET_RAW",
		"RestrictNamespaces=true",
		"RestrictSUIDSGID=true",
		"MemoryDenyWriteExecute=true",
		"KillSignal=SIGTERM",
		"KillMode=control-group",
		"TimeoutStopSec=30s",
		"SendSIGKILL=yes",
		"ProcessType</key><string>Background",
		"<key>ExitTimeOut</key><integer>30</integer>",
		"<key>Umask</key><integer>63</integer>",
		"StateDirectory=zeno-agent",
		"StateDirectoryMode=0700",
		`AGENT_DATA_DIR="/var/lib/zeno-agent"`,
		`AGENT_DATA_DIR="/Library/Application Support/Zeno Agent/data"`,
		`-data-dir "$AGENT_DATA_DIR"`,
		`<string>-data-dir</string><string>$(xml_escape "$AGENT_DATA_DIR")</string>`,
		"run_agent_install_check",
		"-install-check",
		"prepare_macos_logging",
		"install_macos_logging",
		"restore_macos_logging",
		"# Managed by Zeno Agent installer",
		"newsyslog -n -f",
		"-log-file</string><string>$(xml_escape \"$MACOS_LOG_FILE\")",
		"validate_controller_url",
		"insecure_args=(-allow-insecure-http)",
		"<string>-allow-insecure-http</string>",
		"远程 ZENO_CONTROLLER_URL 必须使用 https",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("install.sh missing %q", want)
		}
	}
	if strings.Contains(script, "ExecStart=$BIN -controller-url") {
		t.Fatalf("install.sh still writes an unescaped systemd ExecStart")
	}
	if strings.Contains(script, "restore_binary_backup \"$backup_bin\" \"$BIN\" || true") {
		t.Fatalf("install.sh still swallows binary restore failures")
	}
	if strings.Contains(script, "cp -p \"$backup_token\" \"$TOKEN_FILE\" 2>/dev/null || true") {
		t.Fatalf("install.sh still swallows token restore failures")
	}
	if strings.Contains(script, "cp -p \"$service_config_backup\" \"$service_config\" 2>/dev/null") {
		t.Fatalf("install.sh still restores service config non-atomically")
	}
	if strings.Contains(script, "[ \"$service_config_existed\" -eq 1 ] && [ \"$service_was_active\" -eq 1 ]") {
		t.Fatalf("install.sh still gates active-state restoration on /etc unit existence")
	}
	if strings.Contains(script, "ExecStop=") {
		t.Fatalf("install.sh adds a redundant ExecStop instead of using systemd native SIGTERM handling")
	}
	if strings.Contains(script, "<key>StandardOutPath</key>") || strings.Contains(script, "<key>StandardErrorPath</key>") {
		t.Fatalf("macOS service still relies on non-reopenable launchd stdout/stderr log descriptors")
	}
}

func TestElevatedInstallCheckRunsBeforeServiceMutationAndNeverPersists(t *testing.T) {
	unixBytes, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	unix := string(unixBytes)
	transaction := strings.LastIndex(unix, `if [ -n "$ENROLLMENT_TOKEN" ]; then`)
	if transaction < 0 {
		t.Fatal("Unix enrollment transaction missing")
	}
	unixMain := unix[transaction:]
	atomicInstall := strings.Index(unixMain, `atomic_install_binary "$FOUND" "$BIN" backup_bin`)
	check := strings.Index(unixMain, "run_agent_install_check")
	linuxMutation := strings.Index(unixMain, "install_linux_service")
	macMutation := strings.Index(unixMain, "install_macos_service")
	commit := strings.Index(unixMain, "install_committed=1")
	if atomicInstall < 0 || check < 0 || linuxMutation < 0 || macMutation < 0 || commit < 0 ||
		!(atomicInstall < check && check < linuxMutation && linuxMutation < commit && check < macMutation && macMutation < commit) {
		t.Fatalf("Unix install-check ordering is not transactional")
	}
	checkFunction := extractShellFunction(t, unix, "run_agent_install_check")
	if !strings.Contains(checkFunction, `-token-file "$TOKEN_FILE"`) || strings.Contains(checkFunction, `-token "$TOKEN"`) {
		t.Fatal("Unix install check must use token-file and never put the token in argv")
	}
	linuxService := extractShellFunction(t, unix, "install_linux_service")
	macService := extractShellFunction(t, unix, "install_macos_service")
	if strings.Contains(linuxService, "-install-check") || strings.Contains(macService, "-install-check") {
		t.Fatal("Unix service configuration persisted the one-shot install-check flag")
	}

	windowsBytes, err := os.ReadFile("install.ps1")
	if err != nil {
		t.Fatal(err)
	}
	windows := string(windowsBytes)
	exchange := strings.Index(windows, "Invoke-AgentEnrollment -RuntimeToken $Token")
	check = strings.Index(windows, "$CheckArgs = @($Args) + @('-install-check')")
	mutation := strings.Index(windows, "$BinPath = Join-WindowsCommandLine")
	commit = strings.Index(windows, "$InstallSucceeded = $true")
	if exchange < 0 || check < 0 || mutation < 0 || commit < 0 || !(exchange < check && check < mutation && mutation < commit) {
		t.Fatal("Windows install-check ordering is not transactional")
	}
	if !strings.Contains(windows, "& $Bin @CheckArgs") {
		t.Fatal("Windows install check does not use a PowerShell argument array")
	}
}

func TestInstallersRequireRealServiceReceiptBeforeCommit(t *testing.T) {
	unixBytes, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	unix := string(unixBytes)
	mainStart := strings.LastIndex(unix, `atomic_install_binary "$FOUND" "$BIN" backup_bin`)
	if mainStart < 0 {
		t.Fatal("Unix installer transaction missing")
	}
	main := unix[mainStart:]
	service := strings.Index(main, "install_linux_service")
	receipt := strings.Index(main, "wait_for_service_install_receipt")
	commit := strings.Index(main, "install_committed=1")
	if service < 0 || receipt < 0 || commit < 0 || !(service < receipt && receipt < commit) {
		t.Fatal("Unix installer commits before the real service receipt is verified")
	}
	wait := extractShellFunction(t, unix, "wait_for_service_install_receipt")
	for _, want := range []string{
		`file_owner_mode "$receipt"`,
		`systemctl show --property=MainPID`,
		`"/proc/$pid/status"`,
		`launchctl print system/li.shuijiao.zeno-agent`,
		`ps -o uid= -p "$pid"`,
		`$INSTALL_RECEIPT_PREFIX $install_receipt_nonce`,
	} {
		if !strings.Contains(wait, want) {
			t.Fatalf("Unix service receipt verification missing %q", want)
		}
	}
	if !strings.Contains(extractShellFunction(t, unix, "install_linux_service"), `-install-receipt-file "$install_receipt_file"`) ||
		!strings.Contains(extractShellFunction(t, unix, "install_macos_service"), `-install-receipt-file</string>`) {
		t.Fatal("Unix native services do not receive the non-secret receipt challenge")
	}

	windowsBytes, err := os.ReadFile("install.ps1")
	if err != nil {
		t.Fatal(err)
	}
	windows := string(windowsBytes)
	start := strings.Index(windows, "Start-Service -Name $ServiceName")
	receipt = strings.Index(windows, "Wait-ServiceInstallReceipt -Name $ServiceName")
	commit = strings.Index(windows, "$InstallSucceeded = $true")
	if start < 0 || receipt < 0 || commit < 0 || !(start < receipt && receipt < commit) {
		t.Fatal("Windows installer commits before the SCM service receipt is verified")
	}
	for _, want := range []string{
		"Win32_Service",
		"Win32_Process",
		"GetOwner",
		"Convert-ToSidString $ExpectedAccount",
		`$DataDir = Join-Path $env:ProgramData 'Zeno\agent-data'`,
		"Set-ServiceDataDirectoryAcl -Path $DataDir",
		"(Get-Acl -LiteralPath $Path).Owner",
		"-install-receipt-file",
		"-install-receipt-nonce",
	} {
		if !strings.Contains(windows, want) {
			t.Fatalf("Windows SCM receipt verification missing %q", want)
		}
	}
	if strings.Contains(wait, "TOKEN") || strings.Contains(wait, "token") {
		t.Fatal("Unix receipt verification references credential material")
	}
}

func TestNativeServiceReceiptHarnessesArePlatformSpecific(t *testing.T) {
	for _, fixture := range []struct {
		path string
		want []string
	}{
		{path: "scripts/test-linux-install-receipt.sh", want: []string{"systemctl start", "User=nobody", "MainPID"}},
		{path: "scripts/test-macos-install-receipt.sh", want: []string{"launchctl bootstrap", "<key>UserName</key><string>_nobody</string>", "ps -o uid="}},
		{path: "scripts/test-windows-install-receipt.ps1", want: []string{"New-Service", `NT SERVICE\$name`, "Win32_Service", "Set-ServiceDataDirectoryAcl", "-data-dir", "ChangePermissions", "administrator-owned data-directory upgrade receipt verified"}},
	} {
		content, err := os.ReadFile(fixture.path)
		if err != nil {
			t.Fatalf("read %s: %v", fixture.path, err)
		}
		for _, want := range fixture.want {
			if !strings.Contains(string(content), want) {
				t.Fatalf("%s missing native identity check %q", fixture.path, want)
			}
		}
	}
}

func TestWindowsDataDirectoryAclGrantsChangePermissionsWithoutTakeOwnership(t *testing.T) {
	scriptBytes, err := os.ReadFile("install.ps1")
	if err != nil {
		t.Fatalf("read install.ps1: %v", err)
	}
	function := extractPowerShellFunction(t, string(scriptBytes), "Set-ServiceDataDirectoryAcl")
	for _, want := range []string{
		"SetAccessRuleProtection($true, $false)",
		"SetOwner((New-Object Security.Principal.NTAccount('BUILTIN\\Administrators')))",
		"[Security.AccessControl.FileSystemRights]::Modify -bor [Security.AccessControl.FileSystemRights]::ChangePermissions",
		"[Security.AccessControl.FileSystemRights]::FullControl",
	} {
		if !strings.Contains(function, want) {
			t.Fatalf("Windows data-directory ACL missing %q", want)
		}
	}
	if strings.Contains(function, "TakeOwnership") {
		t.Fatal("Windows data-directory ACL unnecessarily grants TakeOwnership to the service account")
	}

	workflowBytes, err := os.ReadFile(".github/workflows/ci.yml")
	if err != nil {
		t.Fatalf("read CI workflow: %v", err)
	}
	workflow := string(workflowBytes)
	if !strings.Contains(workflow, "./scripts/test-windows-install-receipt.ps1") ||
		!strings.Contains(workflow, "ZENO_REQUIRE_WINDOWS_SERVICE_TEST: '1'") {
		t.Fatal("native Windows CI does not require the real data-directory service receipt harness")
	}
}

func TestMacOSExistingServiceAccountMustBePrivateNoLoginSystemAccount(t *testing.T) {
	content, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatalf("read install.sh: %v", err)
	}
	script := string(content)
	base := extractShellFunction(t, script, "fail") + "\n" +
		extractShellFunction(t, script, "darwin_scalar_attribute") + "\n" +
		extractShellFunction(t, script, "darwin_attribute_values") + "\n" +
		extractShellFunction(t, script, "validate_macos_service_account") + "\n" +
		`GOOS=darwin
SERVICE_USER=_zeno-agent
SERVICE_GROUP=_zeno-agent
dscl() {
  [ "$1" = . ] || return 2
  shift
  if [ "$1" = -read ]; then
    local record="$2" attribute="${3-}"
    case "$record:$attribute" in
      /Users/_zeno-agent:) return 0 ;;
      /Groups/_zeno-agent:) return 0 ;;
      /Users/_zeno-agent:UniqueID) printf 'UniqueID: 499\n' ;;
      /Users/_zeno-agent:PrimaryGroupID) printf 'PrimaryGroupID: 499\n' ;;
      /Users/_zeno-agent:NFSHomeDirectory) printf 'NFSHomeDirectory: /var/empty\n' ;;
      /Users/_zeno-agent:UserShell) printf 'UserShell: %s\n' "$MOCK_SHELL" ;;
      /Users/_zeno-agent:Password) printf 'Password: ********\n' ;;
      /Groups/_zeno-agent:PrimaryGroupID) printf 'PrimaryGroupID: 499\n' ;;
      /Groups/_zeno-agent:GroupMembership)
        [ -n "$MOCK_MEMBER" ] || return 1
        printf 'GroupMembership: %s\n' "$MOCK_MEMBER"
        ;;
      /Groups/_zeno-agent:GroupMembers) return 1 ;;
      *) return 2 ;;
    esac
    return 0
  fi
  if [ "$1" = -list ] && [ "$2:$3" = /Users:UniqueID ]; then
    printf 'root 0\n_zeno-agent 499\n'
    return 0
  fi
  if [ "$1" = -list ] && [ "$2:$3" = /Users:PrimaryGroupID ]; then
    printf 'root 0\n_zeno-agent 499\n'
    return 0
  fi
  if [ "$1" = -list ] && [ "$2:$3" = /Groups:PrimaryGroupID ]; then
    printf 'wheel 0\n_zeno-agent 499\n'
    return 0
  fi
  return 2
}

validate_macos_service_account
`

	for _, tc := range []struct {
		name      string
		shell     string
		member    string
		wantError bool
	}{
		{name: "private no-login account", shell: "/usr/bin/false"},
		{name: "interactive shell", shell: "/bin/zsh", wantError: true},
		{name: "foreign group member", shell: "/usr/bin/false", member: "other", wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command("bash", "-c", base)
			cmd.Env = append(os.Environ(), "MOCK_SHELL="+tc.shell, "MOCK_MEMBER="+tc.member)
			out, err := cmd.CombinedOutput()
			if tc.wantError && err == nil {
				t.Fatalf("unsafe macOS service account was accepted: %s", out)
			}
			if !tc.wantError && err != nil {
				t.Fatalf("safe macOS service account rejected: %v\n%s", err, out)
			}
		})
	}
}

func TestMacOSNewsyslogConfigRefusesUnmanagedCollision(t *testing.T) {
	content, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(content)
	fragment := extractShellFunction(t, script, "fail") + "\n" +
		extractShellFunction(t, script, "reject_symlink_path") + "\n" +
		extractShellFunction(t, script, "assert_regular_file_or_absent") + "\n" +
		extractShellFunction(t, script, "file_owner_mode") + "\n" +
		extractShellFunction(t, script, "prepare_macos_logging") + "\n" +
		`MACOS_LOG_FILE="$1/zeno-agent.log"
MACOS_NEWSYSLOG_CONFIG="$1/zeno-agent.conf"
MACOS_NEWSYSLOG_MARKER="# Managed by Zeno Agent installer"
TMP="$1/tmp"
mkdir -p "$TMP"
macos_newsyslog_config_existed=0
macos_newsyslog_config_backup=""
macos_log_existed=0
macos_log_old_metadata=""
prepare_macos_logging
`

	for _, tc := range []struct {
		name      string
		config    string
		wantError bool
	}{
		{name: "managed", config: "# Managed by Zeno Agent installer\n/var/log/zeno-agent.log _zeno-agent:_zeno-agent 600 7 1024 * N\n"},
		{name: "unmanaged", config: "/var/log/zeno-agent.log root:wheel 600 3 1024 * N\n", wantError: true},
		{name: "marker not first", config: "/var/log/custom.log root:wheel 600 3 1024 * N\n# Managed by Zeno Agent installer\n", wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(dir+"/zeno-agent.conf", []byte(tc.config), 0o644); err != nil {
				t.Fatal(err)
			}
			out, err := exec.Command("bash", "-c", fragment, "bash", dir).CombinedOutput()
			if tc.wantError && err == nil {
				t.Fatalf("unmanaged config was accepted: %s", out)
			}
			if !tc.wantError && err != nil {
				t.Fatalf("managed config was rejected: %v\n%s", err, out)
			}
			if tc.wantError {
				got, readErr := os.ReadFile(dir + "/zeno-agent.conf")
				if readErr != nil || string(got) != tc.config {
					t.Fatalf("unmanaged config was modified: %q, %v", got, readErr)
				}
			}
		})
	}
}

func TestMacOSLoggingRollbackRestoresConfigWithoutOverwritingLog(t *testing.T) {
	content, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatal(err)
	}
	script := string(content)
	dir := t.TempDir()
	config := dir + "/zeno-agent.conf"
	backup := dir + "/zeno-agent.conf.backup"
	logPath := dir + "/zeno-agent.log"
	oldConfig := "# Managed by Zeno Agent installer\nold policy\n"
	if err := os.WriteFile(backup, []byte(oldConfig), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, []byte("new policy\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logPath, []byte("existing log\nnew install log\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	stat := info.Sys().(*syscall.Stat_t)
	metadata := fmt.Sprintf("%d:%d:600", stat.Uid, stat.Gid)
	fragment := extractShellFunction(t, script, "fail") + "\n" +
		extractShellFunction(t, script, "restore_file_backup_atomic") + "\n" +
		extractShellFunction(t, script, "file_owner_mode") + "\n" +
		extractShellFunction(t, script, "restore_macos_logging") + "\n" +
		`chown() { :; }
GOOS=linux
MACOS_NEWSYSLOG_CONFIG="$1"
macos_newsyslog_config_backup="$2"
MACOS_LOG_FILE="$3"
macos_log_old_metadata="$4"
macos_logging_installed=1
macos_newsyslog_config_existed=1
macos_log_created=0
macos_log_existed=1
restore_macos_logging
`
	if out, err := exec.Command("bash", "-c", fragment, "bash", config, backup, logPath, metadata).CombinedOutput(); err != nil {
		t.Fatalf("restore_macos_logging: %v\n%s", err, out)
	}
	gotConfig, err := os.ReadFile(config)
	if err != nil || string(gotConfig) != oldConfig {
		t.Fatalf("restored config = %q, %v", gotConfig, err)
	}
	gotLog, err := os.ReadFile(logPath)
	if err != nil || string(gotLog) != "existing log\nnew install log\n" {
		t.Fatalf("rollback overwrote existing log = %q, %v", gotLog, err)
	}
}

func TestUnixSystemdEscapeBehavior(t *testing.T) {
	content, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatalf("read install.sh: %v", err)
	}
	script := string(content)
	fragment := extractShellFunction(t, script, "fail") + "\n" +
		extractShellFunction(t, script, "reject_systemd_arg") + "\n" +
		extractShellFunction(t, script, "systemd_escape_arg") + "\n" +
		extractShellFunction(t, script, "systemd_join_args") + "\n" +
		"systemd_join_args '/usr/local/bin/zeno-agent' '-token' 'abc$HOME%x\\\"z'\n"
	cmd := exec.Command("bash", "-c", fragment)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("systemd_join_args failed: %v\n%s", err, out)
	}
	got := string(out)
	for _, want := range []string{
		`"/usr/local/bin/zeno-agent"`,
		`"-token"`,
		`abc$$HOME%%x\\\"z`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("escaped ExecStart args %q missing %q", got, want)
		}
	}

	cmd = exec.Command("bash", "-c", fragment+"systemd_join_args $'bad\\narg'\n")
	if err := cmd.Run(); err == nil {
		t.Fatalf("systemd_join_args accepted an argument containing a newline")
	}
}

func TestUnixBinaryBackupRotationKeepsNewestThree(t *testing.T) {
	content, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatalf("read install.sh: %v", err)
	}
	dir := t.TempDir()
	destination := dir + "/zeno-agent"
	for _, suffix := range []string{"20260101-1", "20260201-1", "20260301-1", "20260401-1", "20260501-1"} {
		if err := os.WriteFile(destination+".bak-"+suffix, []byte(suffix), 0o600); err != nil {
			t.Fatalf("write backup: %v", err)
		}
	}
	fragment := extractShellFunction(t, string(content), "rotate_binary_backups") + "\nrotate_binary_backups \"$1\"\n"
	if output, err := exec.Command("bash", "-c", fragment, "bash", destination).CombinedOutput(); err != nil {
		t.Fatalf("rotate_binary_backups: %v\n%s", err, output)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read backup directory: %v", err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	want := []string{"zeno-agent.bak-20260301-1", "zeno-agent.bak-20260401-1", "zeno-agent.bak-20260501-1"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("remaining backups = %v, want %v", names, want)
	}
}

func TestUnixTokenRollbackRestoresOriginalMetadata(t *testing.T) {
	content, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatalf("read install.sh: %v", err)
	}
	script := string(content)
	if strings.Contains(script, `set_token_owner_mode "$backup_token"`) {
		t.Fatal("token backup must retain the original owner and mode")
	}
	fragment := extractShellFunction(t, script, "fail") + "\n" +
		extractShellFunction(t, script, "reject_symlink_path") + "\n" +
		extractShellFunction(t, script, "restore_file_backup_atomic") + "\n" +
		extractShellFunction(t, script, "file_owner_mode") + "\n" +
		extractShellFunction(t, script, "restore_token_backup") + "\n" +
		"GOOS=linux\nbackup_token=\"$1\"\nTOKEN_FILE=\"$2\"\nrestore_token_backup\n"

	dir := t.TempDir()
	backup := dir + "/token.backup"
	token := dir + "/agent-token"
	if err := os.WriteFile(backup, []byte("old-token\n"), 0o600); err != nil {
		t.Fatalf("write backup: %v", err)
	}
	if err := os.WriteFile(token, []byte("new-token\n"), 0o640); err != nil {
		t.Fatalf("write token: %v", err)
	}
	backupInfo, err := os.Stat(backup)
	if err != nil {
		t.Fatalf("stat backup: %v", err)
	}
	backupStat := backupInfo.Sys().(*syscall.Stat_t)
	if out, err := exec.Command("bash", "-c", fragment, "bash", backup, token).CombinedOutput(); err != nil {
		t.Fatalf("restore_token_backup: %v\n%s", err, out)
	}
	info, err := os.Stat(token)
	if err != nil {
		t.Fatalf("stat restored token: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("restored token mode = %04o, want original 0600", got)
	}
	restoredStat := info.Sys().(*syscall.Stat_t)
	if restoredStat.Uid != backupStat.Uid || restoredStat.Gid != backupStat.Gid {
		t.Fatalf("restored token owner = %d:%d, want original %d:%d", restoredStat.Uid, restoredStat.Gid, backupStat.Uid, backupStat.Gid)
	}
	if data, err := os.ReadFile(token); err != nil || string(data) != "old-token\n" {
		t.Fatalf("restored token = %q, %v", data, err)
	}
}

func TestUnixExistingServiceAccountMustBePrivateSystemAccount(t *testing.T) {
	content, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatalf("read install.sh: %v", err)
	}
	script := string(content)
	base := extractShellFunction(t, script, "fail") + "\n" +
		extractShellFunction(t, script, "ensure_linux_service_account") + "\n" +
		"GOOS=linux\nSERVICE_USER=zeno-agent\nSERVICE_GROUP=zeno-agent\nservice_account_created=0\n"

	tests := []struct {
		name      string
		passwd    string
		allUsers  string
		group     string
		allGroups string
		wantError bool
	}{
		{
			name:      "private system account",
			passwd:    "zeno-agent:x:995:995::/nonexistent:/usr/sbin/nologin",
			allUsers:  "root:x:0:0::/root:/bin/bash\nzeno-agent:x:995:995::/nonexistent:/usr/sbin/nologin",
			group:     "zeno-agent:x:995:",
			allGroups: "root:x:0:\nzeno-agent:x:995:",
		},
		{
			name:      "interactive ordinary account",
			passwd:    "zeno-agent:x:1000:1000::/home/zeno-agent:/bin/bash",
			allUsers:  "zeno-agent:x:1000:1000::/home/zeno-agent:/bin/bash",
			group:     "zeno-agent:x:1000:",
			allGroups: "zeno-agent:x:1000:",
			wantError: true,
		},
		{
			name:      "shared primary group",
			passwd:    "zeno-agent:x:995:995::/nonexistent:/usr/sbin/nologin",
			allUsers:  "zeno-agent:x:995:995::/nonexistent:/usr/sbin/nologin\nother:x:996:995::/nonexistent:/usr/sbin/nologin",
			group:     "zeno-agent:x:995:",
			allGroups: "zeno-agent:x:995:",
			wantError: true,
		},
		{
			name:      "supplementary group member",
			passwd:    "zeno-agent:x:995:995::/nonexistent:/usr/sbin/nologin",
			allUsers:  "zeno-agent:x:995:995::/nonexistent:/usr/sbin/nologin\nother:x:996:996::/nonexistent:/usr/sbin/nologin",
			group:     "zeno-agent:x:995:other",
			allGroups: "zeno-agent:x:995:other",
			wantError: true,
		},
		{
			name:      "duplicate numeric gid",
			passwd:    "zeno-agent:x:995:995::/nonexistent:/usr/sbin/nologin",
			allUsers:  "zeno-agent:x:995:995::/nonexistent:/usr/sbin/nologin",
			group:     "zeno-agent:x:995:",
			allGroups: "zeno-agent:x:995:\nalias:x:995:other",
			wantError: true,
		},
		{
			name:      "duplicate same-name passwd records",
			passwd:    "zeno-agent:x:995:995::/nonexistent:/usr/sbin/nologin",
			allUsers:  "zeno-agent:x:995:995::/nonexistent:/usr/sbin/nologin\nzeno-agent:x:1000:1000::/home/zeno-agent:/bin/bash",
			group:     "zeno-agent:x:995:",
			allGroups: "zeno-agent:x:995:",
			wantError: true,
		},
		{
			name:      "duplicate same-name group records",
			passwd:    "zeno-agent:x:995:995::/nonexistent:/usr/sbin/nologin",
			allUsers:  "zeno-agent:x:995:995::/nonexistent:/usr/sbin/nologin",
			group:     "zeno-agent:x:995:",
			allGroups: "zeno-agent:x:995:\nzeno-agent:x:996:other",
			wantError: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mock := `getent() {
  if [ "$1" = passwd ] && [ "${2-}" = zeno-agent ]; then printf '%s\n' "$MOCK_PASSWD"; return 0; fi
  if [ "$1" = passwd ] && [ -z "${2-}" ]; then printf '%s\n' "$MOCK_ALL_USERS"; return 0; fi
  if [ "$1" = group ] && [ "${2-}" = zeno-agent ]; then printf '%s\n' "$MOCK_GROUP"; return 0; fi
  if [ "$1" = group ] && [ -z "${2-}" ]; then printf '%s\n' "$MOCK_ALL_GROUPS"; return 0; fi
  return 2
}
ensure_linux_service_account
`
			cmd := exec.Command("bash", "-c", base+mock)
			cmd.Env = append(os.Environ(), "MOCK_PASSWD="+tc.passwd, "MOCK_ALL_USERS="+tc.allUsers, "MOCK_GROUP="+tc.group, "MOCK_ALL_GROUPS="+tc.allGroups)
			out, err := cmd.CombinedOutput()
			if tc.wantError && err == nil {
				t.Fatalf("unsafe existing account was accepted: %s", out)
			}
			if !tc.wantError && err != nil {
				t.Fatalf("safe service account rejected: %v\n%s", err, out)
			}
		})
	}
	ensureFunction := extractShellFunction(t, script, "ensure_linux_service_account")
	useraddIndex := strings.Index(ensureFunction, "if ! useradd ")
	createdIndex := strings.Index(ensureFunction, "service_account_created=1")
	if useraddIndex < 0 || createdIndex < 0 || createdIndex < useraddIndex {
		t.Fatal("service account cleanup marker must only be set after useradd succeeds")
	}
}

func TestUnixControllerURLValidation(t *testing.T) {
	content, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatalf("read install.sh: %v", err)
	}
	script := string(content)
	fragment := extractShellFunction(t, script, "fail") + "\n" +
		extractShellFunction(t, script, "is_decimal_octet") + "\n" +
		extractShellFunction(t, script, "is_ipv4_loopback") + "\n" +
		extractShellFunction(t, script, "is_ipv4_literal") + "\n" +
		extractShellFunction(t, script, "is_hex16") + "\n" +
		extractShellFunction(t, script, "is_ipv6_literal") + "\n" +
		extractShellFunction(t, script, "is_ipv6_loopback") + "\n" +
		extractShellFunction(t, script, "is_ipv4_mapped_hex_loopback") + "\n" +
		extractShellFunction(t, script, "is_ipv4_mapped_loopback") + "\n" +
		extractShellFunction(t, script, "controller_url_host") + "\n" +
		extractShellFunction(t, script, "controller_url_has_explicit_port") + "\n" +
		extractShellFunction(t, script, "validate_controller_url") + "\n"
	for _, value := range []string{"https://zeno.example.com", "http://localhost:18980", "http://localhost.:18980", "http://127.0.0.1:18980", "http://127.0.0.2:18980", "http://127.255.255.255:18980", "http://[::1]:18980", "http://[::ffff:127.0.0.1]:18980", "http://[::ffff:7f00:1]:18980"} {
		cmd := exec.Command("bash", "-c", "ALLOW_INSECURE_HTTP=0\n"+fragment+"validate_controller_url \"$1\" && [ \"$ALLOW_INSECURE_HTTP\" -eq 0 ]", "bash", value)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("validate_controller_url did not preserve secure default for %q: %v\n%s", value, err, out)
		}
	}
	for _, value := range []string{"http://203.0.113.10:80", "http://203.0.113.10:18980", "http://[::ffff:192.168.1.1]:18980", "http://[::ffff:8000:1]:18980", "http://[2001:db8::10]:18980"} {
		cmd := exec.Command("bash", "-c", "ALLOW_INSECURE_HTTP=0\nALLOW_INSECURE_HTTP_REQUESTED=1\n"+fragment+"validate_controller_url \"$1\" && [ \"$ALLOW_INSECURE_HTTP\" -eq 1 ]", "bash", value)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("validate_controller_url did not require explicit runtime opt-in for %q: %v\n%s", value, err, out)
		}
		cmd = exec.Command("bash", "-c", "ALLOW_INSECURE_HTTP=0\nALLOW_INSECURE_HTTP_REQUESTED=0\n"+fragment+"validate_controller_url \"$1\"", "bash", value)
		if out, err := cmd.CombinedOutput(); err == nil {
			t.Fatalf("validate_controller_url accepted plaintext remote URL without explicit installer opt-in for %q\n%s", value, out)
		}
	}
	for _, value := range []string{
		"http://zeno.example.com",
		"http://localhost.example.com",
		"http://user@localhost:18980",
		"http://127.evil.example",
		"http://127.0.0.1.evil.example",
		"http://127.0.0.256:18980",
		"http://203.0.113.10",
		"http://[2001:db8::10]",
		"http://[::1]evil:18980",
		"http://[not:ipv6]:18980",
		"http://[2001::db8::10]:18980",
		"https://user:pass@zeno.example.com",
		"https://zeno.example.com?token=secret",
		"https://zeno.example.com#fragment",
		"https://:443",
		"ftp://zeno.example.com",
	} {
		cmd := exec.Command("bash", "-c", fragment+"validate_controller_url \"$1\"", "bash", value)
		if err := cmd.Run(); err == nil {
			t.Fatalf("validate_controller_url accepted %q", value)
		}
	}
}

func TestWindowsInstallerEnforcesChecksumsStrictTokenAclAndRollback(t *testing.T) {
	content, err := os.ReadFile("install.ps1")
	if err != nil {
		t.Fatalf("read install.ps1: %v", err)
	}
	script := string(content)
	for _, want := range []string{
		"Assert-ArchiveChecksum",
		"Get-FileHash -Algorithm SHA256",
		"New-TokenBootstrapAcl",
		"Write-StrictTemporaryTokenFile",
		"Assert-TokenBootstrapAcl",
		"Move-TokenIntoPlaceAtomically",
		"Restore-TokenBackup",
		"Set-StrictTokenAcl",
		"Assert-StrictTokenAcl",
		"NT AUTHORITY\\SYSTEM",
		"BUILTIN\\Administrators",
		"NT SERVICE\\$ServiceName",
		"[System.Security.AccessControl.FileSystemRights]::Write",
		"[IO.File]::Replace($Source, $Destination",
		".agent-token.replace-backup-",
		"Set-ServiceBinaryPath",
		"$ServiceBinPathChanged",
		"Restore-PreviousBinary",
		"Remove-OldBinaryBackups",
		"Stop-ServiceAndWait",
		".agent-token.backup-",
		"Set-Acl -Path $Destination -AclObject $OldAcl",
		"$OldServiceStart",
		"$OldServiceSidType",
		"$OldServiceStartName",
		"$OldServiceRequiredPrivileges",
		"$ServiceAccountChanged",
		"$ServiceRequiredPrivilegesChanged",
		"Get-ServiceRegistryPolicy",
		"Set-ServiceLogonAccount",
		"Set-ServiceRequiredPrivileges",
		"Convert-ServiceStartPolicyToScValue",
		"Convert-ServiceSidTypeToScValue",
		"$OldServiceWasRunning",
		"ConvertTo-WindowsCommandLineArgument",
		"CommandLineToArgvW rules",
		"$RestoredPreviousBinary = Restore-PreviousBinary",
		"旧二进制已恢复并通过 SHA256 校验",
		"旧二进制恢复未通过校验",
		"$RecoveryBackupPath",
		"zeno-agent.exe.rollback-",
		"sc.exe sidtype",
		"$OldServiceStartName.Equals('LocalSystem'",
		`Set-ServiceLogonAccount -Name $ServiceName -AccountName "NT SERVICE\$ServiceName"`,
		"保留现有 zeno-agent 自定义服务账户",
		"旧服务账户恢复失败",
		"旧服务最小权限列表恢复失败",
		"拒绝覆盖现有二进制",
		"原备份仍保留在",
		"token 文件恢复失败，备份仍保留在",
		"Assert-ControllerURL",
		"远程 ZENO_CONTROLLER_URL 必须使用 https",
		"if ($AllowInsecureHTTP) { $Args += '-allow-insecure-http' }",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("install.ps1 missing %q", want)
		}
	}
	if strings.Contains(script, "Copy-Item -Force -Path $Found.FullName -Destination $Bin") {
		t.Fatalf("install.ps1 still overwrites the agent binary directly")
	}
	if strings.Contains(script, "Set-Content -Path $TokenTmp") {
		t.Fatalf("install.ps1 still writes token temp file before applying a strict ACL")
	}
	if strings.Contains(script, "Move-Item -Force -Path $TokenTmp -Destination $TokenFile") {
		t.Fatalf("install.ps1 still replaces the token without the atomic helper")
	}
	if strings.Contains(script, "$nullBackup") || strings.Contains(script, "[IO.File]::Replace($Source, $Destination, $null") {
		t.Fatalf("install.ps1 still passes a null backup path to File.Replace")
	}
	if !strings.Contains(script, "Set-TokenBootstrapAcl -Path $BackupToken") || !strings.Contains(script, "Assert-TokenBootstrapAcl -Path $BackupToken") {
		t.Fatalf("install.ps1 does not protect the token rollback backup with the bootstrap ACL")
	}
	if strings.Contains(script, "ZENO_AGENT_SERVICE_NAME") {
		t.Fatalf("install.ps1 exposes a custom service name that the Windows binary cannot register")
	}
}

func TestWindowsEnrollmentExchangeCommitsPendingTokenBeforeSCMChanges(t *testing.T) {
	scriptBytes, err := os.ReadFile("install.ps1")
	if err != nil {
		t.Fatalf("read install.ps1: %v", err)
	}
	script := string(scriptBytes)
	exchange := strings.Index(script, "Invoke-AgentEnrollment -RuntimeToken $Token")
	commit := strings.Index(script, "$EnrollmentTokenInstalled = $true")
	serviceChange := strings.Index(script, "$BinPath = Join-WindowsCommandLine")
	if exchange < 0 || commit < 0 || serviceChange < 0 {
		t.Fatalf("installer is missing enrollment persistence or SCM setup markers")
	}
	if !(exchange < commit && commit < serviceChange) {
		t.Fatalf("pending runtime token must be committed immediately after enrollment exchange and before SCM changes")
	}
}

func TestWindowsEnrollmentRetryReusesProtectedExistingRuntimeToken(t *testing.T) {
	scriptBytes, err := os.ReadFile("install.ps1")
	if err != nil {
		t.Fatalf("read install.ps1: %v", err)
	}
	script := string(scriptBytes)
	exchange := strings.Index(script, "Invoke-AgentEnrollment -RuntimeToken $Token")
	restore := strings.Index(script, "Restore-TokenBackup -Backup $BackupToken -Destination $TokenFile -OldAcl $OldTokenAcl")
	check := strings.Index(script, "$CheckArgs = @($Args) + @('-install-check')")
	if exchange < 0 || restore < 0 || check < 0 || !(exchange < restore && restore < check) {
		t.Fatal("Windows enrollment retry must restore the protected existing token before install-check")
	}
	for _, want := range []string{
		"$HadExistingToken -and $BackupToken",
		"$Token = $null",
		"$EnrollmentToken = $null",
		"将验证并复用现有 runtime token 继续升级",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("Windows enrollment retry missing %q", want)
		}
	}
}

func TestWindowsVirtualServiceAccountOmitsPasswordArgument(t *testing.T) {
	scriptBytes, err := os.ReadFile("install.ps1")
	if err != nil {
		t.Fatalf("read install.ps1: %v", err)
	}
	function := extractPowerShellFunction(t, string(scriptBytes), "Set-ServiceLogonAccount")
	for _, want := range []string{
		"$Name -notmatch '^[A-Za-z0-9_.-]+$'",
		`$virtualAccount = "NT SERVICE\$Name"`,
		"unsupported service account",
		"New-Object Diagnostics.ProcessStartInfo",
		"System32\\sc.exe",
		"[Diagnostics.Process]::Start($startInfo)",
		"$exitCode -eq 0",
	} {
		if !strings.Contains(function, want) {
			t.Fatalf("Windows service account migration missing %q", want)
		}
	}
	if strings.Contains(function, "& sc.exe config") {
		t.Fatal("Windows service account migration still invokes sc.exe directly through PowerShell 5.1")
	}
	if strings.Contains(function, `obj= "{1}" password=`) {
		t.Fatal("Windows virtual service-account migration must not pass a password argument")
	}
}

func TestWindowsInstallerKeepsServiceSIDAvailableDuringAccountMigrationAndRollback(t *testing.T) {
	scriptBytes, err := os.ReadFile("install.ps1")
	if err != nil {
		t.Fatalf("read install.ps1: %v", err)
	}
	script := string(scriptBytes)

	createdSID := strings.Index(script, "& sc.exe sidtype $ServiceName unrestricted")
	createdAccount := strings.Index(script, `Set-ServiceLogonAccount -Name $ServiceName -AccountName "NT SERVICE\$ServiceName"`)
	if createdSID < 0 || createdAccount < 0 || createdSID > createdAccount {
		t.Fatal("fresh Windows install must enable the service SID before assigning the virtual account")
	}

	existingSID := strings.Index(script, "if ($OldServiceSidType -eq 0) {")
	existingAccount := strings.Index(script, "if ($OldServiceStartName.Equals('LocalSystem'")
	if existingSID < 0 || existingAccount < 0 || existingSID > existingAccount {
		t.Fatal("Windows upgrade must enable the service SID before migrating LocalSystem")
	}

	rollbackAccount := strings.LastIndex(script, "if ($ServiceAccountChanged")
	rollbackSID := strings.LastIndex(script, "if ($ServiceSidTypeChanged")
	if rollbackAccount < 0 || rollbackSID < 0 || rollbackAccount > rollbackSID {
		t.Fatal("Windows rollback must restore LocalSystem before disabling the service SID")
	}
}

func extractPowerShellFunction(t *testing.T, script, name string) string {
	t.Helper()
	start := strings.Index(script, "function "+name+"(")
	if start < 0 {
		t.Fatalf("missing PowerShell function %s", name)
	}
	depth := 0
	seenBody := false
	for i := start; i < len(script); i++ {
		switch script[i] {
		case '{':
			depth++
			seenBody = true
		case '}':
			depth--
			if seenBody && depth == 0 {
				return script[start : i+1]
			}
		}
	}
	t.Fatalf("unterminated PowerShell function %s", name)
	return ""
}

func extractShellFunction(t *testing.T, script, name string) string {
	t.Helper()
	start := strings.Index(script, name+"() {")
	if start < 0 {
		t.Fatalf("missing shell function %s", name)
	}
	depth := 0
	for i := start; i < len(script); i++ {
		switch script[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return script[start : i+1]
			}
		}
	}
	t.Fatalf("unterminated shell function %s", name)
	return ""
}
