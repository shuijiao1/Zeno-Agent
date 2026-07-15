package zenoagent_test

import (
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
		"chown root:wheel \"$plist\"",
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
		"ProcessType</key><string>Background",
		"<key>Umask</key><integer>63</integer>",
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
		cmd := exec.Command("bash", "-c", "ALLOW_INSECURE_HTTP=0\n"+fragment+"validate_controller_url \"$1\" && [ \"$ALLOW_INSECURE_HTTP\" -eq 1 ]", "bash", value)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("validate_controller_url did not require explicit runtime opt-in for %q: %v\n%s", value, err, out)
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
		"Get-ServiceRegistryPolicy",
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
		"sc.exe config $ServiceName obj= \"NT SERVICE\\$ServiceName\"",
		"sc.exe privs $ServiceName SeChangeNotifyPrivilege",
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
