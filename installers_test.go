package zenoagent_test

import (
	"os"
	"os/exec"
	"strings"
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
		"restore_file_backup_atomic",
		".${dest_base}.restore.$$",
		"sha256_file \"$backup\"",
		"stop_linux_service_for_restore",
		"reject_symlink_path \"$TOKEN_FILE\" \"token 文件\"",
		"token_owner_group()",
		"root:root",
		"root:wheel",
		"set_token_owner_mode \"$tmp_token\"",
		"assert_token_file_secure",
		".agent-token.backup.",
		"restore_token_backup",
		"service_config_backup",
		"service_was_enabled",
		"service_was_active",
		"if [ \"$service_was_active\" -eq 1 ]; then",
		"$dest.bak-$(date -u +%Y%m%d%H%M%S)",
		"chown root:root \"$unit\"",
		"chown root:wheel \"$plist\"",
		"plutil -lint \"$plist_tmp\"",
		"NoNewPrivileges=true",
		"ProtectSystem=full",
		"ProtectHome=read-only",
		"ProtectKernelTunables=true",
		"PrivateDevices=true",
		"CapabilityBoundingSet=CAP_NET_RAW",
		"AmbientCapabilities=CAP_NET_RAW",
		"RestrictNamespaces=true",
		"MemoryDenyWriteExecute=true",
		"ProcessType</key><string>Background",
		"<key>Umask</key><integer>63</integer>",
		"validate_controller_url",
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
		extractShellFunction(t, script, "is_ipv4_mapped_hex_loopback") + "\n" +
		extractShellFunction(t, script, "is_ipv4_mapped_loopback") + "\n" +
		extractShellFunction(t, script, "controller_url_host") + "\n" +
		extractShellFunction(t, script, "controller_url_has_explicit_port") + "\n" +
		extractShellFunction(t, script, "validate_controller_url") + "\n"
	for _, value := range []string{"https://zeno.example.com", "http://localhost:18980", "http://localhost.:18980", "http://127.0.0.1:18980", "http://127.0.0.2:18980", "http://127.255.255.255:18980", "http://203.0.113.10:18980", "http://[::1]:18980", "http://[::ffff:127.0.0.1]:18980", "http://[::ffff:7f00:1]:18980", "http://[::ffff:192.168.1.1]:18980", "http://[::ffff:8000:1]:18980", "http://[2001:db8::10]:18980"} {
		cmd := exec.Command("bash", "-c", fragment+"validate_controller_url \"$1\"", "bash", value)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("validate_controller_url rejected %q: %v\n%s", value, err, out)
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
		"sc.exe privs $ServiceName SeChangeNotifyPrivilege",
		"拒绝覆盖现有二进制",
		"原备份仍保留在",
		"token 文件恢复失败，备份仍保留在",
		"Assert-ControllerURL",
		"远程 ZENO_CONTROLLER_URL 必须使用 https",
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
