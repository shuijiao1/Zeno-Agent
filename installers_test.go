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
		"NoNewPrivileges=true",
		"ProtectSystem=full",
		"ProtectHome=read-only",
		"ProtectKernelTunables=true",
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
		"Restore-PreviousBinary",
		"Stop-ServiceAndWait",
		".agent-token.backup-",
		"Set-Acl -Path $Destination -AclObject $OldAcl",
		"$OldStartMode",
		"$OldServiceWasRunning",
		"ConvertTo-WindowsCommandLineArgument",
		"CommandLineToArgvW rules",
		"$RestoredPreviousBinary = Restore-PreviousBinary",
		"旧二进制已恢复并通过 SHA256 校验",
		"旧二进制恢复未通过校验",
		"$RecoveryBackupPath",
		"zeno-agent.exe.rollback-",
		"sc.exe sidtype",
		"拒绝覆盖现有二进制",
		"原备份仍保留在",
		"token 文件恢复失败，备份仍保留在",
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
