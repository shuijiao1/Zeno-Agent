package zenoagent_test

import (
	"os"
	"strings"
	"testing"
)

func TestReleaseUsesArmV6CompatibleSingleLinuxArmAsset(t *testing.T) {
	workflowBytes, err := os.ReadFile(".github/workflows/release.yml")
	if err != nil {
		t.Fatalf("read release workflow: %v", err)
	}
	workflow := string(workflowBytes)
	for _, want := range []string{
		"linux/arm",
		`if [ "$goarch" = "arm" ]; then`,
		`GOARCH="$goarch" GOARM=6 go build`,
		`out_dir="dist/zeno-agent_${goos}_${goarch}"`,
	} {
		if !strings.Contains(workflow, want) {
			t.Fatalf("release workflow missing ARM artifact contract %q", want)
		}
	}
	if strings.Contains(workflow, "GOARM=7") {
		t.Fatal("single linux_arm release asset must not be ARMv7-only")
	}

	installerBytes, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatalf("read Unix installer: %v", err)
	}
	if !strings.Contains(string(installerBytes), "armv7l|armv6l) GOARCH=arm") {
		t.Fatal("installer no longer maps both armv6l/armv7l to the compatible linux_arm asset")
	}
}

func TestReleaseProvenanceAssetMatchesInstallers(t *testing.T) {
	const bundleName = "zeno-agent_provenance.sigstore.json"
	for _, path := range []string{".github/workflows/release.yml", "install.sh", "install.ps1"} {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if !strings.Contains(string(content), bundleName) {
			t.Fatalf("%s does not use provenance asset %q", path, bundleName)
		}
	}

	workflowBytes, err := os.ReadFile(".github/workflows/release.yml")
	if err != nil {
		t.Fatalf("read release workflow: %v", err)
	}
	workflow := string(workflowBytes)
	for _, want := range []string{
		"id: provenance",
		"subject-checksums: dist/SHA256SUMS",
		`cp "${{ steps.provenance.outputs.bundle-path }}" dist/` + bundleName,
		"dist/" + bundleName,
	} {
		if !strings.Contains(workflow, want) {
			t.Fatalf("release workflow missing provenance contract %q", want)
		}
	}
}

func TestEnrollmentIsPersistedBeforeOneTimeExchange(t *testing.T) {
	unixBytes, err := os.ReadFile("install.sh")
	if err != nil {
		t.Fatalf("read Unix installer: %v", err)
	}
	unix := string(unixBytes)
	unixStart := strings.LastIndex(unix, `if [ -n "$ENROLLMENT_TOKEN" ]; then`)
	if unixStart < 0 {
		t.Fatal("Unix installer enrollment block missing")
	}
	unixBlock := unix[unixStart:]
	writeIndex := strings.Index(unixBlock, "write_token_file")
	exchangeIndex := strings.Index(unixBlock, `exchange_agent_enrollment "$TOKEN"`)
	if writeIndex < 0 || exchangeIndex < 0 || writeIndex > exchangeIndex {
		t.Fatal("Unix installer must persist the runtime token before consuming enrollment")
	}

	windowsBytes, err := os.ReadFile("install.ps1")
	if err != nil {
		t.Fatalf("read Windows installer: %v", err)
	}
	windows := string(windowsBytes)
	mainStart := strings.Index(windows, "$EnrollmentExchangeSucceeded = $false")
	if mainStart < 0 {
		t.Fatal("Windows installer enrollment state marker missing")
	}
	windowsMain := windows[mainStart:]
	writeIndex = strings.Index(windowsMain, "Write-StrictTemporaryTokenFile -Path $TokenTmp")
	exchangeIndex = strings.Index(windowsMain, "Invoke-AgentEnrollment -RuntimeToken $Token")
	if writeIndex < 0 || exchangeIndex < 0 || writeIndex > exchangeIndex {
		t.Fatal("Windows installer must persist the runtime token before consuming enrollment")
	}
	aclIndex := strings.Index(windowsMain, "Assert-StrictTokenAcl -Path $TokenFile")
	installedIndex := strings.Index(windowsMain, "$EnrollmentTokenInstalled = $true")
	if aclIndex < 0 || installedIndex < 0 || aclIndex > installedIndex {
		t.Fatal("Windows installer must not retain the new token on rollback until its service ACL is usable")
	}
}
