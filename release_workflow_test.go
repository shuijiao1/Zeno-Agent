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

func TestWorkflowsUseNode24JavaScriptActions(t *testing.T) {
	for _, path := range []string{".github/workflows/ci.yml", ".github/workflows/release.yml"} {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		workflow := string(content)
		for _, want := range []string{
			"actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
			"actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e",
		} {
			if !strings.Contains(workflow, want) {
				t.Fatalf("%s missing Node 24 action pin %q", path, want)
			}
		}
		for _, old := range []string{
			"actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
			"actions/setup-go@40f1582b2485089dde7abd97c1529aa768e1baff",
		} {
			if strings.Contains(workflow, old) {
				t.Fatalf("%s still uses Node 20 action pin %q", path, old)
			}
		}
	}
}

func TestReleasePolicyVersionInjectionVulnerabilityGateAndSBOM(t *testing.T) {
	workflowBytes, err := os.ReadFile(".github/workflows/release.yml")
	if err != nil {
		t.Fatalf("read release workflow: %v", err)
	}
	workflow := string(workflowBytes)
	for _, want := range []string{
		"fetch-depth: 0",
		"scripts/check-release-policy.sh",
		"release already exists",
		"govulncheck@v1.6.0",
		"for goos in linux darwin windows",
		`GOOS="$goos" GOARCH=amd64 "$govulncheck" ./...`,
		"cyclonedx-gomod@v1.9.0",
		"for target in linux/amd64 linux/arm64 linux/arm darwin/amd64 darwin/arm64 windows/amd64 windows/arm64",
		`zeno-agent_${goos}_${goarch}.cdx.json`,
		`CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch"`,
		"Validate artifact-specific SBOM coverage",
		"cdx:gomod:build:env:CGO_ENABLED",
		"CGO_ENABLED is not 0",
		"missing platform dependency golang.org/x/sys",
		"zeno-agent_*.cdx.json",
		"-X main.defaultVersion=$version",
	} {
		if !strings.Contains(workflow, want) {
			t.Fatalf("release workflow missing policy contract %q", want)
		}
	}
	if strings.Contains(workflow, "dist/zeno-agent.cdx.json") {
		t.Fatal("release workflow still emits a single host-specific SBOM for all artifacts")
	}
	if strings.Contains(workflow, "workflow_dispatch") {
		t.Fatal("tag-only release workflow must not expose a manual dispatch path that cannot satisfy tag-derived SBOM versioning")
	}
	policyBytes, err := os.ReadFile("scripts/check-release-policy.sh")
	if err != nil {
		t.Fatalf("read release policy: %v", err)
	}
	policy := string(policyBytes)
	for _, want := range []string{"strict SemVer", "VERSION", "merge-base --is-ancestor", "not greater than existing SemVer"} {
		if !strings.Contains(policy, want) {
			t.Fatalf("release policy missing %q", want)
		}
	}
	versionBytes, err := os.ReadFile("VERSION")
	if err != nil {
		t.Fatalf("read VERSION: %v", err)
	}
	if version := strings.TrimSpace(string(versionBytes)); version != "v0.5.1" {
		t.Fatalf("VERSION = %q, want current formal version v0.5.1", version)
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
	installedIndex := strings.Index(windowsMain, "$EnrollmentTokenInstalled = $true")
	serviceChangeIndex := strings.Index(windowsMain, "$BinPath = Join-WindowsCommandLine")
	if installedIndex < 0 || serviceChangeIndex < 0 || installedIndex < exchangeIndex || installedIndex > serviceChangeIndex {
		t.Fatal("Windows installer must preserve the exchanged runtime token before any later SCM change can fail")
	}
}
