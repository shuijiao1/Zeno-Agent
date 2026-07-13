//go:build linux

package agent

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseMountInfoFiltersPseudoAndContainerMounts(t *testing.T) {
	fixture := filepath.Join(t.TempDir(), "mountinfo")
	content := `26 23 8:1 / / rw,relatime - ext4 /dev/vda1 rw
27 26 0:24 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
28 26 0:25 / /run rw,nosuid,nodev - tmpfs tmpfs rw
29 26 0:26 / /var/lib/docker/overlay2/abc/merged rw,relatime - overlay overlay rw
30 26 8:2 / /data rw,relatime - xfs /dev/vdb1 rw
31 26 8:2 / /mnt/data-bind rw,relatime - xfs /dev/vdb1 rw
`
	if err := os.WriteFile(fixture, []byte(content), 0o600); err != nil {
		t.Fatalf("write mountinfo fixture: %v", err)
	}

	file, err := os.Open(fixture)
	if err != nil {
		t.Fatalf("open mountinfo fixture: %v", err)
	}
	defer file.Close()
	var included []string
	scanner := bufio.NewScanner(file)
	seen := map[string]struct{}{}
	for scanner.Scan() {
		mount, ok := parseMountInfoLine(scanner.Text())
		if !ok || !includeDiskMount(mount.mountPoint, mount.fsType, mount.source) {
			continue
		}
		if _, exists := seen[mount.device]; exists {
			continue
		}
		seen[mount.device] = struct{}{}
		included = append(included, mount.mountPoint)
	}
	if strings.Join(included, ",") != "/,/data" {
		t.Fatalf("included mounts = %v, want root and data only once", included)
	}
}
