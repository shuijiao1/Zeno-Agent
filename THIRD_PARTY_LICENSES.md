# Third-party license review

Zeno-Agent itself is MIT licensed. Its runtime module graph is intentionally small:

- `github.com/gorilla/websocket` — BSD-style license
- `golang.org/x/sys` — BSD-3-Clause

Published release assets include target-specific CycloneDX SBOMs, checksums, and provenance. Re-check `go.mod`/`go.sum` and regenerate every target SBOM whenever dependencies change; a generated multi-copy license dump is intentionally not committed while this concise inventory remains complete.
