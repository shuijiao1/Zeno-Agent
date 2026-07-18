# Contributing

Keep pull requests focused and add regression tests. Open an Issue first for protocol, service-account, installer, or supported-platform changes; report vulnerabilities privately through `SECURITY.md`.

Run `go test -race ./...`, `go vet ./...`, `staticcheck ./...`, `bash -n install.sh`, supported cross-builds, `bash scripts/check-sensitive-files.sh`, and `git diff --check`. Run the platform-specific PowerShell/macOS checks when those paths change. Document Controller compatibility, privileges, collected data, migration, and rollback impact.

Never commit `.env`, token files, private keys, runtime data, generated release output, private infrastructure details, or unredacted logs. Use RFC documentation addresses in examples.
