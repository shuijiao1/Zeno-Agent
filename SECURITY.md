# Security Policy

## Private vulnerability reports

Report vulnerabilities privately through GitHub Private Vulnerability Reporting:

<https://github.com/shuijiao1/Zeno-Agent/security/advisories/new>

For Controller/API issues, use <https://github.com/shuijiao1/Zeno/security/advisories/new> and read the Controller [security boundary](https://github.com/shuijiao1/Zeno/blob/main/docs/SECURITY.md).

Do **not** open a public Issue for an unpatched vulnerability. Never attach runtime or enrollment tokens, complete install commands, Authorization headers, token files, service definitions containing arguments, Controller databases/backups, notification credentials, or unredacted logs/screenshots. If private reporting is unavailable, open a public Issue that only asks the maintainer to establish a private contact channel.

Maintainers aim to acknowledge reports within 7 days, provide an initial assessment within 14 days, and coordinate remediation and disclosure with the reporter. Do not disclose before a fix and advisory are ready unless required by law.

## Supported versions

Security fixes are provided for the latest stable Agent release. Upgrade to the latest release before reporting a version-specific issue unless the upgrade itself is the vulnerability. Verified Controller ↔ Agent combinations and deprecation policy are maintained in the Controller [COMPATIBILITY.md](https://github.com/shuijiao1/Zeno/blob/main/docs/COMPATIBILITY.md).

The Agent is an outbound-only monitoring process. It does not provide remote shell, command execution, file management, or generic task execution. Remote Controllers require HTTPS by default; direct-IP HTTP with an explicit port is an unsafe, explicit opt-in and transmits bearer credentials in plaintext.
