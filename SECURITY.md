# Security policy

## Supported status

RCM 2.0 is an unsigned preview. The current source branch receives security
fixes, but there is no supported installer, signed or stable binary, automatic
update channel, or service-level commitment. The only reviewed binary is the
exact SHA-256-bound asset attached to the matching GitHub prerelease.

## Reporting a vulnerability

Use the repository's private security-advisory reporting feature when available.
If that route is unavailable, contact the maintainers through a private channel
listed on the repository owner profile. Do not open a public issue containing an
exploit, credential, token, private host, operator identity, or other sensitive
evidence.

Include a minimal synthetic reproduction, the affected revision, expected and
observed behavior, and the security boundary crossed. Never test against systems
you do not own or lack explicit authorization to assess.

Receipt and remediation timing are handled on a best-effort basis while the
project remains a source preview. A maintainer will coordinate disclosure after
the issue and affected scope are understood.

## Security boundary

The intended boundary is local-first:

- health, temperature, and metrics HTTP endpoints, when composed, bind to
  `127.0.0.1` only;
- RDP service plans are outbound launches and bounded TCP port preflight
  initiated locally; RCM never accepts a remote password;
- the native RDP client is resolved from the Windows system directory, launch
  files have unpredictable application-owned names, sensitive device
  redirection is off by default, and owned files are cleaned at shutdown and
  the next startup;
- the desktop application normally runs without elevation;
- privileged local changes are disabled in the unsigned one-file preview;
- configuration and logs remain in local application data, and configuration
  records are schema-validated and integrity-checked before use;
- dependency inputs are pinned and hash locked; and
- no telemetry, updater, background service, remote RCM command surface, or
  default inbound firewall rule is provided.

Any report showing a listener reachable beyond loopback, unbounded or persistent
elevation, unsafe path handling, secret persistence, remote command execution,
dependency-integrity bypass, or unintended data disclosure is security relevant.

RDP launch files contain the destination and may contain the optional Windows
user name. They are not credential stores, but they are still local operational
metadata. Installed and portable runs isolate them under the current user's
LocalAppData RCM directory; portable configuration and logs may still live
beside the executable. Portable startup fails closed if that per-user metadata
boundary is unavailable. A crash can leave launch files until the next RCM
startup. Reports that show
RCM deleting a non-owned file, launching a non-system `mstsc.exe`, accepting a
password, or enabling a remote host are in scope.

## Out of scope and safe research

Do not perform denial-of-service testing, social engineering, credential attacks,
or testing against live fleet or third-party systems. Reports about an installer,
signed binary, hosted service, or automatic updater are not actionable because
those artifacts do not exist. Reports about the exact unsigned preview asset
are in scope.

Use documentation IP ranges, synthetic local paths, and disposable test state.
Remove secrets from logs and screenshots before submitting a report.
