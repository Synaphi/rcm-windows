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
- Ray is inert unless the user explicitly enables it and selects one absolute
  local `ray.exe`; the desktop accepts exactly Ray 2.55.1, executes only typed
  local start/stop/status/version argv without a shell, bounds time and output,
  strips inherited Ray/Python/pip injection variables, gives each node a full
  local per-user Ray temp path, keeps the dashboard on loopback, and exposes no
  remote RCM cluster command;
- the desktop application normally runs without elevation;
- privileged local changes are disabled in the unsigned one-file preview;
- configuration and logs remain in local application data, and configuration
  records are schema-validated and integrity-checked before use;
- 1.x import is an explicit local-file action under the production singleton;
  the source is byte-checked before and after, raw secret material is rejected
  without echo, credential and remote-control fields are not migrated, and a
  generation-bound authenticated backup is required for rollback;
- dependency inputs are pinned and hash locked; and
- no telemetry, updater, background service, remote RCM command surface, or
  default inbound firewall rule is provided.

Any report showing a listener reachable beyond loopback, unbounded or persistent
elevation, unsafe path handling, secret persistence, remote command execution,
dependency-integrity bypass, or unintended data disclosure is security relevant.
For the local Ray composition, a report is also relevant if disabled settings
cause path or process probing, an unconfigured or non-local executable runs,
an unsupported Ray version proceeds, command output or the configured path is
disclosed, an inherited environment can redirect the Ray address or temp path,
a worker reuses another account's temp path, or failed local-head verification
does not attempt local rollback.

The persisted import receipt, logs, and provenance must not serialize the
migration planner's private overlay, source contents, node values, user names,
controller lists, or local paths. The explicit on-screen confirmation may show
the user-selected source path and eligible node routing values, but it must not
show credential fields or raw secrets and must not persist that preview. A
report showing source mutation, source/destination aliasing, an import while
another production RCM owns the singleton, rollback of the wrong generation,
or any migrated credential or retired remote authority is security relevant.
Use only synthetic configurations when reproducing such a report.

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
