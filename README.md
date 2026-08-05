# RCM 2.x

RCM (RayClusterManager) 2.x is a local-first Windows desktop developer preview.
The repository contains the modular monitoring, cleanup, outbound Remote
Desktop, and optional local Ray service foundations together with the packaged
desktop shell.

This repository is the source for the RCM 2.x Windows preview. The matching
GitHub prerelease, when published, is an unsigned standalone executable rather
than an installer. Windows may show an unrecognized-publisher warning. The
preview is not a signed, stable, supported, or fleet-ready release.

The current preview identity is `2.08.05a` (`v2.08.05a`). Its exact asset
name and verified checksum are published with the GitHub prerelease; do not use
an executable whose name or SHA-256 differs from that release record.

The `v2.08.05a` preview composes the personal-use outbound RDP client, explicit
secret-free 1.x settings import, and explicit local Ray 2.55.1 Start/Stop flow
described below. Historical `v2.08.03b` bytes contain the RDP flow but not the
later import or local Ray composition. Always match the executable, tag,
release notes, size, and SHA-256.

## What the packaged preview currently does

The executable currently provides:

- a single-instance desktop and tray lifecycle with bounded shutdown;
- a GUI setup wizard that creates and validates this PC's local configuration;
- strict, integrity-checked loading of that configuration on later starts;
- explicit, original-preserving import of supported secret-free 1.x settings;
- rendering of configured node records and read-only status/help surfaces;
- a standard-user, outbound-only native Windows Remote Desktop flow; and
- explicit local Ray 2.55.1 Start/Stop commands after local setup; and
- an isolated, non-elevated preview identity.

The monitoring, cleanup, cluster-state observer, and loopback HTTP
implementations are present and tested as service modules, but their
operational desktop commands are not composed into the preview. The two local
Ray commands are composed only for the PC running RCM; the conservative
cluster-state observer remains uncomposed. The Settings surface is read-only;
use the setup wizard for supported local fields. These limitations make this a
developer preview, not a stable 1.x replacement.

RCM is not a managed-node agent or remote control plane. It does not provide
remote RCM metrics or commands, fleet orchestration, password distribution,
automatic updates, telemetry, a background service, default inbound firewall
rules, or an installer/update channel. Local administrator operations remain
disabled in the unsigned one-file preview.

## Personal Remote Desktop

The current source composes a standard-user, outbound-only Windows Remote
Desktop flow:

1. Select a configured node in the main list, then select **RDP**. You can also
   enter or replace the remote address directly in the RDP window.
2. Enter an optional Windows user name and the RDP port. RCM never offers a
   password field; enter credentials only in the Windows sign-in window.
3. Leave clipboard sharing off unless you need it. Drive, generic/USB device,
   camera, microphone, printer, COM-port, smart-card, WebAuthn, and location
   redirection are explicitly disabled.
4. Select **Check and connect**. For a numeric IP address, RCM performs only a
   bounded, cancellable TCP check of the selected address and port. RCM does
   not start a DNS resolver for a host name; **Connect anyway** passes the
   validated host name to Windows for its own resolution and final diagnosis.

The remote PC must support RDP hosting—normally Windows Pro or higher—have
Remote Desktop enabled, be reachable on the selected port, and permit the
Windows account. A Windows Home PC can be the client, but normally cannot be
the RDP host. RCM does not enable the host, modify its firewall, grant user
rights, or send a remote command.

RCM launches the trusted `mstsc.exe` from the Windows system directory using a
per-launch `.rdp` file in the current user's dedicated RCM data directory. The
file contains the destination and optional user name, never a password, and is
created with an atomic local ownership marker. It is removed during normal
shutdown or recovered at the next startup after an interrupted run. If the
native client still has the file open, RCM preserves it, disables new RDP
launches, and retries only during later lifecycle cleanup after that reader has
released it; RCM never waits for or terminates the native client.
Portable mode rejects a metadata directory that overlaps the shared portable
application tree, is on a mapped drive, or traverses a reparse alias. Removing
the owned file does not close or terminate an already-open `mstsc.exe` session.
Because RCM and these files are unsigned, Windows or organizational policy may
show a publisher warning or block the file. Do not weaken policy to bypass that
decision.

Addresses already present in the integrity-wrapped node configuration are
available as RDP defaults. An address or user name typed only in the RDP window
is session-only and is not added to `config.json`.

## Local Ray composition

The `v2.08.05a` preview can perform two user-initiated operations: **Start local
Ray** and **Stop local Ray**. Setup must first explicitly enable Ray, select one
absolute local `ray.exe`, and set the head address. RCM does not scan the user
profile, trust `PATH`, import the 1.x Ray executable path, download Ray, or
invoke another machine.

The compatibility pin is Ray `2.55.1` under CPython 3.12 x64. Each operation
runs `ray.exe --version` first and fails closed on any other result. A local
head role starts a head with its configured address, loopback-only dashboard,
ports, and CPU count, then performs a bounded status verification; failed
verification triggers a local `ray stop` rollback. A local worker role joins
only the configured head and supplies a full per-user local Ray temp path so a
head running under a different Windows account cannot redirect it into that
account's profile. An observer role is refused. Commands use separate argv
tokens, no shell, a sanitized environment that replaces inherited `RAY_*` and
Python/pip controls, bounded time and output, and the same configured local
executable for stop. Command output and the local path are not shown in UI
results.

The selected Ray installation must already work locally. For the dashboard
used by the compatibility lab, install the pinned `ray[default]` extra and the
Microsoft Visual C++ runtime required by Ray's signed Windows child
executables. RCM neither downloads nor repairs these prerequisites; a missing
prerequisite fails the bounded local start.

Ray documents Windows support as beta and Windows multi-node clustering as
experimental. Use this composition only on disposable, route-isolated,
non-production Windows machines. RCM adds no remote RCM command, update,
password, repair, listener, or cluster API. Stop Ray explicitly on every lab
node and verify that Ray processes, temporary lab state, VM checkpoints, and
test-only networking are removed before declaring a test complete.

### Cluster-state observer boundary in current source

The current source also contains a conservative, uncomposed cluster-state
observer. It invokes the selected local Ray CLI directly, never through a
shell, and performs at most five bounded JSON list queries for nodes, jobs,
tasks, actors, and placement groups across at most 32 enabled nodes. It maps
live Ray nodes to the exact configured logical name or IP and treats missing,
duplicate, unexpected, ambiguous, stale, truncated, timed-out, malformed, or
otherwise incomplete evidence as `UNKNOWN`. Live Ray node IDs must also be
globally unique. Non-standard JSON constants and duplicate object keys are
rejected, as is invalid UTF-8. The observation timestamp is a conservative
boundary captured before the first query; the service samples its monotonic
assessment clock after all queries, so a slow query sequence cannot make older
evidence look fresh.

Ray 2.55.1 prints `No resource in the cluster` followed by one platform line
ending instead of JSON for an empty filtered result. RCM accepts only the exact
exit-zero LF and CRLF forms as an empty list; missing or extra line endings,
whitespace variants, warnings, and truncation remain `UNKNOWN`.

Known active jobs, tasks, actors, or placement groups produce `BUSY` even if a
different query is incomplete. `IDLE` is returned only when every required
query is complete and fresh, the configured topology matches, and all active
counts are zero. Ray entrypoint and metadata fields exist only long enough to
classify work and are not logged, persisted, or displayed. The observer is not
yet connected to the desktop or runtime, and it adds no Dashboard HTTP access
or Ray SDK dependency.

This result is a point-in-time observation, not a cluster-wide admission lock.
Another process or Ray client can submit work immediately after an `IDLE`
answer; the existing maintenance guard coordinates only callers in the same
RCM process. A later operation that can disrupt a cluster must re-observe and
use a separately designed admission/fencing mechanism before claiming race-
free safety.

## Fast setup on another Windows PC

1. Download `RCM-2.08.05a-windows-x64.exe` from the matching `v2.08.05a`
   prerelease. Compare its SHA-256 with the value on that release page before
   running it.

```powershell
(Get-FileHash -Algorithm SHA256 .\RCM-2.08.05a-windows-x64.exe).Hash.ToLowerInvariant()
```

The printed value must exactly match the SHA-256 published for that asset.
2. Put the executable in a dedicated, user-writable folder. No installer or
   administrator approval is required by RCM itself; Windows may still show an
   unrecognized-publisher warning because the preview is unsigned.
3. If RCM is running, use **Quit** from its notification-area tray icon;
   closing the main window only hides it. Then launch the local setup wizard
   from PowerShell:

```powershell
Start-Process -FilePath .\RCM-2.08.05a-windows-x64.exe -ArgumentList '--configure' -Wait
```

4. Enter only this PC's node ID, address or host name, role, optional CPU count,
   future monitoring preference, minimized-start preference, explicit local Ray
   enablement, local `ray.exe`, and head-address fields. The monitoring
   preference is stored but its service is not composed. Select **Save**, then
   start the executable normally.

The default packaged layout stores state under
`%LOCALAPPDATA%\RayClusterManager`. To keep state beside the executable instead,
use a dedicated writable folder and set portable mode in the same PowerShell
session before both setup and normal startup. Set it again for every later
launch; double-clicking the executable or using a new shell without this
environment variable selects the installed layout instead.

Portable mode keeps configuration and logs in the portable `data` directory,
but temporary RDP launch files always remain under the current user's
`%LOCALAPPDATA%\RayClusterManager\rdp` directory so a shared portable folder
does not expose their destination or optional user-name metadata. Portable
startup fails closed if a distinct per-user LocalAppData location is
unavailable.

```powershell
$env:RCM_PORTABLE = '1'
Start-Process -FilePath .\RCM-2.08.05a-windows-x64.exe -ArgumentList '--configure' -Wait
Start-Process -FilePath .\RCM-2.08.05a-windows-x64.exe
```

The wizard never accepts a password, token, credential, firewall change, remote
command, or update URL. Saving settings does not start or stop Ray, enable
Windows RDP, open a listener, or contact another PC.

## Requirements

- Python 3.12 x64 for source use; the release build requires CPython 3.12.10
- Windows 11 x64 as the primary development target
- Windows 10 x64 on a best-effort basis
- PowerShell for the documented setup commands
- optional user-supplied Ray 2.55.1 for preview and source local Ray commands;
  Windows multi-node operation remains experimental

The source tree does not bundle dependency wheels or the optional
LibreHardwareMonitor payload. Their approved identities are recorded in the
lock and provenance files.

## Run from source

From PowerShell in the repository root:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --require-hashes -r requirements\runtime-win-x86_64.lock -r requirements\dev.lock
.\.venv\Scripts\python.exe -m pip install --no-build-isolation --no-deps -e .
.\.venv\Scripts\python.exe -m rcm --configure
.\.venv\Scripts\python.exe -m rcm
```

Use only dependency artifacts that match the checked-in hashes. The application
keeps mutable configuration and logs in the current user's local application
data directory; portable deployments use their local `data` directory.

## Configuration and privacy

The first normal start or `--configure` run creates an integrity-wrapped local
`config.json`. Do not hand-edit that envelope: invalid structure, generation,
or checksum data is rejected. Rerun the GUI wizard to change the supported
local fields. Development runs use `%LOCALAPPDATA%\RayClusterManager-dev`; the
packaged default and portable paths are described above.

Configuration is not a credential store. Keep its machine-specific node data,
the whole application-data folder, logs, screenshots, and diagnostics out of
source control and public issues. Repository examples and tests use only
reserved documentation addresses such as `192.0.2.0/24` and synthetic names.
The local HTTP boundary, when composed in a later preview, must remain on
`127.0.0.1`.

### Import an RCM 1.x configuration

The setup wizard offers **Import from RCM 1.x** only after the user
selects that action. Quit both versions first; the window close button may only
hide either application in the notification area. The wizard suggests
`%APPDATA%\RayClusterManager\config.json` but does not scan for or read it in
the background. A different source must be an explicitly selected local,
regular file. Installed and portable 2.x destinations remain separate.

Before confirmation, the wizard shows the source path, schema, SHA-256,
supported node routing preview, and separate value-free mapped, skipped, and
rejected field summaries. It then re-reads the source, requires the same bytes,
stores only supported typed fields through the generation/checksum transaction,
reloads the result, and checks the source again. Existing 2.x sections with no
equivalent imported field remain unchanged. The wizard never renames, rewrites,
schema-upgrades, or deletes the 1.x file. Repeating an identical import is a
no-op and does not advance the destination generation.

Raw password, token, key, or credential material rejects the whole import
without echoing its value. RDP user names and credential references,
controller/trust lists, update or executable paths, and retired remote
repair/update/password/cluster authority are not imported. Safe node routing,
local role/address/CPU data, Ray head and port settings, and semantically
matching local preferences are eligible; importing settings never starts Ray,
launches RDP, opens a listener, elevates, or contacts another PC.

When an import changes 2.x state, the existing authenticated generation is
retained as the store backup and a value-free receipt binds the new generation
to that backup. **Rollback last 1.x import** is accepted only while that exact
imported generation and backup still match; any intervening configuration save
fails closed instead of guessing. Rollback writes the old configuration as a
new monotonic generation and removes only the import receipt. Keep both
versions side by side and use tray **Quit** before switching back to 1.x.

If local configuration becomes unreadable, use tray **Quit** first, then move
the applicable whole state folder to a recovery folder: installed
`%LOCALAPPDATA%\RayClusterManager`, source
`%LOCALAPPDATA%\RayClusterManager-dev`, or the portable executable folder's
`data` subfolder.
This preserves the record, backup, journal, and logs for private diagnosis while
allowing RCM to create clean defaults. Do not publish the recovery folder.

## Verify a checkout

The policy checker requires a complete source tree with no extra tracked source
paths:

```powershell
py -3.12 -B scripts\check_public_source.py
py -3.12 -B -m unittest discover -s tests -p "test_*.py" -v
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for change and review expectations and
[SECURITY.md](SECURITY.md) for the security boundary and reporting process.

## License

Project-owned material is licensed under the [Apache License 2.0](LICENSE).
Third-party components remain under their respective licenses; see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and the checked-in provenance
records. The preview binary carries the reviewed notices and
LibreHardwareMonitor payload selection. Apache-2.0 does not replace any
third-party license.
