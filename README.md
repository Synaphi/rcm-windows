# RCM 2.x

RCM (RayClusterManager) 2.x is a local-first Windows desktop developer preview.
The repository contains the modular monitoring, cleanup, outbound Remote
Desktop, and optional local Ray service foundations together with the packaged
desktop shell.

This repository is the source for the RCM 2.x Windows preview. The matching
GitHub prerelease, when published, is an unsigned standalone executable rather
than an installer. Windows may show an unrecognized-publisher warning. The
preview is not a signed, stable, supported, or fleet-ready release.

The current preview identity is `2.08.03a` (`v2.08.03a`). Its exact asset
name and verified checksum are published with the GitHub prerelease; do not use
an executable whose name or SHA-256 differs from that release record.

## What the packaged preview currently does

The executable currently provides:

- a single-instance desktop and tray lifecycle with bounded shutdown;
- a GUI setup wizard that creates and validates this PC's local configuration;
- strict, integrity-checked loading of that configuration on later starts;
- rendering of configured node records and read-only status/help surfaces; and
- an isolated, non-elevated preview identity.

The monitoring, cleanup, outbound RDP, Ray, and loopback HTTP implementations
are present and tested as service modules, but their operational desktop
commands are not yet composed into this packaged preview. A button that reports
`This operation is not configured` did not perform the requested operation.
The Settings surface is read-only; use the setup wizard for the supported local
fields. These limitations make this a developer preview, not a stable 1.x
replacement.

RCM is not a managed-node agent or remote control plane. It does not provide
remote RCM metrics or commands, fleet orchestration, password distribution,
automatic updates, telemetry, a background service, default inbound firewall
rules, or an installer/update channel. Local administrator operations remain
disabled in the unsigned one-file preview.

## Fast setup on another Windows PC

1. Download `RCM-2.08.03a-windows-x64.exe` from the matching `v2.08.03a`
   prerelease. Compare its SHA-256 with the value on that release page before
   running it.

```powershell
(Get-FileHash -Algorithm SHA256 .\RCM-2.08.03a-windows-x64.exe).Hash.ToLowerInvariant()
```

The printed value must exactly match the SHA-256 published for that asset.
2. Put the executable in a dedicated, user-writable folder. No installer or
   administrator approval is required by RCM itself; Windows may still show an
   unrecognized-publisher warning because the preview is unsigned.
3. If RCM is running, use **Quit** from its notification-area tray icon;
   closing the main window only hides it. Then launch the local setup wizard
   from PowerShell:

```powershell
Start-Process -FilePath .\RCM-2.08.03a-windows-x64.exe -ArgumentList '--configure' -Wait
```

4. Enter only this PC's node ID, address or host name, role, optional CPU count,
   future monitoring preference, and minimized-start preference. The monitoring
   preference is stored but its service is not composed in this preview. Select
   **Save**, then start the executable normally.

The default packaged layout stores state under
`%LOCALAPPDATA%\RayClusterManager`. To keep state beside the executable instead,
use a dedicated writable folder and set portable mode in the same PowerShell
session before both setup and normal startup. Set it again for every later
launch; double-clicking the executable or using a new shell without this
environment variable selects the installed layout instead.

```powershell
$env:RCM_PORTABLE = '1'
Start-Process -FilePath .\RCM-2.08.03a-windows-x64.exe -ArgumentList '--configure' -Wait
Start-Process -FilePath .\RCM-2.08.03a-windows-x64.exe
```

The wizard never accepts a password, token, credential, firewall change, remote
command, or update URL. It does not enable Windows RDP, alter Ray, open a port,
or contact another PC.

## Requirements

- Python 3.12 x64 for source use; the release build requires CPython 3.12.10
- Windows 11 x64 as the primary development target
- Windows 10 x64 on a best-effort basis
- PowerShell for the documented setup commands

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
