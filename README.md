# RCM 2.x

RCM (RayClusterManager) is a compact, local-first Windows desktop application
for PC monitoring, local cleanup, outbound Remote Desktop launches, and optional
Ray integration on the same machine.

This repository is the source for the RCM 2.x Windows preview. The matching
GitHub prerelease, when published, is an unsigned standalone executable rather
than an installer. Windows may show an unrecognized-publisher warning. The
preview is not a signed, stable, supported, or fleet-ready release.

The first preview identity is `2.08.02a` (`v2.08.02a`). Its exact asset
name and verified checksum are published with the GitHub prerelease; do not use
an executable whose name or SHA-256 differs from that release record.

## Current boundary

Implemented and tested behavior is intentionally narrow:

- local hardware and system monitoring;
- local process cleanup with bounded, explicit actions;
- outbound RDP launch and port preflight initiated by the local user;
- optional local Ray lifecycle integration; and
- local health, temperature, and metrics HTTP endpoints bound to loopback only.

RCM is not a managed-node agent or remote control plane. It does not provide
remote RCM metrics or commands, fleet orchestration, password distribution,
automatic updates, telemetry, a background service, default inbound firewall
rules, or an installer/update channel. Local administrator operations remain
disabled in the unsigned one-file preview.

## Requirements

- Python 3.12 or newer
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
.\.venv\Scripts\python.exe -m pip install --require-hashes -r requirements\runtime-win-x86_64.lock
.\.venv\Scripts\python.exe -m pip install --no-deps -e .
.\.venv\Scripts\python.exe -m rcm
```

Use only dependency artifacts that match the checked-in hashes. The application
keeps mutable configuration and logs in the current user's local application
data directory; portable deployments use their local `data` directory.

## Configuration and privacy

Configuration is local JSON. Keep machine-specific topology, credential
references, and operator data out of source control. Synthetic documentation
values are appropriate, for example:

```json
{
  "schema_version": 1,
  "nodes": {
    "items": [
      {
        "node_id": "demo-worker",
        "address": "192.0.2.25",
        "role": "worker",
        "enabled": true,
        "cpu_count": 0
      }
    ],
    "local_node_id": ""
  },
  "remote": {
    "enabled": false,
    "bind_host": "127.0.0.1",
    "port": 8765,
    "max_request_bytes": 1048576,
    "request_timeout_seconds": 15
  }
}
```

The `192.0.2.0/24` block above is reserved for documentation. Do not replace it
with a real host, private-network address, account name, token, or credential.
The local HTTP surface must remain on `127.0.0.1`.

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
