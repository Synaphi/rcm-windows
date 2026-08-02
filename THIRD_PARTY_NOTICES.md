# Third-Party Notices

RCM's source tree refers to reviewed, hash-locked third-party components. No
dependency wheel, LibreHardwareMonitor payload, installer, or combined executable
is included in this source repository.

## Runtime dependencies

| Dependency | Version | License expression |
|---|---:|---|
| certifi | 2026.6.17 | MPL-2.0 |
| cffi | 2.1.0 | MIT-0 |
| charset-normalizer | 3.4.7 | MIT |
| clr-loader | 0.3.1 | MIT |
| idna | 3.18 | BSD-3-Clause |
| Pillow | 10.4.0 | HPND |
| psutil | 5.9.8 | BSD-3-Clause |
| pycparser | 3.0 | BSD-3-Clause |
| pystray | 0.19.5 | LGPL-3.0-only |
| pythonnet | 3.1.0 | MIT |
| requests | 2.34.2 | Apache-2.0 |
| six | 1.17.0 | MIT |
| urllib3 | 2.7.0 | MIT |

## Build and development dependencies

| Dependency | Version | License expression |
|---|---:|---|
| altgraph | 0.17.5 | MIT |
| packaging | 26.2 | Apache-2.0 OR BSD-2-Clause |
| pefile | 2023.2.7 | MIT |
| PyInstaller | 6.11.1 | GPL-2.0-or-later WITH Bootloader-exception |
| PyInstaller hooks contrib | 2026.6 | Apache-2.0 OR GPL-2.0-only |
| pywin32-ctypes | 0.2.3 | BSD-3-Clause |
| setuptools | 83.0.0 | MIT |
| wheel | 0.45.1 | MIT |

## Optional hardware-monitoring component

The packaging metadata can acquire LibreHardwareMonitor 0.9.6 under MPL-2.0 for
an independently reviewed local build. Its archive, assemblies, license text,
and notices are not stored in this source repository. Exact expected identities
and upstream locations are recorded in `policy/vendor-provenance.json` and
`packaging/vendor-data.json`.

## Source-only boundary

Exact dependency wheel filenames, scopes, and SHA-256 identities are recorded in
`policy/dependency-provenance.json`; the requirements locks contain the same
versions and hashes. Each third-party component remains governed by its own
license.

This notice documents source inputs only. It is not a binary distribution
compliance determination. Before any frozen or combined application is built for
redistribution, maintainers must perform a separate review and supply all
required license texts, notices, corresponding-source or relinking mechanisms,
and other obligations, including those applicable to MPL-2.0 components and the
LGPL-3.0-only `pystray` dependency. That review is a release blocker, not an
authorization granted by this file.
