# Contribution instructions

These instructions apply to the entire repository.

## Product boundary

RCM is a source-only, local-first Windows desktop application. Keep changes within
the documented product boundary:

- local Windows hardware monitoring and cleanup;
- outbound Remote Desktop launches initiated by the local user;
- optional Ray integration on the same machine; and
- loopback-only local health and metrics endpoints.

Do not add remote RCM control, fleet orchestration, telemetry, an updater, a
background service, default inbound firewall rules, credential storage, or an
installer/release pipeline unless a maintainer explicitly approves that separate
scope.

## Safety and privacy

- Never commit real operator, customer, fleet, host, account, credential, token,
  certificate, endpoint, or private-network data.
- Use synthetic examples and documentation ranges such as `192.0.2.0/24`,
  `198.51.100.0/24`, and `203.0.113.0/24`.
- Preserve loopback binding for local HTTP surfaces. Treat any change to binding,
  authentication, privilege, process execution, or network behavior as
  security-sensitive.
- Keep the least-privilege split: the normal desktop process is unprivileged and
  elevation is limited to the existing one-shot helper boundary.
- Do not access live systems or publish artifacts as part of ordinary source
  changes.

## Engineering expectations

- Support Python 3.12 or newer and keep the documented Windows behavior intact.
- Preserve deterministic, hash-locked dependency inputs.
- Avoid new runtime dependencies unless the change explicitly requires and
  documents them.
- Keep source, tests, documentation, and policy changes in sync.
- Prefer small, reviewable commits with clear rollback boundaries.

## Verification

Before opening a pull request, run:

```text
python -B scripts/check_public_source.py
python -B -m unittest discover -s tests -p "test_*.py" -v
```

Run additional focused tests for the area changed. A pull request must not weaken
privacy checks, loopback-only invariants, dependency provenance, or license and
notice validation merely to make a check pass.

## Documentation and licensing

- Keep public documentation accurate about the source-only maturity level and
  unsupported features.
- Do not claim that an installer, executable, binary release, stable support
  channel, or fleet-ready deployment exists.
- Project-owned material is licensed under Apache License 2.0. Third-party
  components remain under their respective licenses; update
  `THIRD_PARTY_NOTICES.md` and provenance data when dependencies change.
- Packaging, signing, publishing, or releasing requires a separate maintainer
  decision and a fresh compliance review.
