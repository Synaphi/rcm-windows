# Contributing to RCM

RCM welcomes focused source contributions that preserve its local-first,
least-privilege boundary. The repository may have explicitly reviewed unsigned
prerelease assets, but ordinary source contributions do not authorize or create
a binary release channel.

## Before changing code

1. Read `README.md`, `SECURITY.md`, and the root `AGENTS.md` instructions.
2. Confirm that the change belongs to the current product boundary.
3. Open an issue or discussion before proposing a new remote surface,
   privileged behavior, network listener, dependency, packaging step, or public
   release mechanism.
4. Use only synthetic test and documentation data.

Do not use live fleet systems, customer information, production endpoints,
private-network addresses, credentials, access tokens, certificates, or real
operator identities in development evidence or commits.

## Development setup

Use Python 3.12 x64. The release build requires exact CPython 3.12.10. On
Windows, create an isolated environment and install the hash-locked runtime and
development/build inputs:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --require-hashes -r requirements\runtime-win-x86_64.lock -r requirements\dev.lock
.\.venv\Scripts\python.exe -m pip install --no-build-isolation --no-deps -e .
```

Dependency updates must update the applicable lock files, provenance records,
notices, and tests together. Do not weaken hash enforcement or download an
unreviewed artifact as part of a test.

## Change expectations

- Keep the unprivileged desktop process separate from the one-shot local
  elevation helper.
- Preserve loopback-only binding for local health and metrics endpoints.
- Keep RDP activity outbound and explicitly user initiated.
- Preserve strict configuration parsing and safe local path handling.
- Avoid new runtime dependencies unless the proposed scope requires them.
- Update tests and public documentation with observable behavior.
- Keep commits small, reviewable, and free of generated caches or binaries.

Packaging, signing, uploading, publishing, and releasing are separate maintainer
decisions. A source change must not silently add or perform those actions.

For a maintainer-authorized binary candidate, build only from a clean commit
whose deterministic public-export snapshot is unique in the reachable history.
Private-only policy or evidence commits must precede a public-source change so
the lifecycle verifier can identify exactly one source commit without weakening
the provenance check. If that precondition fails, supersede the candidate and
build again from a corrected clean commit.

## Required verification

Run the public-source contract and the complete test suite:

```powershell
py -3.12 -B scripts\check_public_source.py
py -3.12 -B -m unittest discover -s tests -p "test_*.py" -v
```

Also run focused tests for the component changed. Security-sensitive changes
should include negative tests for malformed, unauthorized, non-loopback,
traversal, race, and rollback cases as applicable.

Do not change a policy expectation simply to make an unexpected result pass.
Explain the intended invariant and update implementation, tests, policy, and
documentation together.

## Pull requests

Describe:

- the problem and observable change;
- exact files and components affected;
- privacy, privilege, network, process, configuration, and dependency impact;
- tests run and their exact result; and
- rollback considerations.

A pull request must contain no sensitive evidence or unrelated cleanup. Hosted
checks must pass on supported runners. Maintainers may require extra review for
privilege, networking, dependency, licensing, or packaging changes.

## License

By contributing, you agree that your contribution is licensed under Apache
License 2.0. Do not submit material that you do not have the right to license.
Identify third-party material and preserve its required attribution and license
terms in `THIRD_PARTY_NOTICES.md` and provenance records.
