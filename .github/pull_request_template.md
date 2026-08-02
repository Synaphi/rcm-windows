# Pull request

## Goal and scope

- Problem solved:
- Observable behavior before:
- Observable behavior after:
- Explicit non-goals:

## Impact

- Privacy impact and data handling:
- Privilege:
- Network/listeners:
- Processes/threads:
- Configuration/migration:
- Dependencies/licenses:
- Packaging/release:
- Performance:

## Verification

- Focused tests and exact results:
- `python -B scripts/check_public_source.py`:
- `python -B -m unittest discover -s tests -p "test_*.py" -v`:
- Manual checks, if any:

## Checklist

- [ ] The change stays within the documented local-first product boundary.
- [ ] Examples, fixtures, logs, and screenshots contain only synthetic data.
- [ ] Loopback, least-privilege, and outbound-only RDP invariants are preserved or
      the security impact is explicitly reviewed.
- [ ] Source, tests, documentation, policy, provenance, and notices agree.
- [ ] No generated cache, wheel, archive, executable, credential, token, private
      endpoint, or operator identity is included.
- [ ] Packaging, publishing, signing, or release actions are not introduced or
      performed without separate maintainer approval.

## Rollback

- Revert boundary:
- Persistent or migrated state affected:
- Follow-up work:
