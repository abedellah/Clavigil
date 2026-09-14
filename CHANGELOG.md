# Changelog

All notable changes to this project are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `src/demo_api.py` — protected demo API validating Keycloak OIDC tokens:
  RS256 signature via JWKS, issuer, audience and expiry, plus group-based
  authorisation.
- Seven unit tests for token validation, covering expired tokens, wrong
  audience, wrong issuer, forged signature, the `alg: none` attack and
  missing required claims. No containers required.

### Removed
- phpLDAPadmin. Development is dormant and it is not a tool used on real
  engagements. Directory inspection now uses `ldapsearch` via `make ldap-users`
  and `make ldap-groups`.

### Fixed
- Keycloak admin token was fetched once and never refreshed, causing 401s on
  long runs. It is now renewed from the `exp` claim with a 30-second margin.

## [1.0.0] - 2026-09-09

### Added
- JML lifecycle engine implemented: joiners, movers, leavers, contract expiry.
- Six reconciliation checks: orphan accounts, dormant accounts, entitlement
  drift, segregation-of-duties violations, expired contracts, unprocessed leavers.
- Access certification campaign export, one CSV per reviewing manager.
- Markdown reconciliation report with severity summary and remediation section.
- Two-phase integration test flow: four planted anomalies detected before
  remediation, zero after.

### Changed
- `hr_person` gains an `account_uid` column linking an HR record to its accounts.
- Role `R_BASE_EXT` now matches population `external`, covering both contractors
  and partners.

## [0.1.0] - 2026-09-09

### Added
- Docker Compose stack: OpenLDAP, phpLDAPadmin, Keycloak 26, PostgreSQL 16.
- Database schema: HR referential, entitlement catalogue, RBAC role model,
  segregation-of-duties rules, provisioning audit trail, certification campaigns.
- Seed dataset of 15 identities across employee, contractor and partner
  populations, containing four deliberately planted access anomalies.
- LDAP and Keycloak provisioning connectors.
- Command-line interface for init, sync, reconcile, report and certify.
- CI pipeline: lint, type check, SAST, secret scanning, unit and end-to-end tests.

### Known limitations
- JML lifecycle engine and reconciliation checks are specified but not implemented.
- No TLS between components; laboratory environment only.
- OpenLDAP stands in for Active Directory; Kerberos and GPOs are out of scope.
