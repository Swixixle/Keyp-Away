# Changelog

All notable changes to KeySmith will be documented in this file.

## [0.5.2] - 2026-04-28

### Changed (documentation only)

- README and docs reposition KeySmith as a **prototype** suited to individual/small-team dev workflows; removed language that implied production or enterprise certification
- `docs/THREAT_MODEL.md` — assumptions, in/out-of-scope threats, enforcement limits, bypass paths (`--skip-rotation-check`, direct keychain use)
- `docs/SECURITY.md` — supported versions and private vulnerability reporting expectations
- Clarified that rotation **enforcement** is advisory at the KeySmith `inject` boundary, not OS/kernel policy

**No functional or API changes** in this release.

---

## [0.5.1] - 2026-04-28

### Added

- Rotation policy enforcement (`settings.enforce: true`), with grace-period behavior before blocking `inject`
- `inject --skip-rotation-check` and `inject --project-path` helpers (policy YAML resolution vs `cwd` / `KEYSMITH_DEFAULT_PROJECT`)
- Expanded `team check-rotation` with enforcement awareness and overdue bucketing
- Example team scaffolding under `examples/team/` plus README git guidance notes

### Changed

- `inject` consults `.keysmith/rotation-policy.yaml` enforcement settings when resolving policies
- MCP `inject_credential` exposes failure reasons alongside `injected: false`

### Security

- Added `docs/THREAT_MODEL.md` documenting assumptions **and documented limitations**
- Added `docs/SECURITY.md` — coordinated disclosure skeleton
- README reframed around honest scope (prototype / dev-centric workflow)

### Fixed

- Clearer errors when overdue rotation blocks `inject` (with remediation snippets)

---

## [0.5.0] - 2026-04-27

### Added — Team workflows

- `keysmith team init / status / share / receive / check-rotation`
- Git-tracked YAML + optional `.keysmith/secrets/*.age` ciphertext
- Repo-local receipts under `.keysmith-receipts/events.jsonl` for share events with optional signer `actor`
- Minimal `[team]` extra hook (YAML already core dependency)

---

## [0.4.0] - 2026-04-28

### Added — Cryptographic receipts

- Signed JSONL receipts for connect / rotate / inject / guided health flows per project (`~/.keysmith/receipts/<project>.jsonl`)
- `keysmith receipts` + `--verify` offline verification pathway
- `cryptography`-backed signing keys anchored in OS keychain accounts

---

## [0.3.1] - 2026-04-27

### Added — Offline “AI-ish” tooling

- `analyze-scopes`, `suggest-rotation`, `ai-groups`, `ai-anomalies`

### Fixed

- Regression where `audit-unused` registration dropped transiently (`@cli.command` wiring)

---

## [0.3.0] - 2026-04-26

### Added

- Heuristic scope scanner + rotation suggestions foundations

---

## [0.2.3] - 2026-04-26

### Added

- `rotation-done`, upgraded `summary`, hook messaging polish

---

## [0.2.0] - 2026-04-26

### Added — Safety net + lifecycle

- `install-hook`, `scrub-history`, `audit-scope`, usage ledger, rotation reminders, `audit-unused`

---

## [0.1.0] - 2026-04-25

### Added — Initial release

- Scanner + broker + MCP server + registry seeds
