# Changelog

All notable changes to KeySmith will be documented in this file.

## [0.5.0] - 2026-04-27

### Added

- **`keysmith team`** — git-checked `.keysmith/team.yaml`, optional `credentials.yaml` and `rotation-policy.yaml`, **age**-encrypted blobs under `.keysmith/secrets/` (requires `age` on `PATH`)
- **`~/.keysmith/team-identity.age`** for decrypting shares; `team init` generates an age keypair
- **`.keysmith-receipts/events.jsonl`** — mergeable signed share events (**`TeamReceiptLog`**) with optional **`actor`** (`--as` / `KEYSMITH_TEAM_ACTOR`)
- Receipt signing supports optional **`actor`** in canonical payload verification
- Optional **`[team]`** extra (`pip install -e ".[team]"`) — declare-only; **`PyYAML`** is already core

### Changed

- Version bumped to **0.5.0**

## [0.4.0] - 2026-04-28

### Added

- Ed25519-signed receipt JSONL logs under `~/.keysmith/receipts/<project>.jsonl` for store, inject, rotate, guided health verification
- Signing key PEM in OS keychain (`receipt-signing-key:<project>`)
- **`keysmith receipts [--verify]`** to list events and verify signatures offline
- Dependency on **`cryptography`**

### Changed

- **`mint-admin`** uses **`scan_project(Path.cwd()).project`** for the minted-token handle so it matches manifests and receipts
- MCP tools use **`CredentialBroker(project_name=...)`** so receipts attach when applicable

## [0.3.1] - 2026-04-27

### Added — “AI” insights (offline heuristics)

- Smart scope inference from Python `httpx` / `requests` URL patterns (`analyze-scopes`)
- Rotation interval suggestions with optional policy write for manifest slugs (`suggest-rotation --apply`)
- Credential grouping from slug naming patterns (`ai-groups`)
- Usage ledger anomaly hints (`ai-anomalies`)

### Changed

- `suggest-rotation` combines scope scan, registry cues, usage ledger, and `.env` presence

### Fixed

- Restored `@cli.command("audit-unused")` registration after `analyze-scopes`

## [0.3.0] - 2026-04-26

### Added

- `analyze-scopes` static HTTP pattern analysis toward registry hosts

## [0.2.3] - 2026-04-26

### Added

- `rotation-done` command to mark credentials as rotated after replacement
- `summary` command for at-a-glance health overview
- `doctor --show-usage` for last-access and rotation backlog hints
- Stronger pre-commit hook messages when staged secrets are guessed

## [0.2.2] — earlier v0.2.x

### Added

- Usage tracking in broker operations (`~/.keysmith/usage.json`)
- Rotation reminder schedules (`~/.keysmith/rotation.json`)
- Unused credential detection (`audit-unused`)

## [0.2.0]

### Added — security and lifecycle

- Pre-commit hook for staged secret literals
- Shell history scrubbing (`scrub-history`)
- Heuristic over-scope hints (`audit-scope`)
- Manual rotation policy CLI (`set-rotation`, `check-rotation`)

## [0.1.0]

### Added — initial release

- Credential discovery from code and env stacks
- Guided setup and OS keychain broker
- MCP server for assistant integration
- Explicit trust boundary: metadata to models, secrets in keychain only

[0.4.0]: https://github.com/Swixixle/Keyp-Away/releases/tag/v0.4.0
[0.3.1]: https://github.com/Swixixle/Keyp-Away/releases/tag/v0.3.1
[0.3.0]: https://github.com/Swixixle/Keyp-Away/releases/tag/v0.3.0
[0.2.3]: https://github.com/Swixixle/Keyp-Away/releases/tag/v0.2.3
