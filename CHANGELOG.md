# Changelog

All notable changes to KeySmith will be documented in this file.

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

[0.3.1]: https://github.com/Swixixle/Keyp-Away/releases/tag/v0.3.1
[0.3.0]: https://github.com/Swixixle/Keyp-Away/releases/tag/v0.3.0
[0.2.3]: https://github.com/Swixixle/Keyp-Away/releases/tag/v0.2.3
