# KeySmith

> **Local-first MCP credential broker** — reason about API keys without the model ever receiving raw secrets.

**Core principle:** The AI may reason about credentials, but it should never possess credentials.

[![Python](https://img.shields.io/badge/python-3.11+-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## What is this?

KeySmith helps AI assistants (Claude, ChatGPT via MCP, etc.) **diagnose** missing or misconfigured credentials by returning **handles, fingerprints, and status** — never plaintext keys.

**Problems it targets**

- Manual token flows and hidden failures when env vars are wrong
- Pasting bearer tokens into chat
- Local Open Case / adapter projects with many API keys (FEC, Congress.gov, Perplexity, …)

**Example (`keysmith doctor`)**

```bash
keysmith doctor --project-path ~/Open-Case

# Credential Status
# ✓ CONGRESS_API_KEY      valid (keychain)     congress_...
# ○ FEC_API_KEY           present (.env)       —
# ✗ PERPLEXITY_API_KEY    missing              —
```

KeySmith scans **code** for required env vars and checks **OS keychain** plus **`.env` / `.env.local` / `.env.example`** for *presence only* (values are never read into LLM payloads).

---

## Quick Start (5 minutes)

```bash
# 1. Install (from this repo)
git clone https://github.com/Swixixle/Keyp-Away.git
cd Keyp-Away
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,mcp]"

# 2. Scan your project
cd /path/to/your/project
keysmith summary

# 3. Set up missing credentials (guided)
keysmith setup fec
# Browser → copy key → clipboard / hidden paste → optional health check

# 4. Optionally apply heuristic rotation suggestions for manifest slugs only
keysmith suggest-rotation --apply

# 5. Install leak protection
keysmith install-hook
keysmith scrub-history --dry-run   # preview first; omit --dry-run when ready
```

Adjust provider slugs (`fec`, `congress_gov`, …) and paths to match your app.

---

## Architecture

```
Claude / ChatGPT (MCP tools)
       ↓
KeySmith MCP server (metadata only)
       ↓
Credential broker (handles, fingerprints)
       ↓
OS keychain (macOS Keychain, Secret Service on Linux, Windows Credential Locker)
```

**What assistants see**

```json
{
  "env": "FEC_API_KEY",
  "status": "valid_keychain",
  "fingerprint": "fec_xxxxx...xxxx",
  "location": "keychain"
}
```

**What assistants never receive**

```json
{ "FEC_API_KEY": "sk-real-secret" }
```

Responses avoid logging secrets: log redaction and prompts use hidden input where secrets are entered.

---

## Install and daily commands

### Install

```bash
git clone https://github.com/Swixixle/Keyp-Away.git
cd Keyp-Away

python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev,mcp]"
```

### Scan a project

```bash
cd /path/to/your/app
keysmith doctor
```

Use `--skip-health` to avoid HTTP checks against provider APIs (offline / CI).

### Guided setup (registry provider)

Uses the bundled provider registry (e.g. `fec`, `congress_gov`): optional browser open, masked clipboard offer, hidden paste fallback, then optional HTTP health check.

```bash
keysmith setup fec --project-path /path/to/your/app
```

Registry keys are shown if the slug is unknown. The keychain handle uses your **scanned** credential slug when it matches the provider (e.g. `congress` for `congress_gov`).

### Store a key in the keychain (manual, hidden prompt)

```bash
keysmith connect fec --project-path /path/to/your/app
```

### Inject a keychain handle into the current process env (no secret printed)

```bash
keysmith inject 'sec://my-project/fec/api-key' FEC_API_KEY
```

### Mint a short-lived admin token (Open Case–style)

```bash
export KEYSMITH_OPEN_CASE_ADMIN_URL=https://your-app.example.com
keysmith mint-admin --ttl 60
```

Only the **handle URI and fingerprint** are echoed — not the token body.

---

## Claude Desktop (MCP)

Point the MCP server at the venv binary and set a default project root so `doctor` can omit `project_path`:

```json
{
  "mcpServers": {
    "keysmith": {
      "command": "/absolute/path/to/Keyp-Away/.venv/bin/keysmith-mcp",
      "args": [],
      "env": {
        "KEYSMITH_DEFAULT_PROJECT": "/Users/you/Open-Case"
      }
    }
  }
}
```

Config file (macOS): `~/Library/Application Support/Claude/claude_desktop_config.json`

Restart Claude Desktop after edits. The `doctor` tool returns `project_path`, `env_file_vars` (presence map), and per-credential `status` / `location`.

**Quick checklist**

| Step | Action |
|------|--------|
| 1 | `pip install -e ".[mcp]"` so `keysmith-mcp` exists in this repo’s venv |
| 2 | Put the **absolute** path to `.venv/bin/keysmith-mcp` in `command` |
| 3 | Set `KEYSMITH_DEFAULT_PROJECT` to your app root so tools can omit `project_path` |
| 4 | Restart Claude Desktop after every config change |

The server is **stdio-only** (no network port). Tools: `doctor`, `inject_credential`, `mint_admin_token` (requires `KEYSMITH_OPEN_CASE_ADMIN_URL` or `OPEN_CASE_ADMIN_URL` for mint).

---

## Cryptographic receipts (v0.4)

KeySmith can append **Ed25519-signed JSON lines** for lifecycle events (connect, inject, rotate, guided health check). This is a **local audit trail** — **receipts, not verdicts**: they attest that KeySmith recorded an event, not that a third party blessed it.

- **Log:** `~/.keysmith/receipts/<scanned-project>.jsonl` (one JSON object per line)  
- **Signing key:** stored in the OS keychain under account `receipt-signing-key:<project>` (PEM-encoded Ed25519 private key)  
- **Payload:** never includes raw secrets — handles, fingerprints, and action labels only  

```bash
keysmith receipts --project-path /path/to/app
keysmith receipts --project-path /path/to/app --verify
```

---

## CLI commands

| Command | Purpose |
|--------|---------|
| `keysmith summary [--project-path DIR] [--skip-health]` | At-a-glance counts + unused/over-scope/rotation notices |
| `keysmith doctor [--project-path DIR] [--skip-health] [--show-usage]` | Scan code + env; optional last-access hints + rotation backlog |
| `keysmith rotation-done <slug> [--project-path DIR]` | Mark rotated (advance next reminder; requires `set-rotation` first) |
| `keysmith setup <registry_key> [--project-path DIR]` | Guided: browser, clipboard or hidden paste, health check |
| `keysmith connect <slug\|ENV_NAME> --project-path DIR` | Manual store (hidden prompt) |
| `keysmith inject <handle_uri> <TARGET_ENV>` | Load keychain secret into `os.environ` |
| `keysmith mint-admin [--ttl N] [--base-url URL]` | Mint admin JWT and store handle |
| `keysmith install-hook [--repo-path DIR]` | Git pre-commit hook: block likely staged secrets |
| `keysmith scrub-history [--dry-run]` | Remove secret-shaped lines from shell history backups (`.bak`) |
| `keysmith audit-scope [--project-path DIR]` | Warn if registry lists scopes but code usage looks read-only |
| `keysmith analyze-scopes [--project-path DIR]` | Infer read/write/admin-ish needs from httpx/requests calls to registry hosts |
| `keysmith suggest-rotation [--project-path DIR] [--apply]` | Heuristic rotation-day suggestions; optionally write reminders for manifest slugs |
| `keysmith ai-groups [--project-path DIR]` | Group credentials by slug patterns (tier/region/AWS/GCP-ish) |
| `keysmith ai-anomalies [--days N]` | Flag coarse ledger outliers (heavy daily rate vs span, resurfaced-quiet keys) |
| `keysmith audit-unused [--days 90]` | Handles tracked in `~/.keysmith/usage.json` stale N+ days |
| `keysmith set-rotation <slug> [--days N] [--project-path DIR]` | Rotation reminder cadence (`~/.keysmith/rotation.json`) |
| `keysmith check-rotation` | Overdue vs next-7-days reminders |
| `keysmith receipts [--project-path DIR] [--verify]` | Show (and optionally verify) signed JSONL event receipts |

---

## v0.2 feature set

- Pre-commit staged secret heuristic (`install-hook`), shell-history scrubbing, heuristic over-scope hints  
- **Usage ledger** — `doctor`/`verify`, `inject`, and `store` bump `~/.keysmith/usage.json` (handles only); `audit-unused` surfaces stale credentials  
- **Rotation reminders** — local policy JSON (not secrets); auto-rotation deliberately out of scope for now  

---

## v0.3 feature set

- **`analyze-scopes`** — Python `httpx` / `requests` URL scan vs registry hosts; coarse read/write/admin-style paths (offline heuristic).
- **`suggest-rotation`** — merges scope signals, registry class, ledger counts, `.env` hints; **`--apply`** writes rotation reminders for slugs present in **`scan_project`** only.
- **`ai-groups`** — slug pattern groups (tier / region / cloud-family-ish).
- **`ai-anomalies`** — ledger outliers (heavy implied daily rate vs span; resurfaced-quiet patterns). Not replacement for full audit trails.

Everything above is **offline** — no external model API.

---

## v0.4 feature set

- **Cryptographic receipts** — Ed25519-signed append-only JSONL for store / inject / rotate / guided health verification; **`keysmith receipts --verify`** validates signatures offline.

---

## AI-style analysis commands

Examples (your output will vary):

### Scope scan

```bash
keysmith analyze-scopes
```

### Rotation suggestions

```bash
keysmith suggest-rotation
keysmith suggest-rotation --apply
```

### Credential groups

```bash
keysmith ai-groups
```

### Usage anomalies

```bash
keysmith ai-anomalies
```

---

## How it works

### Scanner

- Python: `os.getenv`, `os.environ`, `Settings.*` heuristics, pytest `skipif`, etc.
- Files: `.env.example`, `Dockerfile` `ENV`, `requirements*.txt` hints
- **`.env` stack:** `.env.example` → `.env` → `.env.local` (later overrides). Parser records **presence** (`"present"`) for non-placeholder values only — **values are never surfaced** in MCP/CLI output.

### Broker

Secrets are stored under keyring service name **`keysmith`**, keyed by **`sec://<project>/<slug>/api-key`**. `verify()` can report:

- **`valid`** — in keychain; optional provider HTTP health when not skipped  
- **`invalid`** — keychain value fails health check  
- **`present_dotenv`** — not in keychain but variable appears satisfied in layered env files (presence inference)  
- **`missing`** — neither  
- **`error`** — keychain / tooling error  

Each successful **read** from the keychain during `verify`, `inject`, or `store` also records the **handle URI + timestamp** under `~/.keysmith/usage.json` (never the secret value).

### MCP tools

| Tool | Role |
|------|------|
| `doctor` | Scan + status (includes `env_file_vars` summary and `credentials[*].status` / `location`) |
| `inject_credential` | `inject(handle, env_var)` in server process |
| `mint_admin_token` | Calls configured admin `/admin/token`; stores minted token as handle |

---

## Provider registry

Bundled YAML lists providers such as FEC and Congress.gov (`keysmith/providers/registry.yaml`) with signup URLs and HTTP health probes. Extend the file for additional services.

---

## Development

```bash
pip install -e ".[dev,mcp]"
pytest -q
ruff check keysmith tests
```

---

## Roadmap (sketch)

- Automated rotation execution (provider-specific)  
- Receipts / attestations for rotation events  
- More detection patterns (`BaseSettings`, monorepos)  
- Richer scope introspection when providers expose token metadata APIs

---

## Security

- Treat LLM + tools as **untrusted**; broker and OS keychain are **trusted** for storage.  
- No raw secrets in MCP JSON, doctor output, or successful connect/mint echoes.  
- Logging uses redaction filters; avoid `print` in stdio MCP paths (use `logging` to stderr).  
- Report sensitive issues via [GitHub Security Advisories](https://github.com/Swixixle/Keyp-Away/security) for this repository.

---

## Philosophy

> Secrets should move through systems with explicit handles — not through chat paste buffers.

KeySmith is **not** a full password manager; it is a **thin orchestration layer** for local dev and AI-assisted workflows.

---

## License

See [LICENSE](LICENSE).

---

## Credits

Built by [Alex Maksimovich](https://github.com/Swixixle) in the **Keyp-Away** repository (KeySmith package). Designed for workflows like **Open Case** civic data adapters.

---

## Contributing

1. Do **not** log or return raw secret values in PRs.  
2. Add tests for new scanner patterns or broker behavior.  
3. Update `keysmith/providers/registry.yaml` when adding provider metadata.

Issues: [github.com/Swixixle/Keyp-Away/issues](https://github.com/Swixixle/Keyp-Away/issues)
