# KeySmith

**Local-first credential workflow for AI-assisted development teams**

KeySmith helps developers using AI coding tools (Cursor, Claude Code, etc.) manage API credentials without accidentally leaking them in chat logs, prompts, or `.env` files.

## ⚠️ Security Status

KeySmith is a **working prototype** suitable for:

- ✅ Personal development workflows  
- ✅ Small trusted teams (2-5 people)  
- ✅ Non-critical API credentials  
- ✅ Learning and experimentation  

KeySmith is **NOT recommended** for:

- ❌ Production secrets at scale  
- ❌ Regulated environments (HIPAA, SOC2, PCI-DSS)  
- ❌ High-security contexts  
- ❌ Adversarial threat models  

**No formal security audit has been performed. Use at your own risk.**

For threat model and security assumptions, see [Threat model](docs/THREAT_MODEL.md). Coordinated disclosure notes live in [Security policy](docs/SECURITY.md).

---

## What Problem Does This Solve?

When building with AI coding assistants, credentials leak through new vectors:

**The Problem:**

```bash
# Developer working with Claude
You: "Here's my API key: sk-abc123... can you help debug this?"
Claude: [Now has your production API key in training data]

# Or worse
git add .env
git commit -m "quick fix"
# Oops, API keys in git history forever
```

**Common pain points:**

- Pasting API keys in AI chat to get help  
- `.env` files scattered across projects  
- No idea which credentials are expired/invalid  
- Team members DM'ing keys in Slack  
- No rotation discipline  
- Silent adapter failures (wrong/missing keys)  

**KeySmith's approach:**

- Credentials stay in OS keychain (never in AI context)  
- AI works with handles (`sec://project/provider/api-key`), not raw secrets  
- Health checks detect invalid keys before runtime  
- Git-based team sharing with age-encryption  
- Rotation reminders with optional enforcement  
- Cryptographic audit trail (Ed25519 receipts)  

---

## Quick Start (5 Minutes)

### Install

```bash
git clone https://github.com/Swixixle/Keyp-Away.git
cd Keyp-Away
python3 -m venv .venv
source .venv/bin/activate  # or `.venv\Scripts\activate` on Windows
pip install -e ".[dev]"
```

### Scan Your Project

```bash
cd ~/your-project
keysmith summary

# Output:
# Credential Health Summary: your-project
# Total credentials detected: 12
#   ✓ In keychain (validated): 0
#   ○ In .env files: 5
#   ✗ Missing: 7
```

### Set Up a Credential

```bash
keysmith setup github
# → Browser opens to GitHub token page
# → Copy token
# → KeySmith auto-detects clipboard
# → Stores in OS keychain
# → Runs health check
# ✓ Stored and verified
```

### View Status

```bash
keysmith doctor

# ✓ GITHUB_TOKEN          valid (keychain)    ghp_...xJ9K
# ○ OPENAI_API_KEY        present (.env)      —
# ✗ ANTHROPIC_API_KEY     missing             —
```

### Daily Use

```bash
# Check what's missing
keysmith summary

# Set up missing credentials
keysmith setup anthropic

# Check rotation status
keysmith check-rotation

# View audit trail
keysmith receipts
```

---
## Core Features

### 1. AI-Safe Credential Handling

**Problem:** AI assistants cannot help with authentication if secrets are withheld from context, yet typing secrets into chat risks exposure.

**Solution:** MCP (Model Context Protocol) integration with opaque handles (`sec://...`) so tools can introspect **presence and lifecycle** without transmitting raw secrets.

**How it works:**

```python
# In your code
import os

fec_key = os.getenv("FEC_API_KEY")

# KeySmith scans references, stores secrets in OS keychain, and MCP surfaces handles only:
# sec://project/fec/api-key
```

**MCP Integration (Claude Desktop):**

```json
{
  "mcpServers": {
    "keysmith": {
      "command": "/path/to/keysmith-mcp",
      "env": {
        "KEYSMITH_DEFAULT_PROJECT": "/path/to/project"
      }
    }
  }
}
```

### 2. Multi-Signal Scanner

Detects credential references across common Python idioms plus `.env` / Dockerfile / tests (project-dependent—see manifests and scanner docs).

### 3. Guided Setup

Use `keysmith setup <slug>` for browser + clipboard-guided flows toward provider dashboards.

### 4. Health Checks

Preferentially validates keychain-held secrets via provider checks when wired in registry (not every provider has an HTTP ping).

### 5. Cryptographic Receipts (v0.4+)

Several lifecycle paths append Ed25519-signed JSON lines under `~/.keysmith/receipts/<project>.jsonl` for connect / inject / rotate / guided-health completion.

See `keysmith receipts` and `--verify`.

### 6. Team Collaboration (v0.5+)

Git-based YAML + `.keysmith/secrets/*.age` ciphertext and repo-local receipts under `.keysmith-receipts/`.

Uses **age** (install separately) — no SaaS prerequisite.

Team policies example (`rotation-policy.yaml`):

```yaml
policies:
  fec:
    rotation_days: 90
    risk_level: medium

settings:
  enforce: true          # Block inject when overdue beyond grace
  grace_period_days: 7
```

### 7. Rotation Management

Suggestions via `keysmith suggest-rotation` (+ optional `--apply` heuristics).  

**Inject enforcement (opt-in):** YAML `enforce` + reminders in `~/.keysmith/rotation.json`.

**Note:** Enforcement is friction at the KeySmith `inject` boundary, not OS kernel policy. Bypass includes `--skip-rotation-check`. Successful injects emit `credential_injected` receipts, but payloads **do not** currently record bypass vs enforced inject—assume process review rather than relying on receipt metadata alone.

### 8. Usage Tracking & Anomaly Detection

`audit-unused`, `ai-anomalies`, etc.—**offline ledger heuristics** (no upstream LLM API).

---
## Architecture

### Security Model

**Three layers:**

1. **Storage:** OS keychain (platform-dependent backends).
2. **Access:** Credential broker + scanners + reminders.
3. **AI Integration:** MCP returns metadata/handles—not raw secrets from KeySmith-managed paths.

**Key principles:**

- Prefer keychain-backed storage for tooling flows (vs dotenv-only presence checks).  
- Handles (`sec://...`) travel through docs/MCP/logs more safely than pasted secrets—**not** magic against a determined local attacker.

**Protects partly against:**

- Accidental spills into AI chat/logs (when MCP/handle workflow is respected).  
- Unclear drift on rotation timelines (human process + reminders).  
- Receipt tampering (append-only logs with signatures—**local hygiene**, not quorum consensus).

**Does not protect against:**

- Full local compromise (`--skip-rotation-check`, direct keychain access, malware).

See [Threat model](docs/THREAT_MODEL.md).

### Directory Structure

```
your-project/
├── .keysmith/
│   ├── team.yaml
│   ├── credentials.yaml
│   ├── rotation-policy.yaml
│   └── secrets/              # optional age blobs
├── .keysmith-receipts/
│   └── events.jsonl          # repo-local team-ish receipts when used
├── .gitignore               # tailor for secrets/*.age policy

~/.keysmith/
├── usage.json
├── receipts/
│   └── <project>.jsonl
├── rotation.json
└── team-identity.age       # decrypt path for shares
```

---

## CLI Reference

### Core Commands

| Command | Description |
|---------|-------------|
| `keysmith summary` | Overall credential posture |
| `keysmith doctor` | Detailed scans + statuses |
| `keysmith setup <provider>` | Guided setup flows |
| `keysmith connect <provider>` | Manual store prompts |
| `keysmith inject <handle> <env>` | Inject OS keychain handle into env (optional rotation enforcement) |
| `keysmith receipts [--verify]` | View or verify receipts |

### Team Commands (v0.5+)

| Command | Description |
|---------|-------------|
| `keysmith team init` | Scaffold YAML + receipts dir + identity |
| `keysmith team status` | Repo + YAML vs keychain / `.env` `.age` |
| `keysmith team share <slug>` | Produce `.age`, append team receipts |
| `keysmith team receive <slug>` | Decrypt ciphertext into OS keychain |
| `keysmith team check-rotation` | Compare rotation YAML vs local ledger |

### Audit & Analysis

| Command | Description |
|---------|-------------|
| `keysmith analyze-scopes` | Heuristic HTTP scopes |
| `keysmith suggest-rotation` | Suggestions (`--apply` optional) |
| `keysmith ai-groups` | Pattern-ish grouping story |
| `keysmith ai-anomalies` | Ledger noise hints |
| `keysmith audit-unused --days N` | Stale handle hints |
| `keysmith check-rotation` | Personal backlog |

### Safety Tools

| Command | Description |
|---------|-------------|
| `keysmith install-hook` | Pre-commit heuristic |
| `keysmith scrub-history` | Backup + scrub backups |

---

## Team Workflow Example

### Initial Setup

```bash
cd ~/project
mkdir -p .keysmith
cp examples/team/team.yaml .keysmith/
cp examples/team/rotation-policy.yaml .keysmith/

vim .keysmith/team.yaml

keysmith team init
keysmith team share fec
git add .keysmith/ .keysmith-receipts/
git commit -m "Initialize team credential sharing"
git push
```

### New Member

```bash
git clone https://github.com/yourteam/project.git
cd project
keysmith team init
# → share pubkey with lead, wait for team.yaml update
git pull
keysmith team receive fec
keysmith summary
```

### Daily Ops

```bash
keysmith team check-rotation
keysmith setup fec
keysmith team share fec
git add .keysmith/secrets/fec.age .keysmith-receipts/
git commit -m "Rotate FEC credential"
git push
# peers: git pull && keysmith team receive fec
```

---
## AI Features (Offline Heuristics)

**Important:** These are **offline pattern-matching heuristics**, not LLM API calls.

### Scope Detection

`keysmith analyze-scopes` inspects httpx/requests usage against registry hosts.

### Rotation Suggestions

`keysmith suggest-rotation` merges registry metadata, scope scan, usage ledger, `.env` presence.

### Credential Grouping

`keysmith ai-groups` reports naming-pattern clusters (not cloud IAM magic).

### Anomaly Detection

`keysmith ai-anomalies` reads local usage JSON for coarse dormancy / burst shapes.

**No external model API. No training data. Runs offline.**

---

## Installation

### Requirements

- **Python 3.11+** (see `pyproject.toml`)
- macOS, Linux, or Windows (keyring backends vary)
- Team sharing: install [`age`](https://github.com/FiloSottile/age)

### Basic Install

```bash
pip install -e "."
```

### With Development Tools

```bash
pip install -e ".[dev]"
```

### With Team Dependencies Group

```bash
pip install -e ".[team]"   # declares intent; YAML already ships as core dependency
brew install age # macOS
```

### MCP (Claude Desktop)

```bash
pip install -e ".[mcp]"
```

Point `command` at your venv-resolved `/absolute/path/.venv/bin/keysmith-mcp` and set `KEYSMITH_DEFAULT_PROJECT`.

---

## Provider Registry

`keysmith/providers/registry.yaml` declares docs + health pings + rotation hints—extend freely for non-bundled services.

---

## Testing

```bash
pytest -q
```

Current automated tests are **narrow** sanity checks—not a security proof.

Coverage highlights (see `/tests`): broker receipts, scanners, MCP wiring, scheduler edges, representative team flows—**explicitly incomplete** versus adversarial goals.

---

## Limitations & Known Issues

See [Threat model](docs/THREAT_MODEL.md).

High level:

1. Not audited end-to-end.  
2. Enforcement is procedural friction.  
3. Python-centric scanner fidelity varies by project shape.  
4. Manual rotations at upstream providers remain your responsibility.

---

## Roadmap

Explicit **non-goals:** managed cloud sync tenancy, sprawling RBAC product, kernel modules.

Near-term pragmatism: bugfixes, sharper docs/tests, iterative registry growth.

---

## Contributing

Issues + small PRs welcome—keep patches focused; include tests when touching behavior knobs.

---

## Philosophy

Receipts attest to **operations KeySmith witnessed**, not third-party attestations—“receipts, not verdicts.”

---

## License

MIT — see [`LICENSE`](LICENSE).

---

## Acknowledgments

Built by Alex Maksimovich — see README history for sibling projects (**Open Case**, **PUBLIC EYE** inspirations).

Credits: **age**, **SOPS**, **1Password** ergonomics inspirations, MCP community.

---

## Support

GitHub Issues / Discussions. **Best effort**—no SLA.

---

## FAQ

**Q: Production-grade?**
A: **No**—iterate with established secret managers once stakes rise.

**Q: Why not Vault/Doppler/etc.?**
A: Those excel at centrally governed secrets—KeySmith stitches local dev ergonomics + git coordination + MCP affordances cheaply—but only if the tradeoffs suit you.

**Q: What about CI/CD runners?**
A: Prefer your platform’s sealed secrets primitives; KeySmith targets interactive developer hosts.

---

**Built with honesty, shipped with humility.**
