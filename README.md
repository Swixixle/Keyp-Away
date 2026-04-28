# KeySmith

Local-first credential broker so assistants can reason about API keys via **handles and status**, not raw secrets. Core rule: secrets never appear in MCP tool results, CLI output (except hidden prompts), or logs.

## Install

Use a virtual environment ([PEP 668](https://peps.python.org/pep-0668/)–safe):

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,mcp]"
```

## Commands

Scan a repo and summarize keychain presence (and optional provider HTTP checks):

```bash
keysmith doctor --project-path /path/to/your/repo
```

Store a key interactively (`Paste API key` uses hidden input — nothing echoed):

```bash
keysmith connect fec --project-path /path/to/your/repo
```

Mint a short-lived admin JWT from Open Case (response JSON must expose a token field):

```bash
export KEYSMITH_OPEN_CASE_ADMIN_URL=https://your-app.example.com
keysmith mint-admin --ttl 60
```

Handles look like `sec://<project>/<slug>/api-key` and live in the OS keychain under service name `keysmith`.

## MCP (Claude Desktop / Cursor)

Install with the `mcp` extra, then configure a stdio server, for example:

`command`: path to `.venv/bin/keysmith-mcp`

Run `pip install "keysmith[mcp]"` in the env that runs the server.

Set **`KEYSMITH_DEFAULT_PROJECT`** on the MCP process (for example in Claude Desktop’s MCP server `env`) so the `doctor` tool can omit `project_path` and always scan that directory (for example `/Users/alexmaksimovich/Open-Case`).

## Layout

| Path | Role |
|------|------|
| `keysmith/scanner/detector.py` | Scans Python, `.env.example`, Dockerfile, `requirements*.txt` |
| `keysmith/broker/vault.py` | Keychain-backed `CredentialBroker`; `inject` loads `os.environ` only |
| `keysmith/cli/main.py` | `doctor`, `connect`, `mint-admin` |
| `keysmith/mcp/server.py` | FastMCP tools (`doctor`, `inject_credential`, `mint_admin_token`) |
| `keysmith/providers/registry.yaml` | Provider metadata & health URLs |

Development: `pytest`, `ruff check keysmith tests`.

Repository history: formerly the placeholder README for **Keyp-Away**.
