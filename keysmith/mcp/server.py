"""MCP stdio server exposing KeySmith tools (metadata only — no raw secrets)."""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path


def main() -> None:
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as e:
        raise SystemExit('Install MCP support: pip install "keysmith[mcp]"') from e

    import httpx

    from keysmith.broker.vault import CredentialBroker
    from keysmith.scanner.detector import scan_project

    mcp_app = FastMCP("KeySmith")

    def _handle(project: str, slug: str) -> str:
        return f"sec://{project}/{slug}/api-key"

    @mcp_app.tool()
    async def doctor(
        project_path: str | None = None,
        skip_health: bool = False,
    ) -> dict[str, object]:
        """Scan project and return credential status (fingerprints — never secrets).

        If ``project_path`` is omitted, uses ``KEYSMITH_DEFAULT_PROJECT`` (default ".").
        Set ``KEYSMITH_DEFAULT_PROJECT`` in the MCP server's environment (e.g. Claude Desktop config).
        """

        if project_path is None or project_path.strip() == "":
            project_path = os.getenv("KEYSMITH_DEFAULT_PROJECT", ".")

        root = Path(project_path).expanduser().resolve()
        manifest = scan_project(root)
        broker = CredentialBroker()
        results: dict[str, dict[str, object]] = {}

        for name, info in sorted(manifest.credentials.items()):
            uri = _handle(manifest.project, name)
            prov = None if skip_health else info.provider
            st = broker.verify(uri, provider_for_health=prov)
            results[name] = {
                "env": info.env,
                "detected_in": info.detected_in,
                "provider": info.provider,
                "scope": info.scope,
                "handle_uri": uri,
                "status": st.status,
                "fingerprint": st.fingerprint,
                "last_used": st.last_used,
                "expires": st.expires,
            }

        return {"project": manifest.project, "credentials": results}

    @mcp_app.tool()
    async def inject_credential(handle: str, target_env: str) -> dict[str, object]:
        """Load the secret referenced by ``handle`` into ``target_env`` for this process only."""

        broker = CredentialBroker()
        ok = broker.inject(handle, target_env)
        return {"injected": ok, "env_var": target_env}

    @mcp_app.tool()
    async def mint_admin_token(project: str, ttl_minutes: int = 60) -> dict[str, object]:
        """Mint a short-lived admin token and store handle metadata only."""

        base = os.environ.get("KEYSMITH_OPEN_CASE_ADMIN_URL") or os.environ.get("OPEN_CASE_ADMIN_URL")
        if not base:
            return {
                "ok": False,
                "error": "Set KEYSMITH_OPEN_CASE_ADMIN_URL or OPEN_CASE_ADMIN_URL",
            }
        url = base.rstrip("/") + "/admin/token"
        try:
            with httpx.Client(timeout=30.0) as client:
                r = client.post(url, json={"ttl_minutes": ttl_minutes, "project": project})
        except Exception as e:
            return {"ok": False, "error": str(e)}
        if r.status_code >= 400:
            return {"ok": False, "status_code": r.status_code}
        try:
            data = r.json()
        except Exception:
            return {"ok": False, "error": "response was not JSON"}
        raw = (
            data.get("token")
            or data.get("access_token")
            or data.get("admin_token")
            or data.get("value")
            or ""
        )
        if not isinstance(raw, str) or not raw.strip():
            return {"ok": False, "error": "no token field"}
        uri = _handle(project, "open-case-admin-token")
        broker = CredentialBroker()
        h = broker.store(uri, raw.strip())
        return {"ok": True, "handle_uri": h.uri, "fingerprint": h.fingerprint}

    mcp_app.run(transport="stdio")
