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

    from keysmith.broker.vault import CredentialBroker, project_from_handle_uri
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

        Args:
            project_path: Project root directory. If omitted or empty, uses
                ``KEYSMITH_DEFAULT_PROJECT`` (fallback ``"."``).
            skip_health: If true, skip provider HTTP health checks.
        """

        if project_path is None or project_path.strip() == "":
            project_path = os.getenv("KEYSMITH_DEFAULT_PROJECT", ".")

        try:
            path = Path(project_path).expanduser().resolve()

            if not path.exists():
                return {
                    "error": f"Project path does not exist: {project_path}",
                    "suggested_path": os.getenv("KEYSMITH_DEFAULT_PROJECT"),
                }

            manifest = scan_project(path)
            broker = CredentialBroker(project_name=manifest.project)
            creds: dict[str, dict[str, object]] = {}

            for name, info in sorted(manifest.credentials.items()):
                handle_uri = _handle(manifest.project, name)
                in_env_file = manifest.env_file_vars.get(info.env.upper()) == "present"
                prov = None if skip_health else info.provider
                try:
                    status = broker.verify(
                        handle_uri,
                        provider_for_health=prov,
                        dotenv_reports_present=in_env_file,
                    )
                    if status.status == "valid":
                        final_status = "valid_keychain"
                        location = "keychain"
                    elif status.status == "present_dotenv":
                        final_status = "present_env_file"
                        location = "dotenv"
                    elif status.status == "invalid":
                        final_status = "invalid"
                        location = "keychain"
                    elif status.status == "error":
                        final_status = "error"
                        location = "none"
                    else:
                        final_status = "missing"
                        location = "none"

                    creds[name] = {
                        "env": info.env,
                        "detected_in": info.detected_in,
                        "provider": info.provider,
                        "scope": info.scope,
                        "handle_uri": handle_uri,
                        "status": final_status,
                        "location": location,
                        "fingerprint": status.fingerprint
                        if status.status in ("valid", "invalid", "present_dotenv")
                        else "",
                        "last_used": status.last_used,
                        "expires": status.expires,
                        "in_env_file": in_env_file,
                    }
                except Exception as e:
                    logging.getLogger(__name__).exception("doctor credential check failed slug=%s", name)
                    creds[name] = {
                        "env": info.env,
                        "status": "error",
                        "final_status": "error",
                        "location": "none",
                        "error": str(e),
                        "in_env_file": in_env_file,
                    }

            return {
                "project": manifest.project,
                "project_path": str(path),
                "env_file_vars": manifest.env_file_vars,
                "credentials": creds,
            }

        except Exception as e:
            logging.getLogger(__name__).exception("doctor scan failed")
            return {
                "error": f"Failed to scan project: {e!s}",
                "project_path": project_path,
            }

    @mcp_app.tool()
    async def inject_credential(handle: str, target_env: str) -> dict[str, object]:
        """Load the secret referenced by ``handle`` into ``target_env`` for this process only."""

        proj = project_from_handle_uri(handle)
        broker = CredentialBroker(project_name=proj) if proj else CredentialBroker()
        ok, err = broker.set_in_process(handle, target_env)
        if not ok:
            return {"injected": False, "env_var": target_env, "error": err or "inject failed"}
        return {"injected": True, "env_var": target_env}

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
        broker = CredentialBroker(project_name=project)
        h = broker.store(uri, raw.strip())
        return {"ok": True, "handle_uri": h.uri, "fingerprint": h.fingerprint}

    mcp_app.run(transport="stdio")
