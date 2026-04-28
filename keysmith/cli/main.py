"""KeySmith CLI."""

from __future__ import annotations

import logging
import os
from pathlib import Path

import click
import httpx

from keysmith.broker.vault import CredentialBroker, SecretHandle
from keysmith.logging_config import SecretRedactionFilter, configure_safe_logging
from keysmith.models import CredentialEntry, CredentialManifest
from keysmith.providers.loader import get_signup_url
from keysmith.scanner.detector import scan_project

configure_safe_logging()
_ROOT = logging.getLogger()
if not any(isinstance(f, SecretRedactionFilter) for f in _ROOT.filters):
    _ROOT.addFilter(SecretRedactionFilter())


def _handle_for(project: str, slug: str) -> str:
    return f"sec://{project}/{slug}/api-key"


def _resolve_cred_slug(manifest: CredentialManifest, name: str) -> str | None:
    trimmed = name.strip()
    cand = trimmed.lower()
    if cand in manifest.credentials:
        return cand
    target = trimmed.upper().replace("-", "_")
    for slug, ci in manifest.credentials.items():
        if ci.env.upper() == target:
            return slug
    return None


def _env_marked_present(manifest: CredentialManifest, env_var: str) -> bool:
    return manifest.env_file_vars.get(env_var.upper()) == "present"


@click.group()
def cli() -> None:
    """KeySmith — AI credential broker."""

@cli.command("install-hook")
@click.option("--repo-path", default=".", type=click.Path(exists=True, file_okay=False))
def install_hook(repo_path: str) -> None:
    """Install a git pre-commit hook that blocks likely secret literals in staged files."""

    from keysmith.hooks.pre_commit import install_hook as do_install

    do_install(Path(repo_path))


@cli.command("scrub-history")
@click.option("--dry-run", is_flag=True, help="Show what would be removed.")
def scrub_history(dry_run: bool) -> None:
    """Remove lines that look like secrets from ~/.bash_history, ~/.zsh_history, …"""

    from keysmith.scrub.history import scrub_all_history

    scrub_all_history(dry_run=dry_run)


@cli.command("audit-scope")
@click.option("--project-path", default=".", type=click.Path(exists=True, file_okay=False))
def audit_scope(project_path: str) -> None:
    """Warn when bundled providers list scopes but project usage looks read-only."""

    from keysmith.audit.scope import check_scope_overuse

    warnings = check_scope_overuse(Path(project_path).resolve())
    if not warnings:
        click.echo("No heuristic over-scope warnings (see provider registry scopes).")
        return

    click.echo(f"Potential over-scoping: {len(warnings)}\n")

    for w in warnings:
        click.echo(w.env_var)
        click.echo(f"  Assumed issued scope: {w.assumed_key_scope}")
        click.echo(f"  Code heuristic needs: {w.required_scope}")
        click.echo(f"  {w.severity}: {w.recommendation}")
        click.echo()


@cli.command("doctor")
@click.option("--project-path", default=".", type=click.Path(exists=True, file_okay=False))
@click.option(
    "--skip-health",
    is_flag=True,
    help="Only check keychain presence, not provider HTTP health.",
)
def doctor(project_path: str, skip_health: bool) -> None:
    """Scan project and show credential status."""
    path = Path(project_path).resolve()
    manifest = scan_project(path)
    broker = CredentialBroker()

    click.echo("Credential Status\n")

    computed: list[tuple[CredentialEntry, str, SecretHandle]] = []
    for cred_name, cred_info in sorted(manifest.credentials.items()):
        handle = _handle_for(manifest.project, cred_name)
        in_env = _env_marked_present(manifest, cred_info.env)
        prov = cred_info.provider if not skip_health else None
        st = broker.verify(
            handle,
            provider_for_health=prov,
            dotenv_reports_present=in_env,
        )
        if st.status == "valid":
            sym, label = "✓", "valid (keychain)"
        elif st.status == "present_dotenv":
            sym, label = "○", "present (.env)"
        elif st.status == "invalid":
            sym, label = "✗", "invalid"
        elif st.status == "error":
            sym, label = "✗", "error"
        else:
            sym, label = "✗", "missing"

        click.echo(f"{sym} {cred_info.env:30} {label:22} {st.fingerprint}")
        computed.append((cred_info, cred_name, st))

    click.echo("\nSuggested fixes:")
    for cred_info, slug, st in computed:
        in_env = _env_marked_present(manifest, cred_info.env)
        if st.status == "missing" and not in_env:
            click.echo(f"  keysmith connect {slug} --project-path {path}")
        elif st.status == "invalid" and cred_info.provider:
            su = get_signup_url(str(cred_info.provider))
            if su:
                click.echo(f"  Replace or renew {cred_info.env} (signup: {su})")
            else:
                click.echo(f"  Replace or renew {cred_info.env}")


@cli.command("setup")
@click.argument("provider_slug")
@click.option("--project-path", default=".", type=click.Path(exists=True, file_okay=False))
def setup(provider_slug: str, project_path: str) -> None:
    """Guided setup: open signup URL (optional), clipboard or hidden paste, then health check."""

    from keysmith.cli.guided import guided_setup

    if not guided_setup(provider_slug, Path(project_path)):
        raise click.Abort()


@cli.command("connect")
@click.argument("credential_name")
@click.option("--project-path", default=".", type=click.Path(exists=True, file_okay=False))
def connect(credential_name: str, project_path: str) -> None:
    """Store a credential in the OS keychain (input hidden)."""
    path = Path(project_path).resolve()
    manifest = scan_project(path)
    broker = CredentialBroker()
    slug = _resolve_cred_slug(manifest, credential_name)
    if slug is None:
        click.echo(
            f"Unknown credential '{credential_name}' for this project "
            f"(scanned as '{manifest.project}'). Run `keysmith doctor` first.",
            err=True,
        )
        raise SystemExit(1)
    env_name = manifest.credentials[slug].env
    handle = _handle_for(manifest.project, slug)
    click.echo(f"Connecting {env_name} (handle {handle})…")
    secret = click.prompt("Paste API key", hide_input=True)
    out = broker.store(handle, secret)
    click.echo(f"✓ Stored — {out.uri}  fingerprint {out.fingerprint}")


@cli.command("inject")
@click.argument("handle_uri")
@click.argument("target_env")
def inject(handle_uri: str, target_env: str) -> None:
    """Load a keychain-backed handle into TARGET_ENV for this shell process."""
    broker = CredentialBroker()
    ok = broker.inject(handle_uri, target_env)
    if not ok:
        click.echo(
            "Failed: unknown handle or no secret stored in OS keychain for this URI.",
            err=True,
        )
        raise SystemExit(1)
    click.echo(f"✓ Loaded into environment variable {target_env}")


@cli.command("mint-admin")
@click.option("--ttl", default=60, help="Token lifetime in minutes.")
@click.option(
    "--base-url",
    envvar="KEYSMITH_OPEN_CASE_ADMIN_URL",
    default=None,
    help="Open Case admin base URL (e.g. https://app.example.com).",
)
def mint_admin(ttl: int, base_url: str | None) -> None:
    """Mint a short-lived admin token and store it as a keychain handle (no raw token printed)."""
    base = base_url or os.environ.get("OPEN_CASE_ADMIN_URL")
    if not base:
        click.echo(
            "Set KEYSMITH_OPEN_CASE_ADMIN_URL or OPEN_CASE_ADMIN_URL to your Open Case base URL.",
            err=True,
        )
        raise SystemExit(1)
    url = base.rstrip("/") + "/admin/token"
    try:
        with httpx.Client(timeout=30.0) as client:
            r = client.post(url, json={"ttl_minutes": ttl})
    except Exception as e:
        click.echo(f"Request failed: {e}", err=True)
        raise SystemExit(1) from e

    if r.status_code >= 400:
        click.echo(f"Admin token mint failed ({r.status_code}).", err=True)
        raise SystemExit(1)

    data = {}
    try:
        data = r.json()
    except Exception:
        click.echo("Response was not JSON; cannot store token handle.", err=True)
        raise SystemExit(1)

    raw = (
        data.get("token")
        or data.get("access_token")
        or data.get("admin_token")
        or data.get("value")
        or ""
    )
    if not isinstance(raw, str) or not raw.strip():
        click.echo("JSON did not include a token field this CLI understands.", err=True)
        raise SystemExit(1)

    project = Path.cwd().resolve().name
    handle_uri = _handle_for(project, "open-case-admin-token")
    broker = CredentialBroker()
    h = broker.store(handle_uri, raw.strip())
    click.echo(f"✓ Stored admin token handle: {h.uri}")
    click.echo(f"  fingerprint {h.fingerprint}")

