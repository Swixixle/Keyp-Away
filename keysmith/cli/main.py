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


@click.group()
def cli() -> None:
    """KeySmith — AI credential broker."""


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
        prov = cred_info.provider if not skip_health else None
        st = broker.verify(handle, provider_for_health=prov)
        sym = "✓" if st.status == "valid" else "✗"
        click.echo(f"{sym} {cred_info.env:30} {st.status:10} {st.fingerprint}")
        computed.append((cred_info, cred_name, st))

    click.echo("\nSuggested fixes:")
    for cred_info, slug, st in computed:
        if st.status == "missing":
            click.echo(f"  keysmith connect {slug} --project-path {path}")
        elif st.status == "invalid" and cred_info.provider:
            su = get_signup_url(str(cred_info.provider))
            if su:
                click.echo(f"  Replace or renew {cred_info.env} (signup: {su})")
            else:
                click.echo(f"  Replace or renew {cred_info.env}")


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

