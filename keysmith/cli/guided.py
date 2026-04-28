"""Guided credential setup with minimal typing (browser open + optional clipboard)."""

from __future__ import annotations

import time
import webbrowser
from pathlib import Path

import click

from keysmith.broker.vault import CredentialBroker
from keysmith.models import CredentialManifest
from keysmith.providers.loader import load_provider_registry, run_health_check
from keysmith.scanner.detector import scan_project


def _provider_entry(provider_key: str) -> dict | None:
    data = load_provider_registry().get("providers", {})
    return data.get(provider_key) if isinstance(data, dict) else None


def _storage_slug(manifest: CredentialManifest, registry_key: str) -> str:
    """Prefer manifest slug that maps to this provider (e.g. congress → congress_gov)."""
    k = registry_key.strip()
    for slug, ent in manifest.credentials.items():
        if ent.provider == k:
            return slug
    kl = k.lower()
    if kl in manifest.credentials:
        return kl
    return kl


def guided_setup(registry_key: str, project_path: Path) -> bool:
    """Open signup URL, then store key via clipboard heuristic or hidden prompt."""
    manifest = scan_project(project_path.resolve())
    provider = _provider_entry(registry_key)
    providers = load_provider_registry().get("providers", {})
    avail = ", ".join(sorted(providers.keys())) if isinstance(providers, dict) else ""

    if not provider:
        click.echo(f"Unknown provider: {registry_key}", err=True)
        if avail:
            click.echo(f"Available registry keys: {avail}", err=True)
        else:
            click.echo("Could not load provider registry.", err=True)
        return False

    pname = str(provider.get("name", registry_key))
    signup_url = provider.get("signup_url")
    slug = _storage_slug(manifest, registry_key)

    try:
        click.clear()
    except Exception:
        pass

    click.echo("=" * 60)
    click.echo(f"  KeySmith Guided Setup: {pname}")
    click.echo("=" * 60)
    click.echo()
    click.echo("What we're doing:")
    click.echo(f"   Storing credentials for registry key “{registry_key}” ({pname}).")
    click.echo(f"   Project scanned as: {manifest.project}")
    click.echo(f"   Keychain handle slug: {slug}")
    click.echo()

    if not signup_url:
        click.echo("No signup_url in registry; continue with manual paste only.", err=True)
    else:
        click.echo("Step 1: Get your API key")
        click.echo(f"   Signup/docs URL: {signup_url}")
        click.echo()

        if click.confirm("Open signup page in your default browser?", default=True):
            opened = webbrowser.open(signup_url)
            if opened:
                click.echo("   Browser open requested.")
            else:
                click.echo("   Browser could not be opened; use the URL above.")
        click.echo()

    click.echo("   Tip: Sign up or log in, create an API key, then copy it (e.g. Cmd+C).")
    click.echo()
    click.pause("Press Enter when you've copied your key.")
    click.echo()

    secret: str | None = None
    try:
        import pyperclip

        raw = pyperclip.paste()
        clipboard = raw.strip() if isinstance(raw, str) else ""
        looks_like_key = (
            15 <= len(clipboard) <= 512
            and "\n" not in clipboard
            and " " not in clipboard.strip()
        )
        if looks_like_key:
            head = clipboard[:6]
            tail = clipboard[-6:]
            mask = f"{head}⋯{tail}" if len(clipboard) > 12 else "⋯⋯"
            click.echo("Clipboard snippet (masked):")
            click.echo(f"   {mask}")
            click.echo(f"   (length {len(clipboard)})")
            click.echo()
            if click.confirm("Use this clipboard value?", default=True):
                secret = clipboard
    except ImportError:
        pass
    except Exception:
        pass

    if not secret:
        click.echo("Paste your API key (hidden):")
        secret = click.prompt("   ", hide_input=True, confirmation_prompt=False)

    if not secret or not secret.strip():
        click.echo("No secret entered; aborted.", err=True)
        return False

    broker = CredentialBroker()
    handle = f"sec://{manifest.project}/{slug}/api-key"
    result = broker.store(handle, secret.strip())
    click.echo()
    click.echo("Stored in OS keychain (value not echoed).")
    click.echo(f"   Handle: {result.uri}")
    click.echo(f"   Fingerprint: {result.fingerprint}")
    click.echo()

    hc = provider.get("health_check")
    if hc:
        click.echo("Testing key against provider health check…")
        time.sleep(0.3)
        ok = run_health_check(registry_key, secret.strip())
        if ok:
            click.echo("   Health check: OK")
        else:
            click.echo("   Health check failed or unreachable — verify the key in the dashboard.")
    click.echo()

    click.echo("=" * 60)
    click.echo(f"  Done: {pname}")
    click.echo("=" * 60)
    return True

