"""KeySmith CLI."""

from __future__ import annotations

import logging
import os
from datetime import datetime
from pathlib import Path

import click
import httpx

from keysmith.broker.vault import CredentialBroker, SecretHandle, project_from_handle_uri, slug_from_handle_uri
from keysmith.logging_config import SecretRedactionFilter, configure_safe_logging
from keysmith.models import CredentialEntry, CredentialManifest
from keysmith.providers.loader import get_signup_url
from keysmith.scanner.detector import scan_project

from keysmith.cli.team_cmd import team_cli

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


def _broker_for_manifest(path: Path) -> CredentialBroker:
    return CredentialBroker(project_name=scan_project(path.resolve()).project)


def _sharing_hint(slug: str, provider: dict) -> str:
    slug_l = slug.lower()
    name = str(provider.get("name", "")).lower()
    cats = provider.get("credential_types") if isinstance(provider.get("credential_types"), list) else []
    if "gov" in slug_l or "fec" in slug_l or "congress" in slug_l:
        return "allowed"
    if "government" in name or "commission" in name or "election" in name:
        return "allowed"
    if cats and any(str(c).lower() in {"public_api", "government_api"} for c in cats):
        return "allowed"
    return "forbidden"


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


@cli.command("analyze-scopes")
@click.option("--project-path", default=".", type=click.Path(exists=True, file_okay=False))
def analyze_scopes(project_path: str) -> None:
    """Infer coarse API scope needs from Python httpx/requests usage toward registry hosts."""

    from keysmith.ai.scope_analyzer import analyze_all_scopes

    root = Path(project_path).resolve()
    click.echo("Analyzing HTTP usage patterns toward registry provider hosts…\n")

    results = analyze_all_scopes(root)

    if not results:
        click.echo("No API usage detected for bundled providers (or only low-confidence defaults).")
        return

    for provider_slug, requirement in sorted(results.items()):
        confidence_icon = "🟢" if requirement.confidence > 0.8 else "🟡"

        click.echo(f"{confidence_icon} {provider_slug}")
        click.echo(f"   Required scope: {requirement.required_scope}")
        click.echo(f"   Confidence: {requirement.confidence:.0%}")
        click.echo(f"   Reasoning: {requirement.reasoning}")

        if requirement.evidence:
            click.echo(f"   Evidence: {len(requirement.evidence)} API call(s)")
            for call in requirement.evidence[:2]:
                click.echo(f"     • {call.method} {call.endpoint} ({call.file}:{call.line})")

        click.echo()

@cli.command("audit-unused")
@click.option("--days", default=90, type=int, help="Stale threshold in days.")
def audit_unused(days: int) -> None:
    """List tracked handles not accessed in N+ days (requires prior verify/inject/store)."""

    from keysmith.audit.usage import check_unused_credentials

    unused = check_unused_credentials(days=days)
    if not unused:
        click.echo(f"No handles unused for {days}+ days (of those tracked in ~/.keysmith/usage.json).")
        return

    click.echo(f"Stale handles (unused {days}+ days): {len(unused)}\n")
    for handle, days_idle in unused:
        click.echo(handle)
        click.echo(f"  Roughly {days_idle} day(s) since last access")
        click.echo("  Consider rotating or deleting if unused.")
        click.echo()


@cli.command("suggest-rotation")
@click.option("--project-path", default=".", type=click.Path(exists=True, file_okay=False))
@click.option(
    "--apply",
    is_flag=True,
    help="Persist suggested policies to ~/.keysmith/rotation.json for manifest credentials only.",
)
def suggest_rotation(project_path: str, apply: bool) -> None:
    """Heuristic rotation intervals from scope scan, registry class, usage ledger, and .env hints."""

    from keysmith.ai.rotation_suggest import RotationSuggestion, suggest_all_rotations
    from keysmith.rotation.scheduler import RotationScheduler

    root = Path(project_path).resolve()
    click.echo("Analyzing credentials for rotation suggestions…\n")

    suggestions = suggest_all_rotations(root)

    if not suggestions:
        click.echo("No registry providers loaded; nothing to score.")
        raise SystemExit(0)

    manifest = scan_project(root)
    by_risk: dict[str, list[tuple[str, RotationSuggestion]]] = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
    }

    for slug, sug in suggestions.items():
        by_risk[sug.risk_level].append((slug, sug))

    scheduler = RotationScheduler() if apply else None

    for risk_level in ("critical", "high", "medium", "low"):
        items = by_risk[risk_level]
        if not items:
            continue
        icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}[risk_level]
        click.echo(f"{icon} {risk_level.upper()} ({len(items)} provider(s))\n")

        for slug, sug_t in sorted(items, key=lambda x: x[0]):
            click.echo(f"  {slug}")
            click.echo(f"    Suggested interval: {sug_t.suggested_days} days")
            click.echo(f"    Confidence: {sug_t.confidence:.0%}")
            click.echo(f"    {sug_t.reasoning}")
            if sug_t.factors:
                click.echo("    Factors:")
                for f in sug_t.factors:
                    click.echo(f"      • {f}")

            if apply and scheduler:
                if slug not in manifest.credentials:
                    click.echo("    (apply skipped: slug not in scanned manifest)")
                else:
                    handle = _handle_for(manifest.project, slug)
                    scheduler.set_policy(handle=handle, rotation_days=sug_t.suggested_days)
                    click.echo(f"    Policy applied for {handle}")

            click.echo()

    if not apply:
        click.echo("Tip: pass --apply to write policies for credentials present in the manifest scan.")


@cli.command("ai-groups")
@click.option("--project-path", default=".", type=click.Path(exists=True, file_okay=False))
def ai_groups(project_path: str) -> None:
    """Heuristic groups (tier / region / cloud family) from credential slug names."""

    from keysmith.ai.credential_graph import analyze_credential_relationships

    root = Path(project_path).resolve()
    click.echo("Analyzing credential slug groupings…\n")

    groups = analyze_credential_relationships(root)

    if not groups:
        click.echo("No groups detected (need multiple related slugs in the manifest).")
        return

    for group in groups:
        relationship_icon = {
            "tiered_access": "🔐",
            "regional": "🌍",
            "service_family": "📦",
        }.get(group.relationship, "🔗")
        click.echo(f"{relationship_icon} {group.group_name}")
        click.echo(f"   Type: {group.relationship}")
        click.echo(f"   Credentials: {', '.join(group.credentials)}")
        click.echo(f"   Note: {group.reasoning}")
        click.echo()


@cli.command("ai-anomalies")
@click.option("--days", default=30, type=int, help="Rough recency horizon for resurfaced-key hints.")
def ai_anomalies(days: int) -> None:
    """Flag unusual totals vs ledger span (frequency, quiet credentials touched again)."""

    from keysmith.ai.anomaly_detector import check_for_anomalies

    click.echo(f"Checking usage ledger for anomalies (~{days} day window for recency hints)…\n")

    anomalies = check_for_anomalies(lookback_days=days)

    if not anomalies:
        click.echo("No anomalies detected (or ledger empty).")
        return

    n = len(anomalies)
    click.echo(f"Found {n} anomaly report(s).\n")

    for anomaly in anomalies:
        severity_icon = {"high": "🔴", "medium": "🟡", "low": "🟢"}.get(anomaly.severity, "⚪")
        click.echo(f"{severity_icon} {anomaly.handle}")
        click.echo(f"   Type: {anomaly.anomaly_type}")
        click.echo(f"   {anomaly.description}")
        click.echo(f"   Baseline: {anomaly.baseline}")
        click.echo(f"   Observed: {anomaly.observed}")
        click.echo(f"   → {anomaly.recommendation}")
        click.echo()


@cli.command("receipts")
@click.option("--project-path", default=".", type=click.Path(exists=True, file_okay=False))
@click.option(
    "--verify",
    "do_verify",
    is_flag=True,
    help="Verify Ed25519 signatures on every line in the JSONL log.",
)
def receipts_cmd(project_path: str, do_verify: bool) -> None:
    """Show or verify append-only signed credential event receipts for the scanned project."""

    from keysmith.receipts.signing import ReceiptSigner, ReceiptLog

    root = Path(project_path).resolve()
    manifest = scan_project(root)
    receipt_log = ReceiptLog(manifest.project)
    all_receipts = receipt_log.read_all()

    if not all_receipts:
        click.echo("No receipts found for this project.")
        click.echo("Receipts are recorded when you connect, inject, rotate, or complete guided health checks.")
        return

    signer = ReceiptSigner(manifest.project)

    verify_map: dict[int, bool] = {}
    if do_verify:
        click.echo("Verifying receipt signatures…\n")
        for i, r in enumerate(all_receipts):
            verify_map[i] = signer.verify_receipt(r)
        valid = sum(1 for v in verify_map.values() if v)
        invalid = len(all_receipts) - valid
        click.echo(f"✓ {valid} valid receipt(s)")
        if invalid:
            click.echo(f"✗ {invalid} invalid receipt(s) (log may be tampered or key rotated)")
        click.echo()

    click.echo(f"Credential event receipts: {manifest.project}\n")
    icons = {
        "credential_connected": "🔗",
        "credential_rotated": "🔄",
        "credential_verified": "✓",
        "credential_injected": "💉",
        "credential_handed_off": "🤝",
    }

    for i, receipt in enumerate(all_receipts):
        event_type = str(receipt.get("event_type", ""))
        icon = icons.get(event_type, "📝")
        ts = receipt.get("timestamp", "")
        click.echo(f"{icon} {ts}")
        click.echo(f"   Event: {event_type}")
        click.echo(f"   Handle: {receipt.get('handle', '')}")
        meta = receipt.get("metadata") or {}
        if isinstance(meta, dict) and "fingerprint" in meta:
            click.echo(f"   Fingerprint: {meta['fingerprint']}")
        if do_verify:
            ok = verify_map[i]
            click.echo(f"   Signature: {'✓ valid' if ok else '✗ invalid'}")
        click.echo()


@cli.command("set-rotation")
@click.argument("credential_slug")
@click.option("--days", default=90, type=int, help="Rotate every N days.")
@click.option("--project-path", default=".", type=click.Path(exists=True, file_okay=False))
def set_rotation(credential_slug: str, days: int, project_path: str) -> None:
    """Set a rotation reminder schedule for a manifest credential."""

    from keysmith.rotation.scheduler import RotationScheduler

    path = Path(project_path).resolve()
    manifest = scan_project(path)
    slug = _resolve_cred_slug(manifest, credential_slug)
    if slug is None:
        click.echo(
            f"Unknown credential '{credential_slug}'. Run `keysmith doctor` first.",
            err=True,
        )
        raise SystemExit(1)
    handle = _handle_for(manifest.project, slug)
    RotationScheduler().set_policy(handle=handle, rotation_days=days)
    click.echo(f"Rotation schedule set for {handle} (every {max(1, days)} day(s)).")


@cli.command("check-rotation")
def check_rotation() -> None:
    """Show overdue and upcoming rotation reminders."""

    from keysmith.rotation.scheduler import rotation_cli_main

    raise SystemExit(rotation_cli_main())


@cli.command("rotation-done")
@click.argument("credential_slug")
@click.option("--project-path", default=".", type=click.Path(exists=True, file_okay=False))
def rotation_done(credential_slug: str, project_path: str) -> None:
    """Reset rotation timer after you replaced a credential in the OS keychain."""

    from keysmith.rotation.scheduler import RotationScheduler

    path = Path(project_path).resolve()
    manifest = scan_project(path)
    slug = _resolve_cred_slug(manifest, credential_slug)
    if slug is None:
        click.echo(f"Unknown credential '{credential_slug}'. Run `keysmith doctor` first.", err=True)
        raise SystemExit(1)
    handle = _handle_for(manifest.project, slug)
    scheduler = RotationScheduler()
    pol = scheduler._load().get(handle)
    if not pol:
        click.echo(f"❌ No rotation policy set for {handle}.", err=True)
        click.echo(f"   Set one with: keysmith set-rotation {slug} --days N")
        raise SystemExit(1)

    scheduler.mark_rotated(handle)
    updated = scheduler._load()[handle]
    next_rotation = datetime.fromisoformat(updated.next_rotation).strftime("%Y-%m-%d")
    click.echo(f"✅ Marked {handle} as rotated")
    click.echo(f"   Next rotation: {next_rotation}")


@cli.command("summary")
@click.option("--project-path", default=".", type=click.Path(exists=True, file_okay=False))
@click.option(
    "--skip-health",
    is_flag=True,
    help="Skip provider HTTP health validation (offline / CI scripts).",
)
def summary(project_path: str, skip_health: bool) -> None:
    """At-a-glance credential posture; runs HTTP validation when bundled providers expose checks.

    Health probes are enabled by default — pass ``--skip-health`` only when deliberately offline/faster scans.
    """
    from keysmith.audit.scope import check_scope_overuse
    from keysmith.audit.usage import check_unused_credentials
    from keysmith.rotation.scheduler import check_rotation_status

    path = Path(project_path).resolve()
    manifest = scan_project(path)
    broker = CredentialBroker()

    in_keychain = in_env_only = invalid_or_err = missing = 0
    prefix = f"sec://{manifest.project}/"
    proj = manifest.project

    for cred_name, cred_info in sorted(manifest.credentials.items()):
        handle = _handle_for(manifest.project, cred_name)
        in_env = _env_marked_present(manifest, cred_info.env)
        prov_for = None if skip_health else (cred_info.provider or cred_name)
        st = broker.verify(
            handle,
            provider_for_health=prov_for,
            dotenv_reports_present=in_env,
        )
        if st.status == "valid":
            in_keychain += 1
        elif st.status == "present_dotenv":
            in_env_only += 1
        elif st.status in ("invalid", "error"):
            invalid_or_err += 1
        else:
            missing += 1

    total = len(manifest.credentials)

    click.echo(f"Credential health summary: {proj}\n")
    click.echo(f"Total credentials detected: {total}")
    click.echo(f"  ✓ In keychain (validated): {in_keychain}")
    if invalid_or_err:
        click.echo(f"  ⚠️ Invalid/error: {invalid_or_err}")
    click.echo(f"  ○ In .env files: {in_env_only}")
    click.echo(f"  ✗ Missing: {missing}")
    click.echo()

    issues: list[str] = []
    unused = check_unused_credentials(days=90)
    unused_here = [(h, d) for h, d in unused if h.startswith(prefix)]
    if unused_here:
        issues.append(f"{len(unused_here)} credential(s) unused for 90+ days (usage ledger)")
    scopes = check_scope_overuse(path)
    if scopes:
        issues.append(f"{len(scopes)} over-scoped credential(s) (heuristic)")
    rot = check_rotation_status()
    overdue_here = [p for p in rot["overdue"] if p.handle.startswith(prefix)]
    upcoming_here = [p for p in rot["upcoming"] if p.handle.startswith(prefix)]
    if overdue_here:
        issues.append(f"🔴 {len(overdue_here)} credential(s) overdue for rotation")
    elif upcoming_here:
        issues.append(f"🟡 {len(upcoming_here)} credential(s) due soon")
    if invalid_or_err:
        issues.append(f"⚠️ {invalid_or_err} credential(s) failed health check or errored")

    if issues:
        click.echo("Issues found:")
        for line in issues:
            click.echo(f"  ⚠️  {line}")
        click.echo()
        click.echo("Run specific commands for details:")
        click.echo("  keysmith doctor")
        click.echo("  keysmith audit-unused")
        click.echo("  keysmith check-rotation")
    else:
        click.echo("✅ No issues detected")

    if skip_health:
        click.echo(
            "\n💡 Tip: Health checks skipped. Run without --skip-health to validate credentials against providers."
        )


@cli.command("generate-manifest")
@click.option("--project-path", default=".", type=click.Path(exists=True, file_okay=False))
@click.option(
    "--output",
    "-o",
    default=".keysmith/credentials.yaml",
    help="Destination path (.keysmith/credentials.yaml by default)",
)
@click.option(
    "--skip-health",
    is_flag=True,
    help="Emit status without running bundled HTTP probes",
)
def generate_manifest_cmd(project_path: str, output: str, skip_health: bool) -> None:
    """Generate ``credentials.yaml`` from the scanned manifest (hand-editable afterward)."""

    import yaml as _yaml

    from keysmith.providers.loader import load_provider_registry, provider_has_health_check

    root = Path(project_path).resolve()
    manifest = scan_project(root)
    registry = load_provider_registry().get("providers", {})
    broker = CredentialBroker()
    rp = sorted(manifest.credentials.items())

    click.echo(f"🔍 Scanning {root}")
    click.echo(f"Found {len(rp)} credential(s)\n")

    manifest_blob: dict[str, object] = {
        "project": manifest.project,
        "generated": datetime.now().isoformat(timespec="seconds"),
        "credentials": {},
    }
    credentials_out: dict[str, object] = {}
    analyzer = None
    for cred_slug, cred_info in rp:
        handle = _handle_for(manifest.project, cred_slug)
        prov_key = cred_info.provider or cred_slug
        pdata = registry.get(cred_slug) or registry.get(prov_key) or {}

        scope_str = "unknown"
        try:
            from keysmith.ai.scope_analyzer import ScopeAnalyzer

            analyzer = analyzer or ScopeAnalyzer(root)
            try:
                req = analyzer.analyze_provider(cred_slug)
                scope_str = req.required_scope
            except ValueError:
                pass
        except Exception:
            pass

        prov_for_health = None if skip_health else prov_key
        st = broker.verify(
            handle,
            provider_for_health=prov_for_health,
            dotenv_reports_present=_env_marked_present(manifest, cred_info.env),
        )

        click.echo(f"  {cred_slug}: {st.status}")

        entry: dict[str, object] = {
            "env": cred_info.env,
            "provider": cred_slug,
            "scope": scope_str,
            "status": st.status,
        }
        has_hc = provider_has_health_check(prov_key) if prov_key else False
        entry["probe"] = {"http_health_check_available": has_hc, "skipped": skip_health}

        if isinstance(pdata.get("docs_url"), str):
            entry["docs_url"] = pdata["docs_url"]
        if isinstance(pdata.get("signup_url"), str):
            entry["signup_url"] = pdata["signup_url"]

        rotation = pdata.get("rotation") if isinstance(pdata.get("rotation"), dict) else {}
        if isinstance(rotation.get("recommended_days"), int):
            entry["rotation_days"] = rotation["recommended_days"]
        if rotation.get("risk_level"):
            entry["risk_level"] = rotation["risk_level"]

        req_files = list(cred_info.required_for or cred_info.detected_in)
        if req_files:
            entry["required_for"] = sorted(req_files)

        envs = {"local": "optional", "staging": "optional", "production": "optional"}
        if st.status in ("valid", "invalid"):
            envs["staging"] = "required"
            envs["production"] = "required"
        entry["environments"] = envs

        entry["sharing"] = _sharing_hint(cred_slug, pdata)

        credentials_out[cred_slug] = entry

    manifest_blob["credentials"] = credentials_out

    out_path = Path(output)
    out_abs = out_path if out_path.is_absolute() else (root / out_path)
    out_abs.parent.mkdir(parents=True, exist_ok=True)
    text = _yaml.safe_dump(manifest_blob, sort_keys=False, allow_unicode=True, default_flow_style=False)
    out_abs.write_text(text, encoding="utf-8")

    try:
        rel_arg = out_abs.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        rel_arg = str(out_abs.resolve())
    click.echo("\nNext steps:")
    click.echo(f"  git add {rel_arg}")
    click.echo("  git commit -m \"Add credentials manifest\"")
    click.echo("\n💡 Tip: Check this file into git once reviewed.")


@cli.command("doctor")
@click.option("--project-path", default=".", type=click.Path(exists=True, file_okay=False))
@click.option(
    "--skip-health",
    is_flag=True,
    help="Skip provider HTTP probes (offline / CI only).",
)
@click.option(
    "--show-usage",
    is_flag=True,
    help="Append last-access ages and project-scoped rotation backlog.",
)
def doctor(project_path: str, skip_health: bool, show_usage: bool) -> None:
    """Scan credential status; HTTP probes run when registry entries include health endpoints."""

    from keysmith.audit.usage import UsageTracker
    from keysmith.providers.loader import provider_has_health_check

    path = Path(project_path).resolve()
    manifest = scan_project(path)
    broker = CredentialBroker()

    usage_tracker = UsageTracker() if show_usage else None

    proj_prefix = f"sec://{manifest.project}/"

    click.echo("Credential Status\n")

    computed: list[tuple[CredentialEntry, str, SecretHandle]] = []
    for cred_name, cred_info in sorted(manifest.credentials.items()):
        handle = _handle_for(manifest.project, cred_name)
        in_env = _env_marked_present(manifest, cred_info.env)
        prov_key = cred_info.provider or cred_name
        prov_for = None if skip_health else prov_key
        st = broker.verify(
            handle,
            provider_for_health=prov_for,
            dotenv_reports_present=in_env,
        )

        has_hc = bool(prov_key) and provider_has_health_check(prov_key) and not skip_health

        if st.status == "valid":
            sym, label = "✓", "valid (keychain)"
        elif st.status == "present_dotenv":
            sym, label = "○", "present (.env)"
        elif st.status == "invalid":
            sym, label = "✗", "invalid (keychain)"
        elif st.status == "error":
            sym, label = "✗", "error"
        else:
            sym, label = "✗", "missing"

        line = f"{sym} {cred_info.env:30} {label:28} {st.fingerprint}"
        if has_hc:
            if st.status == "valid":
                line += "  ✓ health OK"
            elif st.status == "invalid":
                line += "  ✗ health failed"
        elif not skip_health and st.status == "valid" and prov_key:
            line += "  (no HTTP probe)"

        if usage_tracker:
            usage = usage_tracker.get_usage(handle)
            if usage:
                try:
                    last_used = datetime.fromisoformat(usage.last_accessed)
                    days_ago = (datetime.now() - last_used).days
                    line += f"  (used {days_ago}d ago)"
                except ValueError:
                    pass

        click.echo(line)
        computed.append((cred_info, cred_name, st))

    if show_usage:
        from keysmith.rotation.scheduler import RotationScheduler

        overdue = [
            p
            for p in RotationScheduler().check_due()
            if str(p.handle).startswith(proj_prefix)
        ]
        if overdue:
            click.echo(f"\n⚠️  {len(overdue)} credential(s) overdue for rotation:")
            for pol in overdue:
                click.echo(f"   🔴 {pol.handle}")

    fixes: list[str] = []
    for cred_info, slug, st in computed:
        in_env = _env_marked_present(manifest, cred_info.env)
        if st.status == "missing" and not in_env:
            fixes.append(f"  keysmith setup {slug} --project-path {path}")
        elif st.status == "invalid" and cred_info.provider:
            su = get_signup_url(str(cred_info.provider))
            if su:
                fixes.append(f"  Renew {cred_info.env} (signup: {su})")
            else:
                fixes.append(f"  Renew or replace {cred_info.env}")

    if fixes:
        click.echo("\nSuggested fixes:")
        for row in fixes:
            click.echo(row)

    if skip_health:
        click.echo("\n💡 Tip: Health checks skipped. Run without --skip-health to validate credentials.")


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
    broker = _broker_for_manifest(path)
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


@cli.command("inject", context_settings={"ignore_unknown_options": True})
@click.argument("handle_uri")
@click.argument("target_env")
@click.argument("command", nargs=-1, type=click.UNPROCESSED)
@click.option(
    "--project-path",
    default=None,
    type=click.Path(exists=True, file_okay=False),
    help="Repo root containing .keysmith/rotation-policy.yaml (default: cwd or KEYSMITH_DEFAULT_PROJECT).",
)
@click.option(
    "--skip-rotation-check",
    is_flag=True,
    help="Bypass rotation enforcement (settings.enforce + grace) for this injection.",
)
def inject(
    handle_uri: str,
    target_env: str,
    command: tuple[str, ...],
    project_path: str | None,
    skip_rotation_check: bool,
) -> None:
    """Exec COMMAND with a keychain-backed handle resolved into TARGET_ENV in the child.

    The secret enters only the exec'd child's environment, never the calling
    shell. Usage: keysmith inject <handle> <ENV> -- <cmd> [args...]. On success
    this process is replaced by COMMAND.
    """
    from keysmith.broker.vault import resolve_rotation_policy_root

    proj = project_from_handle_uri(handle_uri)
    broker = CredentialBroker(project_name=proj) if proj else CredentialBroker()
    explicit_root = resolve_rotation_policy_root(Path(project_path).resolve()) if project_path else None

    ok, err = broker.inject(
        handle_uri,
        target_env,
        tuple(command),
        skip_rotation_check=skip_rotation_check,
        project_root_for_policy=explicit_root,
    )

    if not ok:
        assert err is not None
        click.echo(f"✗ {err}", err=True)
        if err == "Credential not found in keychain":
            click.echo(
                "Failed: unknown handle or no secret stored in OS keychain for this URI.",
                err=True,
            )
        elif "OVERDUE" in err:
            slug = slug_from_handle_uri(handle_uri) or "credential"
            click.echo("\nTo rotate:", err=True)
            click.echo(f"  keysmith setup {slug}", err=True)
            click.echo("\nOr bypass (NOT RECOMMENDED):", err=True)
            cmd_str = " ".join(command)
            click.echo(
                f"  keysmith inject {handle_uri} {target_env} --skip-rotation-check -- {cmd_str}",
                err=True,
            )
        raise SystemExit(1)

    # No success branch: a successful inject() replaces this process via
    # os.execvpe and never returns here.


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

    manifest = scan_project(Path.cwd().resolve())
    project = manifest.project
    handle_uri = _handle_for(project, "open-case-admin-token")
    broker = CredentialBroker(project_name=manifest.project)
    h = broker.store(handle_uri, raw.strip())
    click.echo(f"✓ Stored admin token handle: {h.uri}")
    click.echo(f"  fingerprint {h.fingerprint}")


cli.add_command(team_cli)

