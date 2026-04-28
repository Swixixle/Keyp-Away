"""CLI: minimal git-first team workflow (YAML + optional age-shared secrets)."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import click
import yaml

from keysmith.broker.vault import CredentialBroker
from keysmith.receipts.signing import ReceiptSigner, TeamReceiptLog
from keysmith.rotation.scheduler import RotationScheduler
from keysmith.scanner.detector import scan_project
from keysmith.team.paths import credentials_yaml, rotation_policy_yaml, secrets_dir
from keysmith.team.sharing import SecretSharer, TeamKeyManager
from keysmith.team.templates import CREDENTIALS_YAML, ROTATION_POLICY_YAML, TEAM_YAML


@click.group("team")
def team_cli() -> None:
    """Local-first team coordination (.keysmith/*.yaml + optional ``age`` file sharing)."""


def _resolve_root(project_path: str) -> Path:
    return Path(project_path).resolve()


def _handle(project: str, slug: str) -> str:
    return f"sec://{project}/{slug}/api-key"


def _load_yaml(path: Path) -> dict[str, Any]:
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    return raw if isinstance(raw, dict) else {}


def _team_members(cfg: dict[str, Any]) -> list[dict[str, Any]]:
    try:
        m = cfg.get("team") or cfg
        ms = (m.get("members") if isinstance(m, dict) else None) or []
        return [x for x in ms if isinstance(x, dict)]
    except Exception:
        return []


def _member_pubkeys(cfg: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for m in _team_members(cfg):
        pk = str(m.get("pubkey", "")).strip()
        if pk.startswith("age1"):
            out.append(pk)
    return out


@team_cli.command("init")
@click.option("--project-path", default=".", type=click.Path(exists=True, file_okay=False))
def team_init(project_path: str) -> None:
    """Create ``.keysmith/``, template YAML files, ``.keysmith-receipts/``, and an age identity (needs ``age``)."""
    root = _resolve_root(project_path)
    kd = root / ".keysmith"
    kd.mkdir(exist_ok=True)
    secrets_dir(root).mkdir(parents=True, exist_ok=True)
    (root / ".keysmith-receipts").mkdir(exist_ok=True)

    tm = kd / "team.yaml"
    if not tm.exists():
        tm.write_text(TEAM_YAML, encoding="utf-8")
        click.echo(f"Wrote {tm}")
    else:
        click.echo(f"Skipping existing {tm}")

    cr = kd / "credentials.yaml"
    if not cr.exists():
        cr.write_text(CREDENTIALS_YAML, encoding="utf-8")
        click.echo(f"Wrote {cr}")

    rp = kd / "rotation-policy.yaml"
    if not rp.exists():
        rp.write_text(ROTATION_POLICY_YAML, encoding="utf-8")
        click.echo(f"Wrote {rp}")

    (secrets_dir(root) / ".gitkeep").write_text("", encoding="utf-8")

    try:
        pub, prv = TeamKeyManager.generate_keypair()
    except RuntimeError as e:
        click.echo(str(e), err=True)
        click.echo("YAML templates created; install age later and run ``age-keygen``.")
        raise SystemExit(1) from e

    out = TeamKeyManager.store_identity(prv)
    click.echo(f"Stored age identity file: {out}")
    click.echo(f"Your age public key: {pub}")
    click.echo("Add this pubkey to .keysmith/team.yaml under your member entry, commit, push.")


@team_cli.command("status")
@click.option("--project-path", default=".", type=click.Path(exists=True, file_okay=False))
def team_status(project_path: str) -> None:
    """Show ``team.yaml``, roles, and credential coverage (keychain / .env / .age)."""
    root = _resolve_root(project_path)
    tc_path = root / ".keysmith" / "team.yaml"
    if not tc_path.exists():
        click.echo(f"No team config — run keysmith team init ({tc_path})", err=True)
        raise SystemExit(1)

    cfg = _load_yaml(tc_path)
    tname = (cfg.get("team") or {}).get("name") or cfg.get("name") or "unknown"
    members = _team_members(cfg)
    manifest = scan_project(root)
    broker = CredentialBroker()

    click.echo(f"Team: {tname}")
    click.echo(f"Members: {len(members)} checked in")

    for m in members:
        role = str(m.get("role", "?"))
        name = str(m.get("name", "?"))
        icon = "👑" if role == "admin" else "👤"
        click.echo(f"  {icon} {name} ({role})")

    tb = cfg.get("team") if isinstance(cfg.get("team"), dict) else cfg
    sharing_block = tb.get("credential_sharing") if isinstance(tb, dict) else {}
    shared: list[str] = []
    if isinstance(sharing_block, dict):
        sc = sharing_block.get("shared_credentials")
        if isinstance(sc, list):
            shared = [str(x).strip() for x in sc if str(x).strip()]

    click.echo()
    req: set[str] = set(manifest.credentials.keys())
    cred_yaml = credentials_yaml(root)
    if cred_yaml.exists():
        cyc = _load_yaml(cred_yaml).get("credentials")
        if isinstance(cyc, dict) and cyc:
            req |= set(cyc.keys())

    connected = missing = dotenv_ok = inv = 0
    for slug in sorted(req):
        info = manifest.credentials.get(slug)
        env_name = (info.env if info else "") or ""
        env_pres = manifest.env_file_vars.get(env_name.upper()) == "present" if env_name else False
        handle = _handle(manifest.project, slug)
        st = broker.verify(handle, dotenv_reports_present=env_pres)
        if st.status == "valid":
            connected += 1
        elif st.status == "present_dotenv":
            dotenv_ok += 1
        elif st.status in ("invalid", "error"):
            inv += 1
        else:
            missing += 1

    click.echo(f"Credentials (scanner + credentials.yaml): resolved {len(req)} slug(s)")
    click.echo(f"  ✓ keychain ok: {connected}")
    click.echo(f"  ○ .env satisfies: {dotenv_ok}")
    click.echo(f"  ⚠️  invalid/err: {inv}")
    click.echo(f"  ✗ missing: {missing}")
    click.echo()

    click.echo(f"Shared slugs (team.yaml credential_sharing.shared_credentials): {len(shared)}")
    if not shared:
        click.echo("  (none — edit credential_sharing.shared_credentials)")
        return

    sr = secrets_dir(root)
    for slug in shared:
        fp = sr / f"{slug}.age"
        st = broker.verify(_handle(manifest.project, slug))
        if fp.exists():
            extra = "encrypted .age on disk"
            if st.status == "valid":
                click.echo(f"  ✓ {slug} — keychain + {extra}")
            else:
                click.echo(f"  📦 {slug} — {extra} (run: keysmith team receive {slug})")
        elif st.status == "valid":
            click.echo(f"  ✓ {slug} — keychain (no .age committed)")
        else:
            click.echo(f"  ✗ {slug} — missing from keychain and no .age")


@team_cli.command("share")
@click.argument("credential_slug")
@click.option("--project-path", default=".", type=click.Path(exists=True, file_okay=False))
@click.option(
    "--as",
    "actor_email",
    envvar="KEYSMITH_TEAM_ACTOR",
    default=None,
    help="Recorded on team receipt (defaults to KEYSMITH_TEAM_ACTOR)",
)
def team_share(credential_slug: str, project_path: str, actor_email: str | None) -> None:
    """Encrypt keychain credential to ``.keysmith/secrets/<slug>.age`` for listed member pubkeys."""
    root = _resolve_root(project_path)
    tc_path = root / ".keysmith" / "team.yaml"
    if not tc_path.exists():
        click.echo("No .keysmith/team.yaml — run keysmith team init", err=True)
        raise SystemExit(1)

    cfg = _load_yaml(tc_path)
    pks = _member_pubkeys(cfg)
    if not pks:
        click.echo("No valid age pubkeys found under team.members[].pubkey", err=True)
        raise SystemExit(1)

    manifest = scan_project(root)
    handle = _handle(manifest.project, credential_slug.strip())
    sharer = SecretSharer(root / ".keysmith")
    click.echo(f"Encrypting `{credential_slug}` for {len(pks)} recipient(s)…")

    dest = sharer.share_credential(handle, pks)
    click.echo(f"✓ Wrote {dest}")
    signer = ReceiptSigner(manifest.project)
    trek = TeamReceiptLog(root)
    meta: dict[str, Any] = {
        "cipher": "age",
        "path_relative": str(dest.relative_to(root)),
        "recipient_count": len(pks),
    }
    trek.append(
        signer.sign_event(
            "credential_shared",
            handle,
            meta,
            actor=actor_email,
        )
    )
    click.echo("Recorded team receipt under .keysmith-receipts/events.jsonl")


@team_cli.command("receive")
@click.argument("credential_slug")
@click.option("--project-path", default=".", type=click.Path(exists=True, file_okay=False))
def team_receive(credential_slug: str, project_path: str) -> None:
    """Decrypt ``.keysmith/secrets/<slug>.age`` into the OS keychain."""
    identity = Path.home() / ".keysmith" / "team-identity.age"
    if not identity.exists():
        click.echo(f"Missing identity {identity}; run keysmith team init", err=True)
        raise SystemExit(1)

    root = _resolve_root(project_path)
    sharer = SecretSharer(root / ".keysmith")
    enc = secrets_dir(root) / f"{credential_slug.strip()}.age"
    if not enc.exists():
        click.echo(f"Missing {enc}", err=True)
        raise SystemExit(1)

    manifest = scan_project(root)
    secret = sharer.decrypt_to_string(enc, identity)
    handle = _handle(manifest.project, credential_slug.strip())
    broker = CredentialBroker(project_name=manifest.project)
    broker.store(handle, secret)
    click.echo(f"✓ Imported into OS keychain: {handle}")


@team_cli.command("check-rotation")
@click.option("--project-path", default=".", type=click.Path(exists=True, file_okay=False))
def team_check_rotation(project_path: str) -> None:
    """Compare ``rotation-policy.yaml`` hints with saved rotation reminders."""

    root = _resolve_root(project_path)
    pol_path = rotation_policy_yaml(root)
    if not pol_path.exists():
        click.echo(f"No {pol_path} — run keysmith team init", err=True)
        raise SystemExit(1)

    raw = _load_yaml(pol_path)
    policies = raw.get("policies")
    if not isinstance(policies, dict) or not policies:
        click.echo("rotation-policy.yaml has no `policies` entries.")
        return

    manifest = scan_project(root)
    sched = RotationScheduler()
    local = sched._load()
    now = datetime.now(timezone.utc)

    click.echo(f"Team rotation checklist (manifest project={manifest.project})\n")

    for slug, row in sorted(policies.items()):
        if not isinstance(row, dict):
            continue
        td_raw = row.get("rotation_days")
        td: int | None = int(td_raw) if isinstance(td_raw, (int, float)) else None
        handle = _handle(manifest.project, str(slug))
        explain = str(row.get("reason", "")).strip()
        pol_obj = local.get(handle)
        if td is not None and explain:
            yhint = f"{td}d — {explain}"
        elif td is not None:
            yhint = f"{td}d target"
        else:
            yhint = "see YAML"

        if not pol_obj:
            click.echo(f"○ {slug}: no local policy yet (`keysmith set-rotation {slug} --days …`)")
            click.echo(f"   Team file: {yhint}")
            click.echo()
            continue

        try:
            nxt = datetime.fromisoformat(pol_obj.next_rotation.replace("Z", "+00:00"))
            if nxt.tzinfo is None:
                nxt = nxt.replace(tzinfo=timezone.utc)
        except ValueError:
            click.echo(f"? {slug}: bad next_rotation in rotation.json")
            click.echo()
            continue

        overdue = now > nxt
        icon = "🔴" if overdue else "🟢"
        click.echo(f"{icon} {slug}: next_rotation={pol_obj.next_rotation.split('T')[0]}")
        click.echo(f"   Team policy: {yhint}")
        click.echo()