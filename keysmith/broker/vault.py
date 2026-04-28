"""OS keychain broker — opaque handles only; raw values leave only via inject."""

from __future__ import annotations

import hashlib
import os
import re
import sys
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

import keyring
import yaml

from keysmith.audit.usage import UsageTracker
from keysmith.logging_config import configure_safe_logging

KEYRING_SERVICE = "keysmith"


@dataclass(frozen=True)
class SecretHandle:
    """Opaque reference to a secret — never carries raw credentials."""

    uri: str
    fingerprint: str
    status: Literal["valid", "missing", "invalid", "expired", "present_dotenv", "error"]
    last_used: str | None
    expires: str | None


_URI_RE = re.compile(r"^sec://([^/]+)/([^/]+)/([^/]+)$")


def _fingerprint(uri: str, secret: str) -> str:
    h = hashlib.sha256(secret.encode("utf-8")).hexdigest()
    m = _URI_RE.match(uri)
    slug = m.group(2) if m else "key"
    return f"{slug[:8]}_{h[:4]}...{h[-4:]}".lower()


def project_from_handle_uri(handle_uri: str) -> str | None:
    m = _URI_RE.match(handle_uri)
    return m.group(1) if m else None


def slug_from_handle_uri(handle_uri: str) -> str | None:
    m = _URI_RE.match(handle_uri.strip())
    return m.group(2) if m else None


def _parse_iso_datetime(value: str) -> datetime | None:
    try:
        s = value.replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is not None:
            return dt.replace(tzinfo=None)
        return dt
    except ValueError:
        return None


def resolve_rotation_policy_root(explicit: Path | None = None) -> Path:
    """Directory that may contain ``.keysmith/rotation-policy.yaml``.

    Prefer ``explicit``, then ``KEYSMITH_DEFAULT_PROJECT``, then ``Path.cwd()``."""
    if explicit is not None:
        return explicit.expanduser().resolve()
    ks = os.environ.get("KEYSMITH_DEFAULT_PROJECT")
    if ks:
        return Path(ks).expanduser().resolve()
    return Path.cwd()


def load_team_rotation_inject_settings(project_root: Path | None = None) -> tuple[bool, int]:
    """Read ``settings`` from ``.keysmith/rotation-policy.yaml``.

    Returns ``(enforce_blocking, grace_period_days)``. If the file or ``enforce``
    is absent, blocking is disabled (grace default 7 still used for messaging).
    """
    root = resolve_rotation_policy_root(project_root)
    pol_path = root / ".keysmith" / "rotation-policy.yaml"
    if not pol_path.is_file():
        return False, 7
    try:
        raw = yaml.safe_load(pol_path.read_text(encoding="utf-8"))
    except Exception:
        return False, 7
    if not isinstance(raw, dict):
        return False, 7
    settings = raw.get("settings")
    enforce = isinstance(settings, dict) and bool(settings.get("enforce", False))
    grace = settings.get("grace_period_days") if isinstance(settings, dict) else None
    if isinstance(grace, int) and grace >= 0:
        return enforce, grace
    if isinstance(grace, float) and grace >= 0:
        return enforce, int(grace)
    return enforce, 7


class CredentialBroker:
    """Store and verify credential handles via OS keychain."""

    def __init__(
        self,
        *,
        project_name: str | None = None,
        enforce_rotation: bool = True,
    ) -> None:
        configure_safe_logging()
        self._usage = UsageTracker()
        self._receipt_signer = None
        self._receipt_log = None
        self.enforce_rotation = enforce_rotation
        if project_name:
            from keysmith.receipts.signing import ReceiptLog, ReceiptSigner

            self._receipt_signer = ReceiptSigner(project_name)
            self._receipt_log = ReceiptLog(project_name)

    def publish_receipt(self, event_type: str, handle_uri: str, metadata: dict[str, Any]) -> None:
        """Append a signed local receipt when ``project_name`` was passed at construction."""
        if not self._receipt_signer or not self._receipt_log:
            return
        try:
            r = self._receipt_signer.sign_event(event_type, handle_uri, metadata)
            self._receipt_log.append(r)
        except Exception:
            pass

    def _record_usage(self, handle_uri: str) -> None:
        try:
            self._usage.record_access(handle_uri)
        except Exception:
            pass

    def verify(
        self,
        handle_uri: str,
        *,
        provider_for_health: str | None = None,
        dotenv_reports_present: bool = False,
    ) -> SecretHandle:
        """Check secret status without returning raw value.

        If ``provider_for_health`` is set, validates keychain-backed secret against that
        provider when a secret exists — never uploads .env-derived material.

        If there is **no** keychain entry but ``dotenv_reports_present`` is true,
        reports ``present_dotenv`` (presence only — no fingerprint of file contents).
        """
        try:
            raw = keyring.get_password(KEYRING_SERVICE, handle_uri)
            if raw is not None:
                self._record_usage(handle_uri)
                fp = _fingerprint(handle_uri, raw)
                status: Literal[
                    "valid",
                    "missing",
                    "invalid",
                    "expired",
                    "present_dotenv",
                    "error",
                ] = "valid"
                if provider_for_health:
                    from keysmith.providers.loader import provider_has_health_check, run_health_check

                    if provider_has_health_check(provider_for_health):
                        ok = run_health_check(provider_for_health, raw)
                        if not ok:
                            status = "invalid"
                return SecretHandle(
                    uri=handle_uri,
                    fingerprint=fp,
                    status=status,
                    last_used=None,
                    expires=None,
                )
            if dotenv_reports_present:
                return SecretHandle(
                    uri=handle_uri,
                    fingerprint="—",
                    status="present_dotenv",
                    last_used=None,
                    expires=None,
                )
            return SecretHandle(
                uri=handle_uri,
                fingerprint="—",
                status="missing",
                last_used=None,
                expires=None,
            )
        except Exception:
            return SecretHandle(
                uri=handle_uri,
                fingerprint="—",
                status="error",
                last_used=None,
                expires=None,
            )

    def inject(
        self,
        handle_uri: str,
        target_env: str,
        *,
        skip_rotation_check: bool = False,
        project_root_for_policy: Path | None = None,
    ) -> tuple[bool, str | None]:
        """Inject secret into environment variable without printing.

        When ``.keysmith/rotation-policy.yaml`` sets ``settings.enforce: true``,
        blocks injection if the handle is past ``next_rotation`` by more than
        ``grace_period_days`` (default 7). Otherwise returns an error string.
        """
        raw = keyring.get_password(KEYRING_SERVICE, handle_uri)
        if raw is None:
            return False, "Credential not found in keychain"

        enforce_yaml, grace_days = load_team_rotation_inject_settings(project_root_for_policy)

        if self.enforce_rotation and not skip_rotation_check and enforce_yaml:
            from keysmith.rotation.scheduler import RotationScheduler

            pol = RotationScheduler().get_policy(handle_uri)
            if pol is not None:
                nxt = _parse_iso_datetime(pol.next_rotation)
                if nxt is not None:
                    now = datetime.now()
                    if now > nxt:
                        days_overdue = max(0, (now - nxt).days)
                        if days_overdue > grace_days:
                            slug = slug_from_handle_uri(handle_uri) or "credential"
                            return False, (
                                f"Credential rotation OVERDUE by {days_overdue} day(s). "
                                f"Rotate before using: keysmith setup {slug}"
                            )
                        days_until_block = grace_days + 1 - days_overdue
                        print(
                            f"⚠️  Warning: rotation is {days_overdue} day(s) overdue "
                            f"(inject blocks after {grace_days} day(s); ~{days_until_block} day(s) left).",
                            file=sys.stderr,
                        )

        self._record_usage(handle_uri)
        os.environ[target_env] = raw
        fp = _fingerprint(handle_uri, raw)
        self.publish_receipt(
            "credential_injected",
            handle_uri,
            {"target_env": target_env, "fingerprint": fp},
        )
        return True, None

    def store(self, handle_uri: str, value: str) -> SecretHandle:
        """Store secret in OS keychain, return opaque handle metadata only."""
        keyring.set_password(KEYRING_SERVICE, handle_uri, value)
        self._record_usage(handle_uri)
        fp = _fingerprint(handle_uri, value)
        out = SecretHandle(
            uri=handle_uri,
            fingerprint=fp,
            status="valid",
            last_used=None,
            expires=None,
        )
        self.publish_receipt(
            "credential_connected",
            handle_uri,
            {"fingerprint": fp, "action": "store"},
        )
        return out

    def rotate(self, handle_uri: str) -> SecretHandle:
        """Remove stored secret and return metadata for follow-up reconnect."""
        try:
            keyring.delete_password(KEYRING_SERVICE, handle_uri)
        except keyring.errors.PasswordDeleteError:
            pass
        suffix = uuid.uuid4().hex[:8]
        new_uri = f"{handle_uri.rstrip('/')}-rot-{suffix}"
        self.publish_receipt(
            "credential_rotated",
            handle_uri,
            {"action": "detach", "suggested_followup_uri": new_uri},
        )
        return SecretHandle(
            uri=new_uri,
            fingerprint="—",
            status="missing",
            last_used=None,
            expires=None,
        )
