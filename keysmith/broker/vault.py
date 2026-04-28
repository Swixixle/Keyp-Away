"""OS keychain broker — opaque handles only; raw values leave only via inject."""

from __future__ import annotations

import hashlib
import os
import re
import uuid
from dataclasses import dataclass
from typing import Literal

import keyring

from keysmith.audit.usage import UsageTracker
from keysmith.logging_config import configure_safe_logging
from keysmith.providers.loader import run_health_check

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


class CredentialBroker:
    """Store and verify credential handles via OS keychain."""

    def __init__(self) -> None:
        configure_safe_logging()
        self._usage = UsageTracker()

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

    def inject(self, handle_uri: str, target_env: str) -> bool:
        """Inject secret into environment variable without printing."""
        raw = keyring.get_password(KEYRING_SERVICE, handle_uri)
        if raw is None:
            return False
        self._record_usage(handle_uri)
        os.environ[target_env] = raw
        return True

    def store(self, handle_uri: str, value: str) -> SecretHandle:
        """Store secret in OS keychain, return opaque handle metadata only."""
        keyring.set_password(KEYRING_SERVICE, handle_uri, value)
        self._record_usage(handle_uri)
        return SecretHandle(
            uri=handle_uri,
            fingerprint=_fingerprint(handle_uri, value),
            status="valid",
            last_used=None,
            expires=None,
        )

    def rotate(self, handle_uri: str) -> SecretHandle:
        """Remove stored secret and return metadata for follow-up reconnect."""
        try:
            keyring.delete_password(KEYRING_SERVICE, handle_uri)
        except keyring.errors.PasswordDeleteError:
            pass
        suffix = uuid.uuid4().hex[:8]
        new_uri = f"{handle_uri.rstrip('/')}-rot-{suffix}"
        return SecretHandle(
            uri=new_uri,
            fingerprint="—",
            status="missing",
            last_used=None,
            expires=None,
        )
