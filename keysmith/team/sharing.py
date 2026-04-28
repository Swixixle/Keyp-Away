"""Optional age-based secret sharing via checked-in ``.age`` files (requires ``age`` / ``age-keygen`` on PATH)."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import cast


import keyring

from keysmith.broker.vault import KEYRING_SERVICE, slug_from_handle_uri


class SecretSharer:
    """Encrypt/decrypt credential bytes using the ``age`` CLI."""

    def __init__(self, team_dot_keysmith: Path) -> None:
        self.team_dir = team_dot_keysmith
        self.secrets_dir = team_dot_keysmith / "secrets"
        self.secrets_dir.mkdir(parents=True, exist_ok=True)

    def write_encrypted_for_recipients(self, plaintext: bytes, dest: Path, recipient_pubkeys: list[str]) -> None:
        if not recipient_pubkeys:
            raise ValueError("At least one recipient public key is required")
        recipient_flags: list[str] = []
        for pubkey in recipient_pubkeys:
            recipient_flags.extend(["-r", pubkey.strip()])
        cmd = ["age", *recipient_flags, "-o", str(dest)]
        r = subprocess.run(cmd, input=plaintext, capture_output=True, check=False)
        if r.returncode != 0:
            err = (r.stderr or b"").decode("utf-8", errors="replace")
            raise RuntimeError(
                f"'age' failed (is age installed?): {err.strip()}".strip()
                or "`age` command failed — install age and ensure recipients are valid."
            )

    def share_credential(self, handle: str, recipient_pubkeys: list[str]) -> Path:
        raw = keyring.get_password(KEYRING_SERVICE, handle)
        if raw is None:
            raise ValueError(f"No credential in OS keychain for handle: {handle}")
        slug = slug_from_handle_uri(handle)
        if not slug:
            raise ValueError(f"Cannot infer credential slug from handle: {handle}")
        dest = self.secrets_dir / f"{slug}.age"
        self.write_encrypted_for_recipients(raw.encode("utf-8"), dest, recipient_pubkeys)
        return dest

    def decrypt_to_string(self, encrypted_path: Path, identity_file: Path) -> str:
        cmd = ["age", "-d", "-i", str(identity_file), str(encrypted_path)]
        r = subprocess.run(cmd, capture_output=True, check=False)
        if r.returncode != 0:
            err = (r.stderr or b"").decode("utf-8", errors="replace")
            raise RuntimeError(f"Decrypt failed: {err.strip()}")
        return cast("str", r.stdout.decode("utf-8")).strip()


class TeamKeyManager:
    """Thin wrapper around ``age-keygen`` for local onboarding."""

    _PUB_LINE = re.compile(r"^#\s*public\s*key:\s*(age1\S+)\s*$", re.IGNORECASE)
    _SEC_LINE = re.compile(r"^(AGE-SECRET-KEY-1[^\s]+)")

    @classmethod
    def generate_keypair(cls) -> tuple[str, str]:
        r = subprocess.run(
            ["age-keygen"], capture_output=True, text=True, check=False,
        )
        if r.returncode != 0 or not r.stdout:
            err = (r.stderr or "").strip()
            raise RuntimeError(
                f"age-keygen failed (install age: brew install age / https://github.com/FiloSottile/age). {err}"
            )
        pubkey = privkey = None
        for line in r.stdout.splitlines():
            m = cls._PUB_LINE.match(line.strip())
            if m:
                pubkey = m.group(1)
                continue
            m2 = cls._SEC_LINE.match(line.strip())
            if m2:
                privkey = m2.group(1)
                continue
        if not pubkey:
            pm = re.search(r"\b(age1[a-z0-9]+)\b", r.stdout, re.IGNORECASE)
            if pm:
                pubkey = pm.group(1)
        if not privkey:
            for line in r.stdout.splitlines():
                chunk = line.strip().split()[0] if line.strip() else ""
                if chunk.startswith("AGE-SECRET-KEY-"):
                    privkey = chunk
                    break
        if not pubkey or not privkey:
            raise RuntimeError("Could not parse age-keygen output")
        return pubkey, privkey

    @staticmethod
    def store_identity(private_key_line: str) -> Path:
        identity_path = Path.home() / ".keysmith" / "team-identity.age"
        identity_path.parent.mkdir(parents=True, exist_ok=True)
        identity_path.write_text(private_key_line.strip() + "\n", encoding="utf-8")
        identity_path.chmod(0o600)
        return identity_path
