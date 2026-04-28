"""Load provider registry and health-check helpers."""

from __future__ import annotations

import hashlib
import importlib.resources
import logging
from functools import lru_cache
from typing import Any, cast

import httpx
import yaml

_LOGGER = logging.getLogger(__name__)

# Env substring → canonical provider key in registry.yaml
_ENV_PROVIDER_HINTS: dict[str, str] = {
    "FEC": "fec",
    "CONGRESS": "congress_gov",
}


@lru_cache
def load_provider_registry() -> dict[str, Any]:
    """Load provider metadata from bundled registry.yaml."""
    pkg = importlib.resources.files("keysmith.providers")
    blob = pkg.joinpath("registry.yaml").read_bytes()
    data = yaml.safe_load(blob)
    return cast("dict[str, Any]", data or {})


def provider_for_env_name(env_name: str) -> str | None:
    """Infer registry provider key from env var name."""
    u = env_name.upper()
    for needle, pk in _ENV_PROVIDER_HINTS.items():
        if needle in u:
            provs = load_provider_registry().get("providers", {})
            if pk in provs:
                return pk
    providers = load_provider_registry().get("providers", {})
    base = env_name.split("_")[0].lower()
    keys = providers.keys()
    if base and base in keys:
        return base
    return None


def get_signup_url(provider_key: str) -> str | None:
    registry = load_provider_registry()
    pdata = registry.get("providers", {}).get(provider_key, {})
    return pdata.get("signup_url")


def run_health_check(provider_key: str, api_key: str) -> bool:
    """Verify key against provider health endpoint. Never logs the secret."""
    configure_provider_logging_safe()
    registry = load_provider_registry()
    pdata = registry.get("providers", {}).get(provider_key, {})
    hc = pdata.get("health_check")
    if not hc:
        return False
    endpoint_raw = hc.get("endpoint")
    method = hc.get("method", "GET").upper()
    expected = hc.get("expected_status", 200)
    if not endpoint_raw:
        return False
    url = endpoint_raw.replace("{key}", api_key)

    try:
        with httpx.Client(timeout=15.0) as client:
            resp = client.request(method, url)
    except Exception as e:
        fingerprint = hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:8]
        _LOGGER.warning("health check network error provider=%s key_fp=%s err=%s", provider_key, fingerprint, e)
        return False

    fp_log = hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:8]
    _LOGGER.info("health_check provider=%s status_code=%s key_fp=%s", provider_key, resp.status_code, fp_log)
    return resp.status_code == expected


def configure_provider_logging_safe() -> None:
    """Ensure redaction when using httpx/logging in tooling."""
    from keysmith.logging_config import SecretRedactionFilter

    root = logging.getLogger()
    for f in root.filters:
        if isinstance(f, SecretRedactionFilter):
            return
    root.addFilter(SecretRedactionFilter())
