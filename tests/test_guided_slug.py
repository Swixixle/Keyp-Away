"""Tests for guided setup slug resolution."""

from keysmith.cli.guided import _storage_slug
from keysmith.models import CredentialEntry, CredentialManifest


def test_storage_slug_prefers_manifest_provider() -> None:
    manifest = CredentialManifest(
        project="p",
        credentials={
            "congress": CredentialEntry(env="CONGRESS_API_KEY", provider="congress_gov"),
        },
    )
    assert _storage_slug(manifest, "congress_gov") == "congress"


def test_storage_slug_falls_back_to_registry_key() -> None:
    manifest = CredentialManifest(project="p", credentials={})
    assert _storage_slug(manifest, "fec") == "fec"
