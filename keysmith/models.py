"""Shared manifest models for scanner and CLI."""

from __future__ import annotations

from pydantic import BaseModel, Field


class CredentialEntry(BaseModel):
    """One logical credential (e.g. FEC) with env name and provenance."""

    env: str
    detected_in: list[str] = Field(default_factory=list)
    provider: str | None = None
    scope: str | None = None
    required_for: list[str] = Field(default_factory=list)


class CredentialManifest(BaseModel):
    """Result of scanning a project for credential requirements."""

    project: str
    credentials: dict[str, CredentialEntry] = Field(default_factory=dict)
    # Uppercase env var name -> literal "present" (never holds secret bytes)
    env_file_vars: dict[str, str] = Field(default_factory=dict)
