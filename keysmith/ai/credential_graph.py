"""Group manifest credentials by naming patterns (tiers, regions, cloud families)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from keysmith.scanner.detector import scan_project


@dataclass
class CredentialGroup:
    group_name: str
    credentials: list[str]
    relationship: str
    reasoning: str


_TIER_SUFFIXES = ("_read", "_write", "_admin", "_readonly", "_ro", "_rw")


class CredentialGraphAnalyzer:
    """Lightweight grouping from credential slug naming conventions."""

    def __init__(self, project_root: Path) -> None:
        self.project_root = project_root.resolve()
        self.manifest = scan_project(self.project_root)

    def find_groups(self) -> list[CredentialGroup]:
        groups: list[CredentialGroup] = []
        groups.extend(self._find_tiered_access_groups())
        groups.extend(self._find_regional_groups())
        groups.extend(self._find_service_families())
        return groups

    def _find_tiered_access_groups(self) -> list[CredentialGroup]:
        service_map: dict[str, list[str]] = {}
        for cred_slug in self.manifest.credentials:
            base = cred_slug
            lowered = cred_slug.lower()
            for suf in _TIER_SUFFIXES:
                if lowered.endswith(suf):
                    base = cred_slug[: -len(suf)]
                    break
            service_map.setdefault(base, []).append(cred_slug)

        out: list[CredentialGroup] = []
        for base, creds in service_map.items():
            if len(creds) > 1:
                out.append(
                    CredentialGroup(
                        group_name=f"{base} access tiers",
                        credentials=sorted(creds),
                        relationship="tiered_access",
                        reasoning=f"Multiple slug variants under base “{base}”: {', '.join(sorted(creds))}",
                    )
                )
        return out

    def _find_regional_groups(self) -> list[CredentialGroup]:
        regions = ("_us", "_eu", "_asia", "_ap", "_west", "_east", "_north", "_south")
        buckets: dict[str, list[str]] = {}
        for cred_slug in self.manifest.credentials:
            lowered = cred_slug.lower()
            hit = None
            for suf in regions:
                if lowered.endswith(suf):
                    hit = suf
                    break
            if not hit:
                continue
            base = cred_slug[: -len(hit)]
            if not base:
                continue
            buckets.setdefault(base, []).append(cred_slug)

        out: list[CredentialGroup] = []
        for base, creds in buckets.items():
            if len(creds) > 1:
                out.append(
                    CredentialGroup(
                        group_name=f"{base} regions",
                        credentials=sorted(creds),
                        relationship="regional",
                        reasoning=f"Regional suffix variants for base “{base}”.",
                    )
                )
        return out

    def _find_service_families(self) -> list[CredentialGroup]:
        slugs = list(self.manifest.credentials.keys())
        aws_creds = sorted(s for s in slugs if s.lower().startswith("aws_") or "aws_" in s.lower())
        gcp_creds = sorted(
            s
            for s in slugs
            if s.lower().startswith(("gcp_", "google_"))
            or "google" in s.lower()
            or "gcp" in s.lower()
        )
        out: list[CredentialGroup] = []
        if len(aws_creds) > 1:
            out.append(
                CredentialGroup(
                    group_name="AWS-shaped credentials",
                    credentials=aws_creds,
                    relationship="service_family",
                    reasoning="Multiple slugs look AWS-related.",
                )
            )
        if len(gcp_creds) > 1:
            out.append(
                CredentialGroup(
                    group_name="Google / GCP-shaped credentials",
                    credentials=gcp_creds,
                    relationship="service_family",
                    reasoning="Multiple slugs look Google Cloud–related.",
                )
            )
        return out


def analyze_credential_relationships(project_root: Path) -> list[CredentialGroup]:
    """Return heuristic groups for credentials detected in ``scan_project``."""
    return CredentialGraphAnalyzer(project_root).find_groups()
