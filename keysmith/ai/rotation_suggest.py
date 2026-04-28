"""Heuristic rotation policy suggestions combining registry, scope scan, and usage ledger."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Literal, cast

from keysmith.ai.scope_analyzer import ScopeAnalyzer
from keysmith.audit.usage import UsageTracker
from keysmith.providers.loader import load_provider_registry
from keysmith.scanner.detector import scan_project


@dataclass
class RotationSuggestion:
    credential_slug: str
    suggested_days: int
    risk_level: Literal["low", "medium", "high", "critical"]
    confidence: float  # 0.0 to 1.0
    reasoning: str
    factors: list[str]


_BASE_INTERVALS: dict[str, int] = {
    "critical": 30,
    "high": 90,
    "medium": 180,
    "low": 365,
}


def _coerce_risk_level(raw: object) -> Literal["low", "medium", "high", "critical"]:
    if isinstance(raw, str) and raw in ("low", "medium", "high", "critical"):
        return cast("Literal['low', 'medium', 'high', 'critical']", raw)
    return "medium"


class RotationSuggester:
    """Combine scope signals, registry metadata, usage counts, and env exposure hints."""

    def __init__(self, project_root: Path) -> None:
        self.project_root = project_root.resolve()
        self.registry = load_provider_registry()
        self.usage_tracker = UsageTracker()
        self.manifest = scan_project(self.project_root)
        self.scope_analyzer = ScopeAnalyzer(self.project_root)

    def suggest_for_credential(self, credential_slug: str) -> RotationSuggestion:
        provider = self.registry.get("providers", {}).get(credential_slug)

        if provider and isinstance(provider.get("rotation"), dict):
            rotation_info = provider["rotation"]
            if isinstance(rotation_info.get("recommended_days"), int):
                rd = int(rotation_info["recommended_days"])
                return RotationSuggestion(
                    credential_slug=credential_slug,
                    suggested_days=max(1, rd),
                    risk_level=_coerce_risk_level(rotation_info.get("risk_level")),
                    confidence=0.95,
                    reasoning=str(
                        rotation_info.get("reasoning")
                        or "Provider registry recommends this interval."
                    ),
                    factors=["Provider-specified policy"],
                )

        risk_score = 0
        factors: list[str] = []
        confidence = 0.5

        try:
            scope_req = self.scope_analyzer.analyze_provider(credential_slug)
            if scope_req.required_scope == "admin":
                risk_score += 40
                factors.append(f"Admin scope ({scope_req.confidence:.0%} confidence)")
                confidence = max(confidence, scope_req.confidence * 0.9)
            elif scope_req.required_scope == "write":
                risk_score += 25
                factors.append(f"Write scope ({scope_req.confidence:.0%} confidence)")
                confidence = max(confidence, scope_req.confidence * 0.8)
            else:
                risk_score += 10
                factors.append(f"Read-only scope ({scope_req.confidence:.0%} confidence)")
                confidence = max(confidence, scope_req.confidence * 0.7)
        except (ValueError, OSError):
            risk_score += 15
            factors.append("Scope unknown (registry or scan error)")

        if provider:
            provider_name = str(provider.get("name", "")).lower()
            if any(
                term in provider_name for term in ("payment", "stripe", "bank", "financial")
            ):
                risk_score += 30
                factors.append("Financial/payment provider name pattern")
            elif any(term in provider_name for term in ("auth", "oauth", "sso", "identity")):
                risk_score += 25
                factors.append("Identity / authentication provider pattern")
            elif any(term in provider_name for term in ("fec", "congress", "gov")):
                risk_score += 20
                factors.append("Government / regulated data provider")
            elif any(term in provider_name for term in ("admin", "management", "control")):
                risk_score += 20
                factors.append("Administrative API name pattern")
            else:
                risk_score += 10
                factors.append("General API provider")

        handle = f"sec://{self.manifest.project}/{credential_slug}/api-key"
        usage = self.usage_tracker.get_usage(handle)

        if usage:
            try:
                last_ref = datetime.fromisoformat(usage.last_accessed)
                days_since = max(0, (datetime.now() - last_ref).days)
            except ValueError:
                days_since = 0

            if days_since > 180:
                risk_score += 20
                factors.append(f"Stale usage record ({days_since}d since last access)")
            elif usage.access_count > 10000:
                risk_score += 15
                factors.append(f"High access volume ({usage.access_count} total)")
            elif usage.access_count < 10:
                risk_score -= 5
                factors.append(f"Low total access count ({usage.access_count})")

            confidence = min(1.0, confidence + 0.2)
        else:
            factors.append("No usage history in ledger")

        cred_info = self.manifest.credentials.get(credential_slug)
        if cred_info:
            in_env = self.manifest.env_file_vars.get(cred_info.env.upper()) == "present"
            if in_env:
                risk_score += 10
                factors.append(".env layer reports value present (exposure surface)")
            else:
                factors.append("No .env presence flag (often keychain-only)")
                confidence = min(1.0, confidence + 0.1)

        risk_score = max(0, min(100, risk_score))

        if risk_score >= 70:
            risk_level: Literal["low", "medium", "high", "critical"] = "critical"
        elif risk_score >= 50:
            risk_level = "high"
        elif risk_score >= 30:
            risk_level = "medium"
        else:
            risk_level = "low"

        suggested_days = _BASE_INTERVALS[risk_level]

        if usage and usage.access_count > 5000:
            suggested_days = max(1, int(suggested_days * 0.75))

        reasoning = self._build_reasoning(risk_level, suggested_days, factors)

        return RotationSuggestion(
            credential_slug=credential_slug,
            suggested_days=suggested_days,
            risk_level=risk_level,
            confidence=min(1.0, confidence),
            reasoning=reasoning,
            factors=factors,
        )

    def _build_reasoning(self, risk_level: str, days: int, factors: list[str]) -> str:
        risk_desc = {
            "critical": "Critical security posture",
            "high": "High-risk credential",
            "medium": "Moderate security needs",
            "low": "Low-risk profile",
        }
        base = f"{risk_desc[risk_level]} — suggest rotating about every {days} days"
        if len(factors) >= 2:
            base += f" (notably: {factors[0]}; {factors[1]})"
        elif factors:
            base += f" ({factors[0]})"
        return base


def suggest_all_rotations(project_root: Path) -> dict[str, RotationSuggestion]:
    """Return one suggestion per provider key in the bundled registry."""
    suggester = RotationSuggester(project_root)
    registry = load_provider_registry()
    out: dict[str, RotationSuggestion] = {}
    for slug in sorted(registry.get("providers", {}).keys()):
        try:
            out[slug] = suggester.suggest_for_credential(slug)
        except OSError:
            continue
    return out
