"""Flag unusual credential usage using the coarse usage ledger (counts + timestamps)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from keysmith.audit.usage import CredentialUsage, UsageTracker


@dataclass
class UsageAnomaly:
    handle: str
    anomaly_type: str
    severity: str
    description: str
    baseline: str
    observed: str
    recommendation: str


class AnomalyDetector:
    """Heuristics only — no hourly history; complements future structured audit logs."""

    def __init__(self, tracker: UsageTracker | None = None) -> None:
        self.usage_tracker = tracker or UsageTracker()

    def detect_anomalies(self, lookback_days: int = 30) -> list[UsageAnomaly]:
        all_usage = self.usage_tracker.usage_records()
        if len(all_usage) < 1:
            return []

        lookback_days = max(1, lookback_days)
        now = datetime.now()
        horizons = min(lookback_days, 14)

        anomalies: list[UsageAnomaly] = []

        for handle, usage in all_usage.items():
            anomalies.extend(
                self._for_handle(handle, usage, now=now, recent_horizon_days=horizons)
            )

        return anomalies

    def _for_handle(
        self,
        handle: str,
        usage: CredentialUsage,
        *,
        now: datetime,
        recent_horizon_days: int,
    ) -> list[UsageAnomaly]:
        out: list[UsageAnomaly] = []

        try:
            first_seen = datetime.fromisoformat(usage.first_seen)
            last_accessed = datetime.fromisoformat(usage.last_accessed)
        except ValueError:
            return out

        gap = max(0, (last_accessed - first_seen).days)
        span_days = max(1, gap)
        avg_daily = usage.access_count / float(span_days)
        recently_touched = (now - last_accessed).days <= recent_horizon_days

        # Long spread between first/last timestamps, modest totals, resurfaced lately
        if recently_touched and gap >= 60 and usage.access_count <= 50:
            out.append(
                UsageAnomaly(
                    handle=handle,
                    anomaly_type="dormant_activity",
                    severity="medium",
                    description="Credential shows a long timeline between earliest and latest ledger entry with modest totals.",
                    baseline="steady low-volume credential",
                    observed=f"≈{usage.access_count} access(es) spanning ~{gap}d (last within {recent_horizon_days}d)",
                    recommendation="Verify recent use was intentional and consider rotation if unfamiliar.",
                )
            )

        if usage.access_count > 1000 and avg_daily > 100:
            out.append(
                UsageAnomaly(
                    handle=handle,
                    anomaly_type="high_frequency",
                    severity="low",
                    description="Average implied daily access rate is unusually high versus typical interactive use.",
                    baseline="Typical interactive use stays well below 100 accesses per day",
                    observed=f"{avg_daily:.1f} mean accesses/day over {span_days}d ledger window",
                    recommendation="Ensure scripts are not hammering retries; review CI / adapter loops.",
                )
            )

        return out


def check_for_anomalies(lookback_days: int = 30) -> list[UsageAnomaly]:
    detector = AnomalyDetector()
    return detector.detect_anomalies(lookback_days=lookback_days)
