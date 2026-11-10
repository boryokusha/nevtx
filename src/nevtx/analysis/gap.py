from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import List, Optional

from nevtx.core.models import EventRecord


@dataclass
class LogGap:
    start_time: datetime
    end_time: datetime
    duration_minutes: float
    prev_record_id: int
    next_record_id: int
    severity: str = "HIGH"

    @property
    def duration_str(self) -> str:
        hours = int(self.duration_minutes // 60)
        mins = int(self.duration_minutes % 60)
        if hours > 0:
            return f"{hours}h {mins}m"
        return f"{mins}m"


class LogGapDetector:
    """Detects suspicious time gaps in Windows Event Logs indicating anti-forensics or service tampering."""

    @staticmethod
    def analyze(records: List[EventRecord], min_gap_minutes: int = 25) -> List[LogGap]:
        # Filter records that have valid timestamps and sort chronologically
        timed_records = [r for r in records if r.timestamp is not None]
        if len(timed_records) < 2:
            return []

        timed_records.sort(key=lambda r: r.timestamp)
        gaps: List[LogGap] = []

        for i in range(len(timed_records) - 1):
            cur = timed_records[i]
            nxt = timed_records[i + 1]

            delta = nxt.timestamp - cur.timestamp
            gap_minutes = delta.total_seconds() / 60.0

            if gap_minutes >= min_gap_minutes:
                # If gap is > 2 hours or preceded/followed by suspicious activity
                sev = "CRITICAL" if gap_minutes >= 60 else "HIGH"
                gaps.append(
                    LogGap(
                        start_time=cur.timestamp,
                        end_time=nxt.timestamp,
                        duration_minutes=gap_minutes,
                        prev_record_id=cur.record_id,
                        next_record_id=nxt.record_id,
                        severity=sev,
                    )
                )

        return gaps
