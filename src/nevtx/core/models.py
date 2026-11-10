from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class EventRecord:
    """Normalized Windows Event Log entry."""

    record_id: int
    timestamp: Optional[datetime]
    event_id: int
    provider: str
    channel: str
    level: str
    computer: str
    raw_xml: str
    data: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    summary: str = ""
    mitre_matches: List[Any] = field(default_factory=list)
    decoded_payloads: List[str] = field(default_factory=list)

    @property
    def timestamp_str(self) -> str:
        """Formatted ISO timestamp for display."""
        if self.timestamp:
            return self.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        return "N/A"

    @property
    def level_display(self) -> str:
        """Normalized string for log level."""
        lvl = str(self.level).strip().lower()
        if "crit" in lvl:
            return "CRITICAL"
        if "err" in lvl:
            return "ERROR"
        if "warn" in lvl:
            return "WARNING"
        return "INFO"

    @property
    def highest_severity(self) -> str:
        """Determines highest severity between log level and MITRE matches."""
        severities = [m.severity for m in self.mitre_matches]
        if "CRITICAL" in severities:
            return "CRITICAL"
        if "HIGH" in severities:
            return "HIGH"
        if "MEDIUM" in severities:
            return "MEDIUM"
        return self.level_display
