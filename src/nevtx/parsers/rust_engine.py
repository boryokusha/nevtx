from datetime import datetime
import json
from pathlib import Path
from typing import Any, Dict, Iterator, Optional
import xml.etree.ElementTree as ET

from nevtx.core.models import EventRecord
from nevtx.parsers.base import BaseEventParser


class FastEvtxParser(BaseEventParser):
    """High-performance parser utilizing the Rust-backed evtx library."""

    def parse(self, file_path: Path) -> Iterator[EventRecord]:
        try:
            from evtx import PyEvtxParser
        except ImportError:
            raise ImportError(
                "The 'evtx' package is required. Install it using 'pip install evtx'."
            )

        parser = PyEvtxParser(str(file_path))

        for record in parser.records_json():
            try:
                raw_json_str = record.get("data", "{}")
                data_dict = json.loads(raw_json_str)

                event_meta = data_dict.get("Event", {})
                system = event_meta.get("System", {})

                # Extract Event ID (can be int or dict like {"#text": 4624})
                raw_event_id = system.get("EventID", 0)
                if isinstance(raw_event_id, dict):
                    event_id = int(raw_event_id.get("#text", 0))
                else:
                    event_id = int(raw_event_id)

                # Extract Timestamp
                time_created_meta = system.get("TimeCreated", {})
                time_str = time_created_meta.get("#attributes", {}).get("SystemTime")
                timestamp: Optional[datetime] = None
                if time_str:
                    try:
                        # Normalize ISO timestamp (e.g. 2023-01-01T12:00:00.123456Z)
                        clean_time = time_str.split(".")[0].replace("Z", "")
                        timestamp = datetime.fromisoformat(clean_time)
                    except Exception:
                        timestamp = None

                # Extract Provider
                provider_meta = system.get("Provider", {})
                provider = (
                    provider_meta.get("#attributes", {}).get("Name", "Unknown")
                    if isinstance(provider_meta, dict)
                    else str(provider_meta)
                )

                # Extract Channel, Computer, Level, Record ID
                channel = str(system.get("Channel", ""))
                computer = str(system.get("Computer", ""))
                level = str(system.get("Level", "Information"))
                record_id = int(system.get("EventRecordID", record.get("event_record_id", 0)))

                # EventData extraction
                event_data = event_meta.get("EventData", {})
                summary = self._generate_summary(event_id, event_data)

                yield EventRecord(
                    record_id=record_id,
                    timestamp=timestamp,
                    event_id=event_id,
                    provider=provider,
                    channel=channel,
                    level=level,
                    computer=computer,
                    raw_xml=raw_json_str,
                    data=event_data if isinstance(event_data, dict) else {},
                    tags=[],
                    summary=summary,
                )
            except Exception:
                # Skip or yield partially populated record on corrupt individual entry
                continue

    def _generate_summary(self, event_id: int, event_data: Any) -> str:
        """Helper to create a fast one-line summary for the table view."""
        if not isinstance(event_data, dict):
            return ""

        # Windows Security: 4624 (Logon)
        if event_id == 4624:
            user = event_data.get("TargetUserName", "")
            domain = event_data.get("TargetDomainName", "")
            logon_type = event_data.get("LogonType", "")
            return f"Logon: {domain}\\{user} (Type: {logon_type})"

        # Windows Security: 4625 (Failed Logon)
        if event_id == 4625:
            user = event_data.get("TargetUserName", "")
            status = event_data.get("Status", "")
            return f"Failed Logon: {user} (Status: {status})"

        # Windows Security: 4688 / Sysmon 1 (Process Creation)
        if event_id in (4688, 1):
            cmd = event_data.get("CommandLine", event_data.get("NewProcessName", ""))
            return f"Process: {cmd[:60]}..." if len(cmd) > 60 else f"Process: {cmd}"

        # Windows Security: 7045 (Service Installed)
        if event_id == 7045:
            svc_name = event_data.get("ServiceName", "")
            svc_path = event_data.get("ImagePath", "")
            return f"New Service: {svc_name} -> {svc_path}"

        # PowerShell: 4104 (Script Block)
        if event_id == 4104:
            script = str(event_data.get("ScriptBlockText", "")).strip().replace("\n", " ")
            return f"ScriptBlock: {script[:60]}..."

        return ""
