import base64
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class MitreMatch:
    technique_id: str
    technique_name: str
    tactic: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    description: str


class MitreEngine:
    """Lightweight rule-based MITRE ATT&CK and threat signature detector."""

    # Pre-compiled regex patterns for common DFIR attack vectors
    RULES = [
        # T1490: Inhibit System Recovery (Ransomware behavior)
        {
            "id": "T1490",
            "name": "Inhibit System Recovery",
            "tactic": "Impact",
            "severity": "CRITICAL",
            "pattern": re.compile(
                r"(vssadmin.*delete.*shadows|wmic.*shadowcopy.*delete|wbadmin.*delete.*catalog|bcedit.*set.*recoveryenabled.*no)",
                re.IGNORECASE,
            ),
            "desc": "Attempted to delete volume shadow copies or disable system recovery (Common Ransomware trait).",
        },
        # T1003: Credential Dumping
        {
            "id": "T1003",
            "name": "OS Credential Dumping",
            "tactic": "Credential Access",
            "severity": "CRITICAL",
            "pattern": re.compile(
                r"(mimikatz|sekurlsa|comsvcs(\.dll)?.*minidump|procdump.*lsass|ntdsutil.*ac.*i.*ntds)",
                re.IGNORECASE,
            ),
            "desc": "Known credential dumping tools or LSASS process dumping syntax detected.",
        },
        # T1059.001: PowerShell Execution / Reverse Shell
        {
            "id": "T1059.001",
            "name": "Command and Scripting Interpreter: PowerShell",
            "tactic": "Execution",
            "severity": "HIGH",
            "pattern": re.compile(
                r"(powershell.*(-enc|-encodedcommand)|downloadstring|invoke-webrequest|net\.sockets\.tcpclient|iex\s*\(|invoke-expression)",
                re.IGNORECASE,
            ),
            "desc": "Suspicious PowerShell usage: obfuscated encoded command or network download.",
        },
        # T1105: Ingress Tool Transfer
        {
            "id": "T1105",
            "name": "Ingress Tool Transfer",
            "tactic": "Command and Control",
            "severity": "HIGH",
            "pattern": re.compile(
                r"(certutil(\.exe)?.*(-urlcache|-split.*-f)|bitsadmin(\.exe)?.*\/transfer|curl(\.exe)?.*-O)",
                re.IGNORECASE,
            ),
            "desc": "Lolbin used to download external files onto the system.",
        },
        # T1033: System Owner/User Discovery
        {
            "id": "T1033",
            "name": "System Owner/User Discovery",
            "tactic": "Discovery",
            "severity": "LOW",
            "pattern": re.compile(
                r"(whoami(\.exe)?\s+(\/priv|\/all|\/groups)|quser(\.exe)?|query\s+user)",
                re.IGNORECASE,
            ),
            "desc": "Attacker reconnaissance discovering user privileges and active sessions.",
        },
        # T1543.003: Windows Service Persistence
        {
            "id": "T1543.003",
            "name": "Create or Modify System Process: Windows Service",
            "tactic": "Persistence",
            "severity": "HIGH",
            "pattern": re.compile(
                r"(sc(\.exe)?\s+create.*binpath=|new-service)",
                re.IGNORECASE,
            ),
            "desc": "Creation of a new Windows service for persistence.",
        },
    ]

    @classmethod
    def analyze(cls, event_id: int, data: Dict[str, Any]) -> List[MitreMatch]:
        matches: List[MitreMatch] = []

        # 1. EventID-specific high-priority checks
        if event_id in (1102, 104):
            matches.append(
                MitreMatch(
                    technique_id="T1070.001",
                    technique_name="Indicator Removal: Clear Windows Event Logs",
                    tactic="Defense Evasion",
                    severity="CRITICAL",
                    description="The audit log or event log was manually cleared by a user or attacker.",
                )
            )

        if event_id == 7045:
            svc_name = str(data.get("ServiceName", ""))
            svc_path = str(data.get("ImagePath", ""))
            matches.append(
                MitreMatch(
                    technique_id="T1543.003",
                    technique_name="Create or Modify System Process: Windows Service",
                    tactic="Persistence",
                    severity="HIGH",
                    description=f"New service installed on the system: '{svc_name}' pointing to '{svc_path}'.",
                )
            )

        # 2. Text / CommandLine inspections
        # Inspect CommandLine, Image, ScriptBlockText, Path, etc.
        combined_text = " ".join(
            str(v)
            for k, v in data.items()
            if isinstance(v, (str, int))
        )

        for rule in cls.RULES:
            if rule["pattern"].search(combined_text):
                # Avoid duplicate T1543 if already caught by Event 7045
                if not any(m.technique_id == rule["id"] for m in matches):
                    matches.append(
                        MitreMatch(
                            technique_id=rule["id"],
                            technique_name=rule["name"],
                            tactic=rule["tactic"],
                            severity=rule["severity"],
                            description=rule["desc"],
                        )
                    )

        return matches

    @staticmethod
    def extract_base64_payloads(text: str) -> List[str]:
        """Detects and decodes UTF-16LE or ASCII Base64 payloads commonly found in PowerShell."""
        # Match Base64 strings of length >= 20
        b64_pattern = re.compile(r"([A-Za-z0-9+/]{20,}={0,2})")
        decoded_results: List[str] = []

        for candidate in b64_pattern.findall(text):
            try:
                raw_bytes = base64.b64decode(candidate)
                # Try UTF-16LE (Windows PowerShell standard)
                decoded_str = raw_bytes.decode("utf-16le")
                if any(kw in decoded_str.lower() for kw in ("http", "new-object", "download", "invoke", "client", "tcp", "iex")):
                    decoded_results.append(decoded_str)
                    continue

                # Try ASCII/UTF-8 fallback
                decoded_str = raw_bytes.decode("utf-8", errors="ignore")
                if len(decoded_str) > 10 and any(c.isprintable() for c in decoded_str):
                    decoded_results.append(decoded_str)
            except Exception:
                continue

        return decoded_results
