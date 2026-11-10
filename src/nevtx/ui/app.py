import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.syntax import Syntax
from rich.text import Text
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Select,
    Static,
)

from nevtx.analysis.gap import LogGap, LogGapDetector
from nevtx.core.mock import generate_mock_events_by_file
from nevtx.core.models import EventRecord
from nevtx.parsers.rust_engine import FastEvtxParser


class ThreatStatusBar(Static):
    """Visual status bar showing Threat distribution and Anti-Forensics Log Gaps."""

    def update_stats(self, records: List[EventRecord], gaps: List[LogGap]) -> None:
        total = len(records)
        if total == 0:
            self.update("[dim]No events in selected file[/dim]")
            return

        threat_count = sum(1 for r in records if r.mitre_matches)
        normal_count = total - threat_count
        threat_pct = (threat_count / total) * 100

        # Construct a 16-block visual ratio bar
        bar_length = 16
        threat_blocks = int(round((threat_count / total) * bar_length))
        normal_blocks = bar_length - threat_blocks

        text = Text()
        text.append(" 🛡️ THREAT RATIO: ", style="bold bright_white on #222228")
        text.append("▕", style="dim")
        text.append("█" * threat_blocks, style="bold red")
        text.append("█" * normal_blocks, style="bold green")
        text.append("▏ ", style="dim")
        text.append(f"{threat_pct:.1f}% THREATS ", style="bold red" if threat_count > 0 else "bold green")
        text.append(f"({threat_count}/{total}) ", style="bold yellow")
        text.append("│ ", style="dim")
        text.append(f"🟢 {normal_count} Clean ", style="bold green")

        # Anti-Forensics / Log Gap Alert
        if gaps:
            largest_gap = max(gaps, key=lambda g: g.duration_minutes)
            text.append("│ ", style="dim")
            text.append(
                f"🚨 LOG GAP ANOMALY: {largest_gap.duration_str} Silence ({largest_gap.start_time.strftime('%H:%M')} -> {largest_gap.end_time.strftime('%H:%M')}) ",
                style="bold yellow on #7f1d1d" if largest_gap.severity == "CRITICAL" else "bold black on #facc15",
            )

        self.update(text)


class Inspector(Static):
    """Detail pane for inspecting the selected event record with MITRE & Decoded Payload triage."""

    def display_record(self, record: Optional[EventRecord]) -> None:
        if not record:
            self.update("[dim]No record selected.[/dim]")
            return

        renderables: List[RenderableType] = []

        # 1. MITRE ATT&CK Alert Box
        if record.mitre_matches:
            mitre_text = Text()
            for m in record.mitre_matches:
                sev_color = "bold red" if m.severity == "CRITICAL" else "bold yellow"
                mitre_text.append(f"• [{m.technique_id}] {m.technique_name} ", style=sev_color)
                mitre_text.append(f"({m.tactic} - {m.severity})\n", style="bold white")
                mitre_text.append(f"  {m.description}\n", style="dim")

            renderables.append(
                Panel(
                    mitre_text,
                    title="🎯 [bold red]MITRE ATT&CK Triage[/bold red]",
                    border_style="red" if any(m.severity == "CRITICAL" for m in record.mitre_matches) else "yellow",
                )
            )

        # 2. Decoded Base64 Payload Box
        if record.decoded_payloads:
            payload_text = Text()
            for payload in record.decoded_payloads:
                payload_text.append(f"{payload}\n", style="bold green")

            renderables.append(
                Panel(
                    payload_text,
                    title="🔓 [bold green]Decoded Base64 / Obfuscated Payload[/bold green]",
                    border_style="green",
                )
            )

        # 3. Clean Key-Value & Raw Event Details
        details = {
            "RecordID": record.record_id,
            "EventID": record.event_id,
            "TimeCreated": record.timestamp_str,
            "Provider": record.provider,
            "Channel": record.channel,
            "Level": record.level_display,
            "Computer": record.computer,
            "Summary": record.summary,
            "Tags": record.tags,
            "EventData": record.data,
        }

        json_str = json.dumps(details, indent=2, ensure_ascii=False)
        renderables.append(
            Panel(
                Syntax(json_str, "json", theme="monokai", word_wrap=True),
                title="📄 [bold cyan]Event Data (JSON)[/bold cyan]",
                border_style="blue",
            )
        )

        self.update(Group(*renderables))


class NevtxApp(App):
    """Main Textual Application for nevtx with multi-file directory and triage support."""

    CSS = """
    Screen {
        background: #121214;
        color: #e1e1e6;
    }

    #top-bar {
        height: 3;
        dock: top;
        background: #1a1a1e;
        layout: horizontal;
        padding: 0 1;
        align-vertical: middle;
    }

    #file-select {
        width: 36;
        margin-right: 1;
        background: #27272a;
    }

    #search-input {
        width: 1fr;
        border: none;
        background: #202024;
    }

    #quick-filters {
        height: 3;
        dock: top;
        background: #16161a;
        layout: horizontal;
        padding: 0 1;
        align-vertical: middle;
    }

    .filter-btn {
        margin-right: 1;
        height: 1;
        min-width: 10;
        border: none;
        background: #27272a;
        color: #a1a1aa;
    }

    .filter-btn:hover {
        background: #3b82f6;
        color: #ffffff;
    }

    .filter-btn.-active {
        background: #2563eb;
        color: #ffffff;
        text-style: bold;
    }

    #threat-status-bar {
        height: 1;
        dock: top;
        background: #1a1a24;
        color: #ffffff;
        padding: 0 1;
    }

    #main-split {
        height: 1fr;
        layout: horizontal;
    }

    #table-container {
        width: 62%;
        height: 100%;
        border-right: solid #2a2a30;
    }

    #inspector-container {
        width: 38%;
        height: 100%;
        background: #18181b;
        padding: 1;
        overflow-y: auto;
    }

    DataTable {
        height: 100%;
    }

    DataTable > .datatable--cursor {
        background: #2563eb;
        color: #ffffff;
    }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("/", "focus_search", "Search"),
        ("escape", "unfocus_search", "Clear Focus"),
        ("1", "filter_all", "All"),
        ("2", "filter_threats", "Threats"),
        ("3", "filter_logons", "Failed (4625)"),
        ("4", "filter_process", "Process (4688)"),
        ("5", "filter_ps", "PowerShell"),
    ]

    def __init__(
        self,
        file_path: Optional[Path] = None,
        folder_path: Optional[Path] = None,
        is_demo: bool = False,
    ):
        super().__init__()
        self.file_path = file_path
        self.folder_path = folder_path
        self.is_demo = is_demo

        # Multi-file storage: key = display name / path, value = list of records
        self.files_cache: Dict[str, List[EventRecord]] = {}
        self.active_file_key: str = ""
        self.current_records: List[EventRecord] = []
        self.record_map: Dict[int, EventRecord] = {}

        self.active_filter: str = "all"
        self.search_query: str = ""

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="top-bar"):
            # Top-left file dropdown selector
            yield Select[str]([("Loading...", "loading")], id="file-select", allow_blank=False)
            yield Input(placeholder="🔍 Search across events (regex, username, command)... [/]", id="search-input")
        with Container(id="quick-filters"):
            yield Button("[1] All", id="btn-all", classes="filter-btn -active")
            yield Button("[2] 🚨 Threats", id="btn-threats", classes="filter-btn")
            yield Button("[3] 🔑 Failed", id="btn-failed", classes="filter-btn")
            yield Button("[4] 💻 Process", id="btn-process", classes="filter-btn")
            yield Button("[5] ⚡ PS", id="btn-ps", classes="filter-btn")
            yield Button("[6] 🧹 Cleared", id="btn-cleared", classes="filter-btn")
        yield ThreatStatusBar(id="threat-status-bar")
        with Horizontal(id="main-split"):
            with Vertical(id="table-container"):
                yield DataTable(id="events-table", cursor_type="row")
            with Vertical(id="inspector-container"):
                yield Inspector(id="inspector")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one(DataTable)
        table.add_columns("Time", "ID", "Threat / Level", "MITRE", "Summary")
        self.discover_and_load_files()

    def discover_and_load_files(self) -> None:
        select_options: List[Tuple[str, str]] = []

        if self.is_demo:
            self.title = "nevtx [DEMO MODE - Multi-File DFIR Triage]"
            mock_data = generate_mock_events_by_file()
            self.files_cache = mock_data
            for key in mock_data.keys():
                select_options.append((key, key))
            default_key = select_options[0][1]

        elif self.folder_path:
            self.title = f"nevtx [Folder: {self.folder_path.name}]"
            evtx_files = sorted(list(self.folder_path.glob("*.evtx")))
            if not evtx_files:
                self.notify(f"No .evtx files found in {self.folder_path}", severity="error")
                return

            parser = FastEvtxParser()
            all_merged: List[EventRecord] = []

            for p in evtx_files:
                try:
                    records = list(parser.parse(p))
                    self.files_cache[p.name] = records
                    all_merged.extend(records)
                    select_options.append((f"📄 {p.name} ({len(records)})", p.name))
                except Exception as e:
                    self.notify(f"Failed parsing {p.name}: {e}", severity="warning")

            # Add Merged Timeline option if more than 1 file
            if len(evtx_files) > 1:
                all_merged.sort(key=lambda r: r.timestamp or Path.stat)
                merged_key = f"📁 [All Files - Merged Timeline ({len(all_merged)})]"
                self.files_cache[merged_key] = all_merged
                select_options.insert(0, (merged_key, merged_key))

            default_key = select_options[0][1]

        elif self.file_path:
            self.title = f"nevtx - {self.file_path.name}"
            parser = FastEvtxParser()
            try:
                records = list(parser.parse(self.file_path))
            except Exception as e:
                self.notify(f"Error: {e}", severity="error")
                records = []
            self.files_cache[self.file_path.name] = records
            select_options.append((f"📄 {self.file_path.name} ({len(records)})", self.file_path.name))
            default_key = self.file_path.name
        else:
            return

        # Update select options
        select_widget = self.query_one("#file-select", Select)
        select_widget.set_options(select_options)
        self.switch_to_file(default_key)

    def switch_to_file(self, file_key: str) -> None:
        self.active_file_key = file_key
        self.current_records = self.files_cache.get(file_key, [])
        self.record_map = {r.record_id: r for r in self.current_records}

        # Analyze log gaps (anti-forensics)
        gaps = LogGapDetector.analyze(self.current_records, min_gap_minutes=25)

        # Update Threat Bar with Gaps
        threat_bar = self.query_one(ThreatStatusBar)
        threat_bar.update_stats(self.current_records, gaps)

        self.apply_filter()

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.value and event.value != "loading":
            self.switch_to_file(str(event.value))

    def apply_filter(self) -> None:
        table = self.query_one(DataTable)
        table.clear()

        query = self.search_query.lower()

        for record in self.current_records:
            # Check Quick Filter
            if self.active_filter == "threats" and not record.mitre_matches:
                continue
            if self.active_filter == "failed" and record.event_id != 4625:
                continue
            if self.active_filter == "process" and record.event_id not in (4688, 1):
                continue
            if self.active_filter == "ps" and record.event_id != 4104:
                continue
            if self.active_filter == "cleared" and record.event_id not in (1102, 104):
                continue

            # Check Search Query
            if query:
                combined_match = (
                    query in str(record.event_id)
                    or query in record.provider.lower()
                    or query in record.summary.lower()
                    or query in record.computer.lower()
                    or any(query in m.technique_id.lower() or query in m.technique_name.lower() for m in record.mitre_matches)
                )
                if not combined_match:
                    continue

            # Threat / Level Badge
            if record.mitre_matches:
                highest = record.highest_severity
                if highest == "CRITICAL":
                    threat_badge = "[bold red]🚨 CRITICAL[/bold red]"
                elif highest == "HIGH":
                    threat_badge = "[bold orange3]⚠️ HIGH[/bold orange3]"
                else:
                    threat_badge = "[bold yellow]⚡ MEDIUM[/bold yellow]"
                mitre_tag = ", ".join(m.technique_id for m in record.mitre_matches)
                mitre_cell = f"[bold red]{mitre_tag}[/bold red]"
            else:
                level_str = record.level_display
                threat_badge = f"[green]{level_str}[/green]"
                mitre_cell = "[dim]-[/dim]"

            table.add_row(
                record.timestamp_str,
                str(record.event_id),
                threat_badge,
                mitre_cell,
                record.summary,
                key=str(record.record_id),
            )

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        row_key = event.row_key.value
        try:
            record_id = int(row_key)
            record = self.record_map.get(record_id)
            inspector = self.query_one(Inspector)
            inspector.display_record(record)
        except Exception:
            pass

    def action_focus_search(self) -> None:
        self.query_one("#search-input", Input).focus()

    def action_unfocus_search(self) -> None:
        self.query_one(DataTable).focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        self.search_query = event.value.strip()
        self.apply_filter()

    # Quick filter actions
    def set_active_filter(self, filter_name: str) -> None:
        self.active_filter = filter_name
        self.apply_filter()

    def action_filter_all(self) -> None:
        self.set_active_filter("all")

    def action_filter_threats(self) -> None:
        self.set_active_filter("threats")

    def action_filter_logons(self) -> None:
        self.set_active_filter("failed")

    def action_filter_process(self) -> None:
        self.set_active_filter("process")

    def action_filter_ps(self) -> None:
        self.set_active_filter("ps")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id
        if btn_id == "btn-all":
            self.set_active_filter("all")
        elif btn_id == "btn-threats":
            self.set_active_filter("threats")
        elif btn_id == "btn-failed":
            self.set_active_filter("failed")
        elif btn_id == "btn-process":
            self.set_active_filter("process")
        elif btn_id == "btn-ps":
            self.set_active_filter("ps")
        elif btn_id == "btn-cleared":
            self.set_active_filter("cleared")
