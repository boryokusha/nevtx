import json
from pathlib import Path
from typing import Dict, List, Optional

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
    Static,
)

from nevtx.core.mock import generate_mock_events
from nevtx.core.models import EventRecord
from nevtx.parsers.rust_engine import FastEvtxParser


class ThreatStatusBar(Static):
    """Compact visual progress bar showing Threat vs Normal event distribution."""

    def update_stats(self, records: List[EventRecord]) -> None:
        total = len(records)
        if total == 0:
            self.update("[dim]No events loaded[/dim]")
            return

        threat_count = sum(1 for r in records if r.mitre_matches)
        normal_count = total - threat_count
        threat_pct = (threat_count / total) * 100
        normal_pct = 100 - threat_pct

        # Construct a 15-block visual ratio bar
        bar_length = 15
        threat_blocks = int(round((threat_count / total) * bar_length))
        normal_blocks = bar_length - threat_blocks

        # Build Rich formatted text
        text = Text()
        text.append(" 🛡️ Threat Ratio: ", style="bold white")
        text.append("▕", style="dim")
        text.append("█" * threat_blocks, style="bold red" if threat_pct > 30 else "bold yellow")
        text.append("█" * normal_blocks, style="bold green")
        text.append("▏ ", style="dim")
        text.append(f"{threat_pct:.0f}% Threats ", style="bold red" if threat_count > 0 else "green")
        text.append(f"({threat_count}/{total}) ", style="bold yellow")
        text.append("• ", style="dim")
        text.append(f"{normal_count} Clean", style="green")

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
    """Main Textual Application for nevtx with DFIR triage."""

    CSS = """
    Screen {
        background: #121214;
        color: #e1e1e6;
    }

    #filter-bar {
        height: 3;
        dock: top;
        background: #1a1a1e;
        layout: horizontal;
        padding: 0 1;
        align-vertical: middle;
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

    #threat-bar-container {
        width: auto;
        dock: right;
        padding: 0 1;
        align-vertical: middle;
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

    def __init__(self, file_path: Optional[Path] = None, is_demo: bool = False):
        super().__init__()
        self.file_path = file_path
        self.is_demo = is_demo
        self.records: List[EventRecord] = []
        self.record_map: Dict[int, EventRecord] = {}
        self.active_filter: str = "all"
        self.search_query: str = ""

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="filter-bar"):
            yield Input(placeholder="🔍 Search across events (regex, username, command)... [/]", id="search-input")
        with Container(id="quick-filters"):
            yield Button("[1] All", id="btn-all", classes="filter-btn -active")
            yield Button("[2] 🚨 Threats", id="btn-threats", classes="filter-btn")
            yield Button("[3] 🔑 Failed", id="btn-failed", classes="filter-btn")
            yield Button("[4] 💻 Process", id="btn-process", classes="filter-btn")
            yield Button("[5] ⚡ PS", id="btn-ps", classes="filter-btn")
            yield Button("[6] 🧹 Cleared", id="btn-cleared", classes="filter-btn")
            with Container(id="threat-bar-container"):
                yield ThreatStatusBar(id="threat-status-bar")
        with Horizontal(id="main-split"):
            with Vertical(id="table-container"):
                yield DataTable(id="events-table", cursor_type="row")
            with Vertical(id="inspector-container"):
                yield Inspector(id="inspector")
        yield Footer()

    def on_mount(self) -> None:
        if self.is_demo:
            self.title = "nevtx [DEMO MODE - Simulated DFIR Triage]"
        elif self.file_path:
            self.title = f"nevtx - {self.file_path.name}"
        else:
            self.title = "nevtx"

        table = self.query_one(DataTable)
        table.add_columns("Time", "ID", "Threat / Level", "MITRE", "Summary")
        self.load_events()

    def load_events(self) -> None:
        self.records.clear()
        self.record_map.clear()

        if self.is_demo:
            raw_records = generate_mock_events()
        elif self.file_path:
            parser = FastEvtxParser()
            try:
                raw_records = list(parser.parse(self.file_path))
            except Exception as e:
                self.notify(f"Error loading {self.file_path.name}: {e}", severity="error")
                raw_records = []
        else:
            raw_records = []

        for record in raw_records:
            self.records.append(record)
            self.record_map[record.record_id] = record

        # Update threat ratio bar
        threat_bar = self.query_one(ThreatStatusBar)
        threat_bar.update_stats(self.records)

        self.apply_filter()

    def apply_filter(self) -> None:
        table = self.query_one(DataTable)
        table.clear()

        query = self.search_query.lower()

        for record in self.records:
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
