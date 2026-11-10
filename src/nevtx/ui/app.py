import json
from pathlib import Path
from typing import Dict, List, Optional

from rich.syntax import Syntax
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import (
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    Static,
)

from nevtx.core.models import EventRecord
from nevtx.parsers.rust_engine import FastEvtxParser


class Inspector(Static):
    """Detail pane for inspecting the selected event record."""

    def display_record(self, record: Optional[EventRecord]) -> None:
        if not record:
            self.update("[dim]No record selected.[/dim]")
            return

        details = {
            "RecordID": record.record_id,
            "EventID": record.event_id,
            "TimeCreated": record.timestamp_str,
            "Provider": record.provider,
            "Channel": record.channel,
            "Level": record.level_display,
            "Computer": record.computer,
            "Summary": record.summary,
            "EventData": record.data,
        }

        json_str = json.dumps(details, indent=2, ensure_ascii=False)
        self.update(Syntax(json_str, "json", theme="monokai", word_wrap=True))


class NevtxApp(App):
    """Main Textual Application for nevtx."""

    CSS = """
    Screen {
        background: #121214;
        color: #e1e1e6;
    }

    #filter-container {
        height: 3;
        dock: top;
        background: #1a1a1e;
        padding: 0 1;
        layout: horizontal;
    }

    #search-input {
        width: 100%;
        border: none;
        background: #202024;
    }

    #main-split {
        height: 1fr;
        layout: horizontal;
    }

    #table-container {
        width: 60%;
        height: 100%;
        border-right: solid #2a2a30;
    }

    #inspector-container {
        width: 40%;
        height: 100%;
        background: #18181b;
        padding: 1;
        overflow-y: auto;
    }

    DataTable {
        height: 100%;
    }

    DataTable > .datatable--cursor {
        background: #3b82f6;
        color: #ffffff;
    }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("/", "focus_search", "Search"),
        ("escape", "unfocus_search", "Clear Focus"),
    ]

    def __init__(self, file_path: Path):
        super().__init__()
        self.file_path = file_path
        self.records: List[EventRecord] = []
        self.record_map: Dict[int, EventRecord] = {}

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Container(id="filter-container"):
            yield Input(placeholder="🔍 Search (Event ID, username, process, keyword)... [/]", id="search-input")
        with Horizontal(id="main-split"):
            with Vertical(id="table-container"):
                yield DataTable(id="events-table", cursor_type="row")
            with Vertical(id="inspector-container"):
                yield Label("📄 [bold cyan]Event Details[/bold cyan]")
                yield Inspector(id="inspector")
        yield Footer()

    def on_mount(self) -> None:
        self.title = f"nevtx - {self.file_path.name}"
        table = self.query_one(DataTable)
        table.add_columns("Time", "Event ID", "Level", "Provider", "Summary")
        self.load_events()

    def load_events(self) -> None:
        table = self.query_one(DataTable)
        table.clear()
        self.records.clear()
        self.record_map.clear()

        parser = FastEvtxParser()
        try:
            for record in parser.parse(self.file_path):
                self.records.append(record)
                self.record_map[record.record_id] = record

                # Styling level
                level_str = record.level_display
                if level_str in ("CRITICAL", "ERROR"):
                    level_styled = f"[bold red]{level_str}[/bold red]"
                elif level_str == "WARNING":
                    level_styled = f"[bold yellow]{level_str}[/bold yellow]"
                else:
                    level_styled = f"[green]{level_str}[/green]"

                table.add_row(
                    record.timestamp_str,
                    str(record.event_id),
                    level_styled,
                    record.provider[:24],
                    record.summary,
                    key=str(record.record_id),
                )
        except Exception as e:
            self.notify(f"Error loading {self.file_path.name}: {e}", severity="error")

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
        search_input = self.query_one("#search-input", Input)
        search_input.focus()

    def action_unfocus_search(self) -> None:
        table = self.query_one(DataTable)
        table.focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        query = event.value.strip().lower()
        table = self.query_one(DataTable)
        table.clear()

        for record in self.records:
            match = (
                not query
                or query in str(record.event_id)
                or query in record.provider.lower()
                or query in record.summary.lower()
                or query in record.computer.lower()
            )
            if match:
                level_str = record.level_display
                if level_str in ("CRITICAL", "ERROR"):
                    level_styled = f"[bold red]{level_str}[/bold red]"
                elif level_str == "WARNING":
                    level_styled = f"[bold yellow]{level_str}[/bold yellow]"
                else:
                    level_styled = f"[green]{level_str}[/green]"

                table.add_row(
                    record.timestamp_str,
                    str(record.event_id),
                    level_styled,
                    record.provider[:24],
                    record.summary,
                    key=str(record.record_id),
                )
