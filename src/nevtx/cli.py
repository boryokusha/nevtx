import argparse
from pathlib import Path
import sys

from nevtx import __version__
from nevtx.ui.app import NevtxApp


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="nevtx",
        description="A modern, lightweight Windows Event Log (.evtx) TUI viewer and triage tool for Linux.",
    )
    parser.add_argument(
        "target",
        nargs="?",
        type=Path,
        help="Path to an .evtx file OR a directory containing multiple .evtx files (e.g. ~/documents/evtx_files).",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Launch nevtx with simulated multi-file DFIR triage logs & intentional log gap anomalies.",
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    args = parser.parse_args()

    if args.demo:
        app = NevtxApp(is_demo=True)
        app.run()
        return

    # If no target specified, check current working directory for any .evtx files
    target_path = args.target
    if not target_path:
        cwd = Path.cwd()
        evtx_in_cwd = list(cwd.glob("*.evtx"))
        if evtx_in_cwd:
            target_path = cwd
        else:
            parser.print_help()
            print("\n[!] Please specify a path to an .evtx file, a directory of logs, or use --demo to test.")
            sys.exit(1)

    resolved = target_path.expanduser().resolve()
    if not resolved.exists():
        print(f"[!] Path not found: {resolved}")
        sys.exit(1)

    if resolved.is_dir():
        app = NevtxApp(folder_path=resolved)
    else:
        app = NevtxApp(file_path=resolved)

    app.run()


if __name__ == "__main__":
    main()
