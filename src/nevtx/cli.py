import argparse
from pathlib import Path
import sys

from nevtx import __version__
from nevtx.ui.app import NevtxApp


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="nevtx",
        description="A modern, lightweight Windows Event Log (.evtx) TUI viewer for Linux.",
    )
    parser.add_argument(
        "file",
        nargs="?",
        type=Path,
        help="Path to the Windows Event Log (.evtx) file to inspect.",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Launch nevtx with simulated DFIR incident response event logs for demonstration.",
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

    if not args.file:
        parser.print_help()
        print("\n[!] Please specify a path to an .evtx file or use --demo to test.")
        sys.exit(1)

    evtx_path = args.file.expanduser().resolve()
    if not evtx_path.exists():
        print(f"[!] File not found: {evtx_path}")
        sys.exit(1)

    app = NevtxApp(file_path=evtx_path)
    app.run()


if __name__ == "__main__":
    main()
