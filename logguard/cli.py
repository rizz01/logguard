"""Command-line interface."""
import argparse
import sys
from datetime import datetime

from . import __version__
from .detector import analyze
from .parser import parse_lines, parse_web_lines
from .report import to_csv, to_json, to_markdown, to_text

FORMATS = {"text": to_text, "json": to_json, "md": to_markdown, "csv": to_csv}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="logguard", description="Detect SSH brute-force activity in auth logs.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    p.add_argument("logfile", help="path to a log file (e.g. /var/log/auth.log)")
    p.add_argument("--type", choices=["ssh", "web"], default="ssh", help="log type: ssh auth log or web access log (default ssh)")
    p.add_argument("-t", "--threshold", type=int, default=5, help="failures per window to alert (default 5)")
    p.add_argument("-w", "--window", type=int, default=60, help="window in seconds (default 60)")
    p.add_argument("-y", "--year", type=int, default=datetime.now().year, help="year of the log (syslog has none)")
    p.add_argument("-f", "--format", choices=FORMATS, default="text")
    p.add_argument("-o", "--output", help="write the report to a file instead of the screen")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        with open(args.logfile, encoding="utf-8", errors="replace") as fh:
            events = parse_lines(fh, args.year) if args.type == "ssh" else parse_web_lines(fh)
            alerts = analyze(events, args.threshold, args.window, args.type)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    report = FORMATS[args.format](alerts)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report + "\n")
        print(f"Report written to {args.output} ({len(alerts)} alert(s))")
    else:
        print(report)
    return 1 if alerts else 0  # non-zero exit lets scripts/CI react to findings
