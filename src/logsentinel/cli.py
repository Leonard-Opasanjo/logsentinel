"""Command-line interface: `logsentinel analyze` and `logsentinel dashboard`."""

from __future__ import annotations

import argparse
import json
import logging
import subprocess  # nosec B404: only launches streamlit with a fixed argv
import sys
from pathlib import Path

from . import __version__
from .detect import Config, run_all
from .parser import parse_file
from .report import severity_counts, to_json, to_markdown

APP = Path(__file__).with_name("app.py")


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="logsentinel", description="Linux authentication log analyser")
    p.add_argument("--version", action="version", version=f"logsentinel {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="analyse an auth log, print findings, export reports")
    a.add_argument("logfile", type=Path, help="auth.log, secure, or a .gz rotation of one")
    a.add_argument("--year", type=int, help="year for legacy 'Oct 15 08:12:33' timestamps (default: current)")
    a.add_argument("--report", type=Path, metavar="FILE.md", help="write a Markdown incident report")
    a.add_argument("--json", type=Path, metavar="FILE.json", help="write findings and evidence as JSON")
    a.add_argument("--notes", type=Path, metavar="FILE.json",
                   help='analyst notes to merge into the reports, e.g. {"LS-001": "text"}')
    d = Config()
    a.add_argument("--fail-threshold", type=int, default=d.fail_threshold, metavar="N",
                   help="failures from one IP inside the window (default %(default)s)")
    a.add_argument("--brute-threshold", type=int, default=d.brute_threshold, metavar="N",
                   help="failures inside the window that count as brute force (default %(default)s)")
    a.add_argument("--spray-users", type=int, default=d.spray_users, metavar="N",
                   help="distinct usernames from one IP that count as spraying (default %(default)s)")
    a.add_argument("--window", type=int, default=d.window_minutes, metavar="MIN",
                   help="window for the failure thresholds (default %(default)s)")
    a.add_argument("--lookback", type=int, default=d.lookback_minutes, metavar="MIN",
                   help="failures this long before a success are suspicious (default %(default)s)")
    a.add_argument("--business-hours", default="7-19", metavar="START-END",
                   help="weekday hours that are not off-hours (default %(default)s)")
    a.add_argument("--trusted-network", action="append", metavar="CIDR",
                   help="repeatable; logins from elsewhere are flagged (default: RFC 1918 ranges)")
    a.add_argument("-v", "--verbose", action="store_true", help="debug logging")

    s = sub.add_parser("dashboard", help="start the Streamlit dashboard")
    s.add_argument("--host", default="localhost")
    s.add_argument("--port", type=int, default=8501)
    return p


def _config(args: argparse.Namespace) -> Config:
    start, _, end = args.business_hours.partition("-")
    return Config(
        fail_threshold=args.fail_threshold, brute_threshold=args.brute_threshold,
        spray_users=args.spray_users, window_minutes=args.window, lookback_minutes=args.lookback,
        business_hours=(int(start), int(end)),
        trusted_networks=tuple(args.trusted_network or Config().trusted_networks),
    )


def analyze(args: argparse.Namespace) -> int:
    cfg = _config(args)
    notes = json.loads(args.notes.read_text(encoding="utf-8")) if args.notes else {}
    if not isinstance(notes, dict):
        raise ValueError("--notes must be a JSON object keyed by finding id")
    parsed = parse_file(args.logfile, args.year)
    findings = run_all(parsed.events, cfg)
    counts = severity_counts(findings)
    summary = ", ".join(f"{v} {k}" for k, v in counts.items() if v) or "none"
    print(f"{parsed.source}: {parsed.lines} lines, {len(parsed.events)} auth events, "
          f"{len(findings)} findings ({summary})")
    for f in findings:
        print(f"  {f.id}  {f.severity:<8} {f.rule:<23} {f.title}")
    if args.report:
        args.report.write_text(to_markdown(parsed, findings, cfg, notes), encoding="utf-8")
        print(f"report written to {args.report}")
    if args.json:
        args.json.write_text(to_json(parsed, findings, cfg, notes), encoding="utf-8")
        print(f"json written to {args.json}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if getattr(args, "verbose", False) else logging.WARNING,
                        format="%(levelname)s %(name)s: %(message)s")
    if args.command == "dashboard":
        cmd = [sys.executable, "-m", "streamlit", "run", str(APP),
               "--server.address", args.host, "--server.port", str(args.port)]
        return subprocess.call(cmd)  # nosec B603: fixed argv, no shell
    try:
        return analyze(args)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
