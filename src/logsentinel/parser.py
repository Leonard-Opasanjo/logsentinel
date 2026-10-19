"""Parse Linux authentication logs (auth.log, secure) into a pandas DataFrame.

Recognised events: sshd failed and accepted logins, sudo commands and sudo
failures. Other lines are counted and dropped. Log content is untrusted input:
lines are length-capped, decoded with replacement and never evaluated.
"""

from __future__ import annotations

import gzip
import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import pandas as pd

log = logging.getLogger(__name__)

MAX_BYTES = 50 * 1024 * 1024
MAX_LINE = 4096
COLUMNS = [
    "line_no", "timestamp", "host", "process", "pid", "event",
    "user", "src_ip", "method", "invalid", "raw",
]

_MONTHS = {m: i for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)}
# "Oct 15 08:12:33 host sshd[123]: msg"  or  "2026-10-15T08:12:33.123456+03:00 host sshd[123]: msg"
_HEADER = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2} {1,2}\d{1,2} \d\d:\d\d:\d\d"
    r"|\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|[+-]\d\d:\d\d)?)"
    r" (?P<host>\S+) (?P<proc>[\w./-]+)(?:\[(?P<pid>\d+)\])?: ?(?P<msg>.*)$"
)
_SSHD = (
    ("failed", re.compile(
        r"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>\S*) from (?P<ip>\S+) port \d+")),
    ("accepted", re.compile(r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port \d+")),
)
_SUDO = (
    ("sudo_failed", re.compile(
        r"^ *(?P<user>\S+) : (?:\d+ incorrect password attempts?|user NOT in sudoers|command not allowed)")),
    ("sudo", re.compile(r"^ *(?P<user>\S+) : .*COMMAND=")),
)


@dataclass
class ParsedLog:
    events: pd.DataFrame
    source: str = "-"
    lines: int = 0
    unparsed: int = 0  # no recognisable syslog header, or an impossible timestamp
    ignored: int = 0  # valid line that is not an authentication event


def _timestamp(ts: str, year: int) -> datetime:
    if ts[0].isdigit():
        # ISO 8601: keep the host's wall-clock time; the UTC offset is dropped.
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).replace(tzinfo=None)
    mon, day, hms = ts.split()
    # shortcut: legacy syslog has no year, so one year is applied to the whole file;
    # upgrade to month-wrap detection if logs spanning New Year must be analysed.
    return datetime(year, _MONTHS[mon], int(day), *(int(x) for x in hms.split(":")))


def _classify(proc: str, msg: str) -> tuple[str | None, dict]:
    rules = _SSHD if proc.startswith("sshd") else _SUDO if proc == "sudo" else ()
    for event, rx in rules:
        m = rx.match(msg)
        if m:
            return event, m.groupdict()
    return None, {}


def parse_lines(lines: Iterable[str], year: int | None = None, source: str = "-",
                max_bytes: int = MAX_BYTES) -> ParsedLog:
    """Parse an iterable of log lines. Raises ValueError when the input exceeds max_bytes."""
    year = year or datetime.now().year
    rows: list[tuple] = []
    unparsed = ignored = n = size = 0
    for n, line in enumerate(lines, 1):
        size += len(line)
        if size > max_bytes:
            raise ValueError(f"{source}: input exceeds {max_bytes} bytes")
        line = line.rstrip("\r\n")[:MAX_LINE]
        h = _HEADER.match(line)
        if not h:
            unparsed += 1
            continue
        try:
            ts = _timestamp(h["ts"], year)
        except ValueError:
            unparsed += 1
            continue
        event, g = _classify(h["proc"], h["msg"])
        if not event:
            ignored += 1
            continue
        rows.append((n, ts, h["host"], h["proc"], h["pid"], event, g.get("user") or None,
                     g.get("ip"), g.get("method"), bool(g.get("invalid")), line))
    df = pd.DataFrame(rows, columns=COLUMNS)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    log.info("%s: %d lines, %d events, %d unparsed, %d ignored", source, n, len(df), unparsed, ignored)
    return ParsedLog(df, source, n, unparsed, ignored)


def parse_text(text: str, year: int | None = None, source: str = "-",
               max_bytes: int = MAX_BYTES) -> ParsedLog:
    return parse_lines(text.splitlines(), year, source, max_bytes)


def parse_file(path: str | Path, year: int | None = None, max_bytes: int = MAX_BYTES) -> ParsedLog:
    """Parse a log file; `.gz` rotations are read transparently."""
    path = Path(path)
    if path.stat().st_size > max_bytes:
        raise ValueError(f"{path}: file exceeds {max_bytes} bytes")
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
        return parse_lines(fh, year, path.name, max_bytes)
