"""Parse Linux authentication logs (auth.log, secure) into a pandas DataFrame.

Recognised events: sshd failed and accepted logins, sudo commands and sudo
failures. Other lines are counted and dropped. Log content is untrusted input:
lines are length-capped, decoded with replacement and never evaluated.
"""

from __future__ import annotations

import gzip
import io
import logging
import re
import zlib
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pandas as pd

log = logging.getLogger(__name__)

MAX_BYTES = 50 * 1024 * 1024
MAX_LINE = 4096
# sshd repeats a message at most MaxAuthTries times per connection; the cap bounds forged lines.
MAX_REPEAT = 20
COLUMNS = [
    "line_no", "timestamp", "utc", "host", "process", "pid", "event",
    "user", "src_ip", "method", "invalid", "raw",
]

_MONTHS = {m: i for i, m in enumerate("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), 1)}
# "Oct 15 08:12:33 host sshd[123]: msg"  or  "2026-10-15T08:12:33.123456+03:00 host sshd[123]: msg"
_HEADER = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2} {1,2}\d{1,2} \d\d:\d\d:\d\d"
    r"|\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|[+-]\d\d:?\d\d)?)"
    r" (?P<host>\S+) (?P<proc>[\w./-]+)(?:\[(?P<pid>\d+)\])?: ?(?P<msg>.*)$"
)
# rsyslog's RepeatedMsgReduction (on by default on Ubuntu) folds identical lines into this.
_REPEATED = re.compile(r"^message repeated (\d+) times: \[ ?(.*)\]$")
_SSHD = (
    # The username is attacker text and may hold spaces or " from X port N"; the greedy match
    # takes the last " from ... port", which is the one sshd appended.
    ("failed", re.compile(
        r"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>.*) from (?P<ip>\S+) port \d+")),
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


def _timestamp(ts: str) -> tuple[datetime | None, datetime | None, tuple[int, ...] | None]:
    """(wall clock, UTC, None) for ISO 8601; (None, None, (month, day, h, m, s)) for legacy syslog."""
    if ts[0].isdigit():
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        wall = dt.replace(tzinfo=None)  # the host's wall-clock time, used for business hours
        return wall, (dt.astimezone(UTC).replace(tzinfo=None) if dt.tzinfo else wall), None
    mon, day, hms = ts.split()
    if mon not in _MONTHS:
        raise ValueError(f"unknown month {mon!r}")
    parts = (_MONTHS[mon], int(day), *(int(x) for x in hms.split(":")))
    datetime(2000, *parts)  # validate in a leap year; the real year is applied after the whole file is read
    return None, None, parts


def _classify(proc: str, msg: str) -> tuple[str | None, dict]:
    rules = _SSHD if proc.startswith("sshd") else _SUDO if proc == "sudo" else ()
    for event, rx in rules:
        m = rx.match(msg)
        if m:
            return event, m.groupdict()
    return None, {}


def _default_year(last: tuple[int, tuple[int, ...]]) -> int:
    """Year of the first legacy line: the latest one that keeps the last line of the file in the past."""
    wraps, parts = last
    now = datetime.now()
    base = now.year - wraps
    try:
        # a day of slack: a log from a host east of the analyst may run a few hours ahead
        if datetime(now.year, *parts) > now + timedelta(days=1):
            base -= 1
    except ValueError:  # 29 February outside a leap year
        pass
    return base


def parse_lines(lines: Iterable[str], year: int | None = None, source: str = "-",
                max_bytes: int = MAX_BYTES) -> ParsedLog:
    """Parse an iterable of log lines. Raises ValueError when the input exceeds max_bytes.

    Legacy 'Oct 15 08:12:33' stamps carry no year. `year` is the year of the first one, a month more
    than one earlier than the line before (December to January) starts the next year, and without
    `year` the latest year that keeps the last line in the past is used.
    """
    rows: list[list] = []
    legacy: list[tuple[list, int, tuple[int, ...]]] = []  # (row, New Years since the first line, stamp)
    last: tuple[int, tuple[int, ...]] | None = None
    unparsed = ignored = n = size = wraps = prev_month = 0
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
            ts, utc, parts = _timestamp(h["ts"])
        except ValueError:
            unparsed += 1
            continue
        if parts:
            if parts[0] < prev_month - 1:  # one month back is clock jitter at a month end; more is New Year
                wraps += 1
            prev_month, last = parts[0], (wraps, parts)
        msg, times = h["msg"], 1
        rep = _REPEATED.match(msg)
        if rep:
            msg, times = rep[2], min(int(rep[1]), MAX_REPEAT)
        event, g = _classify(h["proc"], msg)
        if not event:
            ignored += 1
            continue
        row = [n, ts, utc, h["host"], h["proc"], h["pid"], event, g.get("user") or None,
               g.get("ip"), g.get("method"), bool(g.get("invalid")), line]
        if parts:
            legacy.append((row, wraps, parts))
        rows += [row] * times  # a folded "message repeated" line counts once per repetition
    if legacy:
        base = year if year is not None else _default_year(last)
        for row, w, parts in legacy:
            try:
                row[1] = row[2] = datetime(base + w, *parts)
            except ValueError:  # 29 February outside a leap year
                unparsed += 1
        rows = [r for r in rows if r[1] is not None]
    df = pd.DataFrame(rows, columns=COLUMNS)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["utc"] = pd.to_datetime(df["utc"])
    log.info("%s: %d lines, %d events, %d unparsed, %d ignored", source, n, len(df), unparsed, ignored)
    return ParsedLog(df, source, n, unparsed, ignored)


def parse_text(text: str, year: int | None = None, source: str = "-",
               max_bytes: int = MAX_BYTES) -> ParsedLog:
    # split on "\n" only, so line numbers match grep -n and editors (splitlines() also breaks on \f, \u2028 ...)
    return parse_lines(text.removesuffix("\n").split("\n") if text else [], year, source, max_bytes)


def parse_bytes(data: bytes, name: str, year: int | None = None, max_bytes: int = MAX_BYTES) -> ParsedLog:
    """Parse raw log bytes. A `.gz` name is decompressed, reading at most max_bytes + 1 bytes of output."""
    if len(data) > max_bytes:
        raise ValueError(f"{name}: file exceeds {max_bytes} bytes")
    if name.endswith(".gz"):
        try:
            data = gzip.GzipFile(fileobj=io.BytesIO(data)).read(max_bytes + 1)
        except (OSError, EOFError, zlib.error) as e:
            raise ValueError(f"{name}: damaged or truncated gzip data ({e})") from e
        if len(data) > max_bytes:
            raise ValueError(f"{name}: input exceeds {max_bytes} bytes after decompression")
    return parse_text(data.decode("utf-8", "replace"), year, name, max_bytes)


def parse_file(path: str | Path, year: int | None = None, max_bytes: int = MAX_BYTES) -> ParsedLog:
    """Parse a log file; `.gz` rotations are read transparently."""
    path = Path(path)
    with open(path, "rb") as fh:
        data = fh.read(max_bytes + 1)
    return parse_bytes(data, path.name, year, max_bytes)
