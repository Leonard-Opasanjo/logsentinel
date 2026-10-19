import gzip
from datetime import datetime

import pytest

from logsentinel.parser import COLUMNS, MAX_LINE, parse_file, parse_lines, parse_text

LEGACY_FAIL = "Oct  7 08:12:33 bastion-01 sshd[1234]: Failed password for invalid user admin from 203.0.113.45 port 50122 ssh2"
ISO_OK = ("2026-10-15T08:12:33.123456+03:00 bastion-01 sshd[1235]: Accepted publickey for alice from 10.0.1.20 "
          "port 51000 ssh2: ED25519 SHA256:abc")
ISO_FAIL = "2026-10-15T08:12:40Z bastion-01 sshd-session[1236]: Failed password for root from 203.0.113.45 port 50123 ssh2"
SUDO = ("2026-10-15T08:13:00+03:00 bastion-01 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; "
        "COMMAND=/usr/bin/apt update")
SUDO_FAIL = ("2026-10-15T08:14:00+03:00 bastion-01 sudo:    carol : 3 incorrect password attempts ; TTY=pts/1 ; "
             "PWD=/home/carol ; USER=root ; COMMAND=/bin/bash")
NOISE = "2026-10-15T08:15:00+03:00 bastion-01 CRON[99]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)"
GARBAGE = "this is not a syslog line"
BAD_DATE = "Feb 30 08:12:33 bastion-01 sshd[1]: Accepted password for bob from 10.0.0.1 port 1 ssh2"


def test_events_and_fields():
    p = parse_lines([LEGACY_FAIL, ISO_OK, ISO_FAIL, SUDO, SUDO_FAIL, NOISE, GARBAGE, BAD_DATE], year=2026)
    ev = p.events
    assert list(ev.columns) == COLUMNS
    assert ev.event.tolist() == ["failed", "accepted", "failed", "sudo", "sudo_failed"]
    assert (p.lines, p.unparsed, p.ignored) == (8, 2, 1)
    f = ev.iloc[0]
    assert (f.user, f.src_ip, f.method, bool(f.invalid), f.line_no) == ("admin", "203.0.113.45", "password", True, 1)
    assert f.timestamp == datetime(2026, 10, 7, 8, 12, 33)
    ok = ev.iloc[1]
    assert ok.timestamp == datetime(2026, 10, 15, 8, 12, 33, 123456)  # wall clock kept, offset dropped
    assert not ok.invalid and ok.method == "publickey"
    assert ev.iloc[2].process == "sshd-session" and ev.iloc[2].timestamp.hour == 8
    assert ev.iloc[3].user == "alice" and ev.iloc[4].user == "carol"


def test_empty_input_keeps_schema():
    p = parse_lines([])
    assert p.events.empty and list(p.events.columns) == COLUMNS and p.lines == 0
    assert str(p.events.timestamp.dtype).startswith("datetime64")


def test_long_line_is_truncated_not_fatal():
    p = parse_lines([ISO_OK + "x" * (MAX_LINE * 2)])
    assert len(p.events) == 1 and len(p.events.raw[0]) == MAX_LINE


def test_size_limits(tmp_path):
    f = tmp_path / "auth.log"
    f.write_text(ISO_OK + "\n")
    with pytest.raises(ValueError, match="exceeds"):
        parse_file(f, max_bytes=10)
    with pytest.raises(ValueError, match="exceeds"):
        parse_text((ISO_OK + "\n") * 3, max_bytes=100)


def test_gzip_and_explicit_year(tmp_path):
    f = tmp_path / "auth.log.1.gz"
    with gzip.open(f, "wt") as fh:
        fh.write(LEGACY_FAIL + "\n")
    p = parse_file(f, year=2025)
    assert p.source == "auth.log.1.gz" and p.events.timestamp[0].year == 2025


def test_default_year_is_current():
    assert parse_lines([LEGACY_FAIL]).events.timestamp[0].year == datetime.now().year


def test_empty_invalid_username():
    line = "Oct  7 08:12:33 h sshd[1]: Failed password for invalid user  from 203.0.113.45 port 50122 ssh2"
    ev = parse_lines([line]).events
    assert ev.user[0] is None and bool(ev.invalid[0]) and ev.src_ip[0] == "203.0.113.45"


def test_non_utf8_bytes_do_not_crash(tmp_path):
    f = tmp_path / "auth.log"
    f.write_bytes(ISO_OK.encode() + b" \xff\xfe\n" + GARBAGE.encode() + b"\n")
    p = parse_file(f)
    assert len(p.events) == 1 and p.unparsed == 1
