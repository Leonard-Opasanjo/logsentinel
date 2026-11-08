import gzip
import tracemalloc
from datetime import datetime, timedelta

import pytest

from logsentinel.parser import COLUMNS, MAX_LINE, MAX_REPEAT, parse_file, parse_lines, parse_text

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


def _legacy(t: datetime, msg: str = "Failed password for root from 203.0.113.45 port 1 ssh2") -> str:
    return f"{t:%b} {t.day:2d} {t:%H:%M:%S} h sshd[1]: {msg}"


def test_default_year_keeps_the_log_in_the_past():
    past, future = datetime.now() - timedelta(days=2), datetime.now() + timedelta(days=3)
    assert parse_lines([_legacy(past)]).events.timestamp[0].year == past.year
    # a date later than today cannot be this year's: it is last year's
    assert parse_lines([_legacy(future)]).events.timestamp[0].year == future.year - 1


def test_legacy_year_rolls_over_at_new_year():
    lines = [_legacy(datetime(2025, 12, 31, 23, 58)), _legacy(datetime(2025, 11, 30, 23, 59)),  # one month back is not New Year
             _legacy(datetime(2026, 1, 1, 0, 1))]
    assert [t.year for t in parse_lines(lines, year=2025).events.timestamp] == [2025, 2025, 2026]


def test_utc_column_orders_across_a_dst_change():
    lines = ["2026-10-25T01:55:00+01:00 h sshd[1]: Failed password for dave from 10.0.1.9 port 1 ssh2",
             "2026-10-25T01:05:00+00:00 h sshd[2]: Accepted password for dave from 10.0.1.9 port 2 ssh2",
             "2026-11-08T18:05:01+0300 h sshd[3]: Accepted password for dave from 10.0.1.9 port 3 ssh2"]  # journalctl
    ev = parse_lines(lines).events
    assert ev.timestamp.tolist() == [datetime(2026, 10, 25, 1, 55), datetime(2026, 10, 25, 1, 5),
                                     datetime(2026, 11, 8, 18, 5, 1)]  # wall clock, for business hours
    assert ev.utc.tolist() == [datetime(2026, 10, 25, 0, 55), datetime(2026, 10, 25, 1, 5),
                               datetime(2026, 11, 8, 15, 5, 1)]


def test_hostile_usernames_cannot_hide_or_move_the_source():
    lines = [f"Oct  7 08:12:3{i} h sshd[1]: Failed password for invalid user {u} from 203.0.113.5 port 4444 ssh2"
             for i, u in enumerate(["admin x", "a from 10.0.1.20 port 1", "root from 10.0.1.20 port 22 ssh2"])]
    ev = parse_lines(lines, year=2026).events
    assert len(ev) == 3 and set(ev.src_ip) == {"203.0.113.5"}
    assert ev.user.tolist() == ["admin x", "a from 10.0.1.20 port 1", "root from 10.0.1.20 port 22 ssh2"]


def test_message_repeated_counts_every_repetition():
    lines = ["Oct  7 08:00:00 h sshd[7]: Failed password for dave from 10.0.1.9 port 5555 ssh2",
             "Oct  7 08:00:04 h sshd[7]: message repeated 2 times: [ Failed password for dave from 10.0.1.9 port 5555 ssh2]",
             "Oct  7 08:00:09 h sshd[8]: message repeated 99999 times: [ Failed password for dave from 10.0.1.9 port 6 ssh2]"]
    p = parse_lines(lines, year=2026)
    assert p.events.line_no.tolist() == [1, 2, 2] + [3] * MAX_REPEAT and p.ignored == 0


def test_bad_month_is_unparsed_not_fatal():
    p = parse_lines(["Xyz 15 08:12:33 h sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2", LEGACY_FAIL])
    assert (p.unparsed, len(p.events)) == (1, 1)


def test_damaged_gzip_is_a_clean_error(tmp_path):
    good = gzip.compress((LEGACY_FAIL + "\n").encode() * 200)
    for name, data in [("truncated.log.gz", good[: len(good) // 2]),
                       ("corrupt.log.gz", good[:10] + b"garbage" * 20), ("plain.log.gz", b"not gzip at all")]:
        (tmp_path / name).write_bytes(data)
        with pytest.raises(ValueError, match="gzip"):
            parse_file(tmp_path / name)


def test_gzip_single_line_bomb_is_refused_without_inflating_it(tmp_path):
    f = tmp_path / "bomb.log.gz"
    f.write_bytes(gzip.compress(b"A" * (20 * 2**20)))  # 20 MB with no newline, about 20 KB compressed
    tracemalloc.start()
    with pytest.raises(ValueError, match="exceeds"):
        parse_file(f, max_bytes=1000)
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    assert peak < 2 * 2**20


def test_line_numbers_match_the_file(tmp_path):
    f = tmp_path / "auth.log"
    f.write_bytes(b"Oct  7 08:00:00 h CRON[1]: form \x0c feed\nOct  7 08:00:01 h app[2]: lone\rcr and \xe2\x80\xa8 LS\n"
                  + LEGACY_FAIL.encode() + b"\n")
    assert parse_file(f, 2026).events.line_no.tolist() == [3]  # the line grep -n reports
    assert parse_text(f.read_bytes().decode(), 2026).events.line_no.tolist() == [3]


def test_empty_invalid_username():
    line = "Oct  7 08:12:33 h sshd[1]: Failed password for invalid user  from 203.0.113.45 port 50122 ssh2"
    ev = parse_lines([line]).events
    assert ev.user[0] is None and bool(ev.invalid[0]) and ev.src_ip[0] == "203.0.113.45"


def test_non_utf8_bytes_do_not_crash(tmp_path):
    f = tmp_path / "auth.log"
    f.write_bytes(ISO_OK.encode() + b" \xff\xfe\n" + GARBAGE.encode() + b"\n")
    p = parse_file(f)
    assert len(p.events) == 1 and p.unparsed == 1
