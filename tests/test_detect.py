import pandas as pd
import pytest

from logsentinel.detect import (
    Config,
    _burst,
    failed_logins,
    off_hours_logins,
    run_all,
    success_after_failures,
    to_frame,
    untrusted_source_logins,
)
from logsentinel.parser import COLUMNS, parse_lines

CFG = Config()


def ev(*rows):
    """rows: (timestamp, event, user, src_ip[, method])"""
    recs = [dict(line_no=i, timestamp=pd.Timestamp(r[0]), host="h", process="sshd", pid="1", event=r[1],
                 user=r[2], src_ip=r[3], method=r[4] if len(r) > 4 else "password", invalid=False, raw=f"line {i}")
            for i, r in enumerate(rows, 1)]
    return pd.DataFrame(recs, columns=COLUMNS)


def fails(ip, start, n, step_s, user="root"):
    t0 = pd.Timestamp(start)
    return [(t0 + pd.Timedelta(seconds=step_s * i), "failed", user, ip) for i in range(n)]


def test_burst():
    ts = pd.Series(pd.to_datetime(["2026-10-15 10:00", "2026-10-15 10:03", "2026-10-15 10:30",
                                   "2026-10-15 10:31", "2026-10-15 10:32"]))
    w = pd.Timedelta(minutes=10)
    assert _burst(ts, 3, w) and _burst(ts, 1, w)
    assert not _burst(ts, 4, w) and not _burst(ts, 6, w)


def test_repeated_failures_threshold():
    assert failed_logins(ev(*fails("203.0.113.1", "2026-10-15 10:00", 4, 60)), CFG) == []
    (f,) = failed_logins(ev(*fails("203.0.113.1", "2026-10-15 10:00", 5, 60)), CFG)
    assert (f.rule, f.severity, f.count, f.src_ip, f.user) == ("repeated_failures", "medium", 5, "203.0.113.1", "root")
    assert f.evidence == [1, 2, 3, 4, 5]


def test_slow_failures_are_not_a_burst():
    assert failed_logins(ev(*fails("203.0.113.1", "2026-10-15 10:00", 8, 3600)), CFG) == []


def test_brute_force():
    (f,) = failed_logins(ev(*fails("203.0.113.1", "2026-10-15 10:00", 20, 5)), CFG)
    assert (f.rule, f.severity, f.count) == ("brute_force", "high", 20)


def test_password_spray_wins_over_count():
    rows = [(pd.Timestamp("2026-10-15 10:00") + pd.Timedelta(minutes=20 * i), "failed", f"user{i}", "203.0.113.1")
            for i in range(7)]
    (f,) = failed_logins(ev(*rows), CFG)
    assert (f.rule, f.severity, f.count) == ("password_spray", "high", 7)
    assert "user0" in f.description and "(+2 more)" in f.user


def test_one_finding_per_ip():
    rows = fails("203.0.113.1", "2026-10-15 10:00", 25, 5) + fails("203.0.113.2", "2026-10-15 10:00", 5, 5)
    assert sorted(f.rule for f in failed_logins(ev(*rows), CFG)) == ["brute_force", "repeated_failures"]


def test_success_after_failures():
    rows = fails("10.0.1.77", "2026-10-15 10:00", 3, 60) + [("2026-10-15 10:05", "accepted", "bob", "10.0.1.77")]
    (f,) = success_after_failures(ev(*rows), CFG)
    assert (f.rule, f.severity, f.user, f.count, f.evidence) == ("success_after_failures", "critical", "bob", 4, [1, 2, 3, 4])


def test_success_ignores_old_failures_and_other_ips():
    rows = fails("10.0.1.77", "2026-10-15 08:00", 3, 60) + [("2026-10-15 10:05", "accepted", "bob", "10.0.1.77")]
    assert success_after_failures(ev(*rows), CFG) == []
    rows = fails("10.0.1.78", "2026-10-15 10:00", 3, 60) + [("2026-10-15 10:05", "accepted", "bob", "10.0.1.77")]
    assert success_after_failures(ev(*rows), CFG) == []


def test_success_counts_failures_once():
    rows = fails("10.0.1.77", "2026-10-15 10:00", 3, 60) + [
        ("2026-10-15 10:05", "accepted", "bob", "10.0.1.77"), ("2026-10-15 10:09", "accepted", "bob", "10.0.1.77")]
    assert len(success_after_failures(ev(*rows), CFG)) == 1


def test_off_hours():
    rows = [("2026-10-15 03:00", "accepted", "alice", "10.0.1.20"),   # Thursday night
            ("2026-10-17 12:00", "accepted", "bob", "10.0.1.21"),     # Saturday noon
            ("2026-10-15 12:00", "accepted", "carol", "10.0.1.22"),   # Thursday noon
            ("2026-10-15 23:30", "accepted", "root", "10.0.1.23")]
    out = {f.user: f.severity for f in off_hours_logins(ev(*rows), CFG)}
    assert out == {"alice": "low", "bob": "low", "root": "high"}


def test_business_hours_boundaries():
    cfg = Config(business_hours=(9, 17))
    rows = [("2026-10-15 09:00", "accepted", "a", "10.0.0.1"), ("2026-10-15 17:00", "accepted", "b", "10.0.0.1"),
            ("2026-10-15 16:59", "accepted", "c", "10.0.0.1"), ("2026-10-15 08:59", "accepted", "d", "10.0.0.1")]
    assert {f.user for f in off_hours_logins(ev(*rows), cfg)} == {"b", "d"}


def test_untrusted_source():
    rows = [("2026-10-15 12:00", "accepted", "erin", "198.51.100.77"),
            ("2026-10-15 12:00", "accepted", "root", "203.0.113.9"),
            ("2026-10-15 12:00", "accepted", "alice", "10.0.1.20"),
            ("2026-10-15 12:00", "accepted", "dave", "not-an-ip")]
    out = {f.user: f.severity for f in untrusted_source_logins(ev(*rows), CFG)}
    assert out == {"erin": "medium", "root": "high", "dave": "medium"}
    cfg = Config(trusted_networks=("198.51.100.0/24",))
    assert {f.user for f in untrusted_source_logins(ev(*rows), cfg)} == {"root", "alice", "dave"}


def test_run_all_orders_and_numbers():
    rows = (fails("203.0.113.9", "2026-10-17 02:11", 4, 60)
            + [("2026-10-17 02:17", "accepted", "dave", "203.0.113.9")]
            + fails("203.0.113.45", "2026-10-15 03:12", 25, 3))
    out = run_all(ev(*rows))
    assert [f.id for f in out] == ["LS-001", "LS-002", "LS-003", "LS-004"]
    assert [f.rule for f in out] == ["success_after_failures", "brute_force", "untrusted_source", "off_hours_login"]
    df = to_frame(out)
    assert list(df.id) == [f.id for f in out] and len(df.columns) == 9


def test_run_all_empty():
    assert run_all(parse_lines([]).events, CFG) == []
    assert to_frame([]).empty


@pytest.mark.parametrize("kw", [
    dict(fail_threshold=0), dict(window_minutes=0), dict(business_hours=(19, 7)), dict(business_hours=(0, 25)),
    dict(trusted_networks=("10.0.0.0/33",)), dict(trusted_networks=("nope",)),
])
def test_config_validation(kw):
    with pytest.raises(ValueError):
        Config(**kw)


def test_config_accepts_host_bits_and_ipv6():
    cfg = Config(trusted_networks=("10.0.0.5/8", "fd00::/8"))
    assert len(cfg.networks) == 2
    rows = [("2026-10-15 12:00", "accepted", "a", "fd00::1"), ("2026-10-15 12:00", "accepted", "b", "2001:db8::1")]
    assert {f.user for f in untrusted_source_logins(ev(*rows), cfg)} == {"b"}
