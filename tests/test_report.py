import json

import pandas as pd

from logsentinel.detect import Config, run_all
from logsentinel.parser import parse_lines
from logsentinel.report import severity_counts, timeline, to_json, to_markdown


def _parsed():
    lines = [f"2026-10-17T02:1{i}:00+03:00 bastion sshd[1]: Failed password for invalid user `x` from 203.0.113.9 "
             "port 1 ssh2" for i in range(1, 4)]
    lines.append("2026-10-17T02:17:00+03:00 bastion sshd[2]: Accepted password for dave from 203.0.113.9 port 2 ssh2")
    return parse_lines(lines, source="unit.log")


def test_markdown_report():
    p = _parsed()
    f = run_all(p.events)
    assert [x.rule for x in f] == ["success_after_failures", "untrusted_source", "off_hours_login"]
    md = to_markdown(p, f, Config(), notes={f[0].id: "Checked with dave.\nVerdict: compromised."})
    assert md.startswith("# LogSentinel incident report")
    assert "`unit.log`" in md and "### LS-001 · CRITICAL" in md and "Checked with dave." in md
    assert md.count("```") == 2 * len(f)              # every evidence fence is closed
    assert "`x`" not in md and "'x'" in md             # log-derived backticks cannot break the fence
    assert "| critical | 1 |" in md and "## Timeline" in md and "| fail_threshold | 5 |" in md
    assert "**Analyst notes:** _none_" in md


def test_json_report():
    p = _parsed()
    f = run_all(p.events)
    doc = json.loads(to_json(p, f, Config(), notes={"LS-001": "n"}))
    assert doc["stats"] == {"lines": 4, "events": 4, "unparsed": 0, "ignored": 0}
    assert doc["severity_counts"] == {"critical": 1, "high": 0, "medium": 1, "low": 1}
    first = doc["findings"][0]
    assert first["id"] == "LS-001" and first["notes"] == "n" and first["evidence"][0]["line"] == 1
    assert "Failed password" in first["evidence"][0]["raw"] and first["first_seen"].startswith("2026-10-17T02:11")
    assert doc["findings"][1]["notes"] == ""


def test_empty_log_reports():
    p = parse_lines([], source="empty.log")
    assert "No findings" in to_markdown(p, [], Config())
    assert json.loads(to_json(p, [], Config()))["findings"] == []


def test_timeline_and_counts():
    tl = timeline(_parsed().events, "1h")
    assert tl.loc[pd.Timestamp("2026-10-17 02:00"), "failed"] == 3
    assert tl.loc[pd.Timestamp("2026-10-17 02:00"), "accepted"] == 1
    assert timeline(parse_lines([]).events).empty
    assert severity_counts([]) == {"critical": 0, "high": 0, "medium": 0, "low": 0}
