import gzip
import json
import subprocess
import sys
from pathlib import Path

from logsentinel.cli import main

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = ROOT / "src/logsentinel/data/sample_auth.log"
RULES = {"success_after_failures", "brute_force", "password_spray", "repeated_failures", "off_hours_login",
         "untrusted_source"}


def test_analyze_sample(tmp_path, capsys):
    notes = tmp_path / "notes.json"
    notes.write_text(json.dumps({"LS-001": "Confirmed compromise."}))
    rc = main(["analyze", str(SAMPLE), "--report", str(tmp_path / "r.md"), "--json", str(tmp_path / "r.json"),
               "--notes", str(notes)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "10 findings" in out and "2 critical" in out
    doc = json.loads((tmp_path / "r.json").read_text())
    assert doc["severity_counts"] == {"critical": 2, "high": 3, "medium": 3, "low": 2}
    assert {f["rule"] for f in doc["findings"]} == RULES
    assert doc["findings"][0]["notes"] == "Confirmed compromise."
    assert "Confirmed compromise." in (tmp_path / "r.md").read_text()


def test_thresholds_change_results(capsys):
    assert main(["analyze", str(SAMPLE), "--trusted-network", "0.0.0.0/0", "--fail-threshold", "3"]) == 0
    out = capsys.readouterr().out
    assert "untrusted_source" not in out
    assert any("repeated_failures" in line and "203.0.113.9" in line for line in out.splitlines())


def test_errors_return_2(tmp_path, capsys):
    assert main(["analyze", str(tmp_path / "missing.log")]) == 2
    assert main(["analyze", str(SAMPLE), "--business-hours", "nine-five"]) == 2
    bad = tmp_path / "n.json"
    bad.write_text("[]")
    assert main(["analyze", str(SAMPLE), "--notes", str(bad)]) == 2
    assert capsys.readouterr().err.count("error:") == 3


def test_module_entry_point():
    r = subprocess.run([sys.executable, "-m", "logsentinel.cli", "--version"], capture_output=True, text=True)
    assert r.returncode == 0 and "logsentinel 0." in r.stdout


def test_sample_is_reproducible(tmp_path):
    out = tmp_path / "sample.log"
    subprocess.run([sys.executable, str(ROOT / "scripts/make_sample_log.py"), str(out)], check=True)
    assert out.read_bytes() == SAMPLE.read_bytes()


def test_sample_report_cites_the_attackers_sudo_commands(tmp_path, capsys):
    assert main(["analyze", str(SAMPLE), "--report", str(tmp_path / "r.md")]) == 0
    assert "467 lines, 280 auth events (0 unparsed, 187 other), 10 findings" in capsys.readouterr().out
    ls002 = (tmp_path / "r.md").read_text().split("### LS-002")[1].split("### LS-003")[0]
    assert "COMMAND=/usr/bin/cat /etc/shadow" in ls002 and "Evidence (7 of 7 lines)" in ls002


def test_notes_follow_the_finding_key_and_unknown_ids_warn(tmp_path, capsys):
    notes = tmp_path / "notes.json"
    notes.write_text(json.dumps({"off_hours_login/192.168.10.5/root/2026-10-17T04:40:07": "Admin maintenance.",
                                 "LS-099": "stale", "LS-001": None}))
    # these thresholds renumber the findings: the root login moves from LS-005 to LS-006
    assert main(["analyze", str(SAMPLE), "--fail-threshold", "2", "--brute-threshold", "5", "--window", "60",
                 "--json", str(tmp_path / "r.json"), "--report", str(tmp_path / "r.md"), "--notes", str(notes)]) == 0
    assert "warning: notes for LS-099 match no finding" in capsys.readouterr().err
    noted = {f["id"]: f["title"] for f in json.loads((tmp_path / "r.json").read_text())["findings"] if f["notes"]}
    assert noted == {"LS-006": "1 off-hours login(s) for root from 192.168.10.5"}


def test_damaged_gzip_exits_2(tmp_path, capsys):
    bad = tmp_path / "auth.log.2.gz"
    bad.write_bytes(gzip.compress(SAMPLE.read_bytes())[:3000])
    assert main(["analyze", str(bad)]) == 2
    assert "gzip" in capsys.readouterr().err


def test_dashboard_turns_telemetry_off_wherever_it_starts(monkeypatch):
    calls = []
    monkeypatch.setattr("logsentinel.cli.subprocess.call", lambda cmd: calls.append(cmd) or 0)
    assert main(["dashboard", "--port", "9000"]) == 0
    cmd = " ".join(calls[0])
    assert "streamlit run" in cmd and "--server.port 9000" in cmd and "--server.address localhost" in cmd
    assert "--browser.gatherUsageStats false" in cmd and "--server.maxUploadSize 50" in cmd
    assert "--server.headless true" in cmd
