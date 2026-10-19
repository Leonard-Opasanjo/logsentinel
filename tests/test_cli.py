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
