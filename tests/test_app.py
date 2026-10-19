from pathlib import Path

from streamlit.testing.v1 import AppTest

APP = Path(__file__).resolve().parents[1] / "src/logsentinel/app.py"


def test_dashboard_renders_sample_and_keeps_notes():
    at = AppTest.from_file(str(APP), default_timeout=60).run()
    assert not at.exception
    metrics = {m.label: m.value for m in at.metric}
    assert metrics["Critical"] == "2" and metrics["High"] == "3" and metrics["Medium / Low"] == "3 / 2"
    assert at.selectbox[0].options[0].startswith("LS-001 · CRITICAL")
    at.text_area(key="note-LS-001").input("Spoke to dave; account disabled.").run()
    assert not at.exception and at.session_state["note-LS-001"] == "Spoke to dave; account disabled."


def test_dashboard_rejects_bad_settings():
    at = AppTest.from_file(str(APP), default_timeout=60)
    at.run()
    at.sidebar.text_area[0].input("not-a-cidr").run()
    assert not at.exception and at.error and "Settings" in at.error[0].value
