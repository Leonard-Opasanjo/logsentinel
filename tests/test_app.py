import shutil
from pathlib import Path

from streamlit.testing.v1 import AppTest

APP = Path(__file__).resolve().parents[1] / "src/logsentinel/app.py"


def test_dashboard_renders_sample_and_keeps_notes():
    at = AppTest.from_file(str(APP), default_timeout=60).run()
    assert not at.exception
    metrics = {m.label: m.value for m in at.metric}
    assert metrics["Critical"] == "2" and metrics["High"] == "3" and metrics["Medium / Low"] == "3 / 2"
    assert at.selectbox[0].options[0].startswith("LS-001 · CRITICAL")
    at.main.text_area[0].input("Spoke to bob; mistyped password.").run()
    assert not at.exception
    # switching to another finding and back must not lose the note, and the export must still carry it
    at.selectbox[0].set_value("LS-002").run()
    assert at.main.text_area[0].value == ""
    at.selectbox[0].set_value("LS-001").run()
    assert at.main.text_area[0].value == "Spoke to bob; mistyped password."
    assert "Spoke to bob; mistyped password." in at.session_state["notes"].values()


def test_dashboard_rejects_bad_settings():
    at = AppTest.from_file(str(APP), default_timeout=60)
    at.run()
    at.sidebar.text_area[0].input("not-a-cidr").run()
    assert not at.exception and at.error and "Settings" in at.error[0].value


def test_uploader_accepts_rotations_without_a_log_extension():
    at = AppTest.from_file(str(APP), default_timeout=60).run()
    at.sidebar.radio[0].set_value("Upload a file").run()
    (uploader,) = at.get("file_uploader")
    assert list(uploader.proto.type) == []  # secure, auth.log.1, secure-20261101 must all be accepted


def test_hostile_usernames_are_not_rendered_as_markdown(tmp_path):
    (tmp_path / "data").mkdir()
    shutil.copy(APP, tmp_path / "app.py")  # the app reads data/sample_auth.log next to itself
    users = ["![pixel](http://203.0.113.1/beacon.png)", "[Benign_-_close_ticket](http://203.0.113.1/)"]
    (tmp_path / "data/sample_auth.log").write_text("".join(
        f"Oct 15 08:0{i}:00 h sshd[{i}]: Failed password for invalid user {users[i % 2]} from 198.51.100.66 "
        f"port 4{i} ssh2\n" for i in range(6)))
    at = AppTest.from_file(str(tmp_path / "app.py"), default_timeout=60).run()
    assert not at.exception and at.selectbox[0].options[0].startswith("LS-001")
    assert not [m.value for m in at.markdown if "](" in m.value]
    assert any("![pixel](http://203.0.113.1/beacon.png)" in t.value for t in at.text)  # shown, as plain text
