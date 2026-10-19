"""LogSentinel dashboard. Run with `logsentinel dashboard` or `streamlit run src/logsentinel/app.py`."""

from __future__ import annotations

import gzip
import io
from datetime import datetime
from pathlib import Path

import streamlit as st

from logsentinel import __version__
from logsentinel.detect import Config, run_all, to_frame
from logsentinel.parser import MAX_BYTES, ParsedLog, parse_text
from logsentinel.report import severity_counts, timeline, to_json, to_markdown

SAMPLE = Path(__file__).with_name("data") / "sample_auth.log"
COLOURS = {"failed": "#d1495b", "accepted": "#2a9d8f", "sudo": "#577590", "sudo_failed": "#f4a261"}

st.set_page_config(page_title="LogSentinel", page_icon="🛡️", layout="wide")


@st.cache_data(show_spinner="Parsing log…")
def parse_upload(data: bytes, name: str, year: int) -> ParsedLog:
    if name.endswith(".gz"):
        data = gzip.GzipFile(fileobj=io.BytesIO(data)).read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError(f"{name} exceeds {MAX_BYTES // 2**20} MB")
    return parse_text(data.decode("utf-8", "replace"), year, name)


with st.sidebar:
    st.title("🛡️ LogSentinel")
    st.caption(f"v{__version__} · Linux authentication log analyser")
    source = st.radio("Log source", ["Bundled sample", "Upload a file"], horizontal=True)
    upload = None
    if source == "Upload a file":
        upload = st.file_uploader("auth.log, secure or a .gz rotation", type=["log", "txt", "gz"])
    year = st.number_input("Year for legacy timestamps", 2000, 2100, datetime.now().year,
                           help="Only used for 'Oct 15 08:12:33' style lines, which carry no year.")
    st.subheader("Detection thresholds")
    fail = st.slider("Repeated failures (per IP, in window)", 2, 50, 5)
    brute = st.slider("Brute force (per IP, in window)", 5, 500, 20)
    spray = st.slider("Password spray (distinct users per IP)", 2, 50, 5)
    window = st.slider("Window (minutes)", 1, 120, 10)
    lookback = st.slider("Success after failures: look-back (minutes)", 1, 240, 30)
    hours = st.slider("Business hours (weekdays)", 0, 24, (7, 19))
    nets = st.text_area("Trusted networks (one CIDR per line)", "\n".join(Config().trusted_networks), height=90)

try:
    cfg = Config(fail_threshold=fail, brute_threshold=brute, spray_users=spray, window_minutes=window,
                 lookback_minutes=lookback, business_hours=hours,
                 trusted_networks=tuple(n.strip() for n in nets.splitlines() if n.strip()))
except ValueError as e:
    st.error(f"Settings: {e}")
    st.stop()

if source == "Upload a file" and upload is None:
    st.info("Upload an authentication log to begin, or switch to the bundled sample.")
    st.stop()

data, name = (upload.getvalue(), upload.name) if upload else (SAMPLE.read_bytes(), SAMPLE.name)
try:
    parsed = parse_upload(data, name, int(year))
except (ValueError, OSError) as e:
    st.error(f"Could not parse {name}: {e}")
    st.stop()

ev = parsed.events
findings = run_all(ev, cfg)
counts = severity_counts(findings)

st.title("Authentication log analysis")
st.caption(f"{name} · {parsed.lines:,} lines · {len(ev):,} auth events · "
           f"{parsed.unparsed:,} unparsed · {parsed.ignored:,} other")
if ev.empty:
    st.warning("No sshd or sudo events found. Check that the file is a Linux authentication log.")
    st.stop()

m = st.columns(6)
m[0].metric("Failed logins", int((ev.event == "failed").sum()))
m[1].metric("Accepted logins", int((ev.event == "accepted").sum()))
m[2].metric("Source IPs", int(ev.src_ip.nunique()))
m[3].metric("Critical", counts["critical"])
m[4].metric("High", counts["high"])
m[5].metric("Medium / Low", f"{counts['medium']} / {counts['low']}")

st.subheader("Timeline")
freq = st.radio("Bucket", ["15min", "1h", "6h", "1D"], index=1, horizontal=True, label_visibility="collapsed")
tl = timeline(ev, freq)
st.bar_chart(tl, color=[COLOURS[c] for c in tl.columns], height=260)

st.subheader(f"Findings ({len(findings)})")
if not findings:
    st.success("No findings at the current thresholds.")
    st.stop()
st.dataframe(to_frame(findings), hide_index=True, width="stretch", column_config={
    "first_seen": st.column_config.DatetimeColumn(format="YYYY-MM-DD HH:mm:ss"),
    "last_seen": st.column_config.DatetimeColumn(format="YYYY-MM-DD HH:mm:ss"),
})

by_id = {f.id: f for f in findings}
left, right = st.columns(2)
with left:
    choice = by_id[st.selectbox("Investigate", list(by_id),
                                format_func=lambda i: f"{i} · {by_id[i].severity.upper()} · {by_id[i].title}")]
    st.markdown(f"**Rule** `{choice.rule}` · **Source** `{choice.src_ip}` · **User** `{choice.user}`  \n"
                f"**First seen** {choice.first_seen:%Y-%m-%d %H:%M:%S} · "
                f"**Last seen** {choice.last_seen:%Y-%m-%d %H:%M:%S} · **Events** {choice.count}")
    st.write(choice.description)
    st.info(choice.recommendation)
    st.text_area("Analyst notes", key=f"note-{choice.id}", height=120,
                 placeholder="What you checked, who you contacted, verdict…")
with right:
    raw = ev.set_index("line_no").raw
    st.markdown(f"**Evidence** ({len(choice.evidence)} lines, first 50 shown)")
    st.code("\n".join(f"{n}: {raw[n]}" for n in choice.evidence[:50]), language="text")

notes = {f.id: st.session_state.get(f"note-{f.id}", "") for f in findings}
st.subheader("Export incident report")
stem = f"logsentinel-{datetime.now():%Y%m%d-%H%M}"
c1, c2 = st.columns(2)
c1.download_button("Download Markdown report", to_markdown(parsed, findings, cfg, notes),
                   f"{stem}.md", "text/markdown", width="stretch")
c2.download_button("Download JSON", to_json(parsed, findings, cfg, notes),
                   f"{stem}.json", "application/json", width="stretch")

with st.expander("All parsed events"):
    st.dataframe(ev.drop(columns=["raw"]), hide_index=True, width="stretch")
