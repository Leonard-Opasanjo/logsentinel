"""Incident report export (Markdown and JSON) and timeline aggregation."""

from __future__ import annotations

import json
import re
from dataclasses import asdict
from datetime import UTC, datetime

import pandas as pd

from .detect import SEVERITIES, Config, Finding
from .parser import ParsedLog

MAX_EVIDENCE = 10
_UNSAFE = re.compile(r"[^\w .,:@/()+-]")


def _safe(value: object) -> str:
    """Replace characters that could break Markdown structure in log-derived text."""
    return _UNSAFE.sub("?", str(value))


def timeline(ev: pd.DataFrame, freq: str = "1h") -> pd.DataFrame:
    """Event counts per time bucket, one column per event type."""
    if ev.empty:
        return pd.DataFrame()
    return ev.groupby([ev.timestamp.dt.floor(freq).rename("time"), "event"]).size().unstack(fill_value=0)


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    return {s: sum(f.severity == s for f in findings) for s in SEVERITIES}


def _evidence(f: Finding, raw: pd.Series, limit: int | None = MAX_EVIDENCE) -> list[str]:
    return [f"{n}: {raw[n]}" for n in f.evidence[:limit]]


def to_markdown(parsed: ParsedLog, findings: list[Finding], cfg: Config,
                notes: dict[str, str] | None = None, generated: datetime | None = None) -> str:
    notes = notes or {}
    generated = generated or datetime.now(UTC)
    ev = parsed.events
    raw = ev.set_index("line_no").raw
    counts = severity_counts(findings)
    lines = [
        "# LogSentinel incident report", "",
        f"- Source: `{_safe(parsed.source)}`",
        f"- Generated: {generated:%Y-%m-%d %H:%M} UTC",
        f"- Lines read: {parsed.lines} (auth events {len(ev)}, unparsed {parsed.unparsed}, other {parsed.ignored})",
    ]
    if not ev.empty:
        lines.append(f"- Period: {ev.timestamp.min():%Y-%m-%d %H:%M} to {ev.timestamp.max():%Y-%m-%d %H:%M} "
                     "(host clock)")
    lines += ["", "## Summary", "", "| Severity | Findings |", "|---|---|"]
    lines += [f"| {s} | {counts[s]} |" for s in SEVERITIES]
    lines += ["", "## Findings", ""]
    if not findings:
        lines.append("No findings at the current thresholds.")
    for f in findings:
        lines += [
            f"### {f.id} · {f.severity.upper()} · {_safe(f.title)}", "",
            f"- Rule: `{f.rule}`",
            f"- Source IP: `{_safe(f.src_ip)}` · User: `{_safe(f.user)}`",
            f"- First seen: {f.first_seen:%Y-%m-%d %H:%M:%S} · Last seen: {f.last_seen:%Y-%m-%d %H:%M:%S} "
            f"· Events: {f.count}", "",
            _safe(f.description), "",
            f"**Recommendation:** {f.recommendation}", "",
            f"**Analyst notes:** {notes.get(f.id, '').strip() or '_none_'}", "",
            f"Evidence ({min(len(f.evidence), MAX_EVIDENCE)} of {len(f.evidence)} lines):", "", "```text",
            *(e.replace("`", "'") for e in _evidence(f, raw)), "```", "",
        ]
    tl = timeline(ev)
    if not tl.empty:
        cols = list(tl.columns)
        lines += ["## Timeline (hourly)", "", "| Hour | " + " | ".join(cols) + " |", "|---|" + "---|" * len(cols)]
        lines += [f"| {t:%Y-%m-%d %H:%M} | " + " | ".join(str(v) for v in row) + " |"
                  for t, row in zip(tl.index, tl.values, strict=True)]
        lines.append("")
    lines += ["## Detection settings", "", "| Setting | Value |", "|---|---|"]
    lines += [f"| {k} | {v} |" for k, v in asdict(cfg).items()]
    return "\n".join(lines) + "\n"


def to_json(parsed: ParsedLog, findings: list[Finding], cfg: Config,
            notes: dict[str, str] | None = None, generated: datetime | None = None) -> str:
    notes = notes or {}
    generated = generated or datetime.now(UTC)
    raw = parsed.events.set_index("line_no").raw
    doc = {
        "tool": "logsentinel",
        "generated": generated.isoformat(timespec="seconds"),
        "source": parsed.source,
        "stats": {"lines": parsed.lines, "events": len(parsed.events),
                  "unparsed": parsed.unparsed, "ignored": parsed.ignored},
        "config": asdict(cfg),
        "severity_counts": severity_counts(findings),
        "findings": [{
            **asdict(f),
            "first_seen": f.first_seen.isoformat(),
            "last_seen": f.last_seen.isoformat(),
            "evidence": [{"line": n, "raw": raw[n]} for n in f.evidence],
            "notes": notes.get(f.id, ""),
        } for f in findings],
    }
    return json.dumps(doc, indent=2, default=str)
