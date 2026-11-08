"""Detection rules. Each rule takes the parsed events and a Config and returns Findings."""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from dataclasses import dataclass, field

import numpy as np
import pandas as pd

SEVERITIES = ("critical", "high", "medium", "low")
MAX_SUDO = 10  # sudo lines added to the evidence of a success after failures


@dataclass(frozen=True)
class Config:
    """Detection thresholds. Windows are in minutes; business_hours is [start, end) on weekdays."""

    fail_threshold: int = 5
    brute_threshold: int = 20
    spray_users: int = 5
    window_minutes: int = 10
    lookback_minutes: int = 30
    success_min_failures: int = 3
    business_hours: tuple[int, int] = (7, 19)
    trusted_networks: tuple[str, ...] = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")

    def __post_init__(self) -> None:
        for name in ("fail_threshold", "brute_threshold", "spray_users", "window_minutes",
                     "lookback_minutes", "success_min_failures"):
            if getattr(self, name) < 1:
                raise ValueError(f"{name} must be at least 1")
        start, end = self.business_hours
        if not 0 <= start < end <= 24:
            raise ValueError("business_hours must satisfy 0 <= start < end <= 24")
        self.networks  # noqa: B018  validates every CIDR

    @property
    def networks(self) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        return [ipaddress.ip_network(n, strict=False) for n in self.trusted_networks]


@dataclass
class Finding:
    rule: str
    severity: str
    title: str
    description: str
    recommendation: str
    src_ip: str | None
    user: str | None
    first_seen: pd.Timestamp
    last_seen: pd.Timestamp
    count: int
    evidence: list[int] = field(default_factory=list)  # line numbers in the source log
    id: str = ""
    key: str = field(init=False)  # stable across runs, unlike the id; analyst notes are keyed by it

    def __post_init__(self) -> None:
        self.evidence = list(dict.fromkeys(self.evidence))  # a folded "message repeated" line counts once
        self.key = f"{self.rule}/{self.src_ip}/{self.user}/{self.first_seen:%Y-%m-%dT%H:%M:%S}"


def _burst(ts: pd.Series, n: int, window: pd.Timedelta) -> bool:
    """True when some n consecutive timestamps fall inside window."""
    if len(ts) < n:
        return False
    ts = ts.sort_values().reset_index(drop=True)
    return bool((ts.diff(n - 1).dropna() <= window).any())


def _users(g: pd.DataFrame) -> str:
    users = sorted(g.user.dropna().unique())
    return ", ".join(users[:5]) + (f" (+{len(users) - 5} more)" if len(users) > 5 else "")


def failed_logins(ev: pd.DataFrame, cfg: Config) -> list[Finding]:
    """Repeated failures, brute force and password spraying: one finding per source IP."""
    window = pd.Timedelta(minutes=cfg.window_minutes)
    out = []
    for ip, g in ev[ev.event == "failed"].groupby("src_ip"):
        n_users = g.user.nunique()
        if n_users >= cfg.spray_users:
            rule, sev = "password_spray", "high"
            why = f"{len(g)} failed logins spread over {n_users} different usernames"
            fix = ("Block the source at the firewall or with fail2ban, check whether any targeted account "
                   "shares a weak password, and move SSH to key-based authentication.")
        elif _burst(g.utc, cfg.brute_threshold, window):
            rule, sev = "brute_force", "high"
            why = f"{len(g)} failed logins, at least {cfg.brute_threshold} within {cfg.window_minutes} minutes"
            fix = ("Block the source, check whether any login from it later succeeded, rate-limit SSH "
                   "(fail2ban, MaxAuthTries) and disable password authentication.")
        elif _burst(g.utc, cfg.fail_threshold, window):
            rule, sev = "repeated_failures", "medium"
            why = f"{len(g)} failed logins, at least {cfg.fail_threshold} within {cfg.window_minutes} minutes"
            fix = ("Confirm with the account owner if the source is internal; otherwise treat it as "
                   "reconnaissance and block it.")
        else:
            continue
        users = _users(g)
        out.append(Finding(rule, sev, f"{len(g)} failed logins from {ip}", f"{why}. Usernames: {users}.",
                           fix, ip, users, g.timestamp.min(), g.timestamp.max(), len(g), g.line_no.tolist()))
    return out


def success_after_failures(ev: pd.DataFrame, cfg: Config) -> list[Finding]:
    """An accepted login preceded by failures from the same IP inside the look-back window.

    The user's sudo lines in the look-back window after the login are added to the evidence.
    """
    lookback = pd.Timedelta(minutes=cfg.lookback_minutes)
    fails = ev[ev.event == "failed"].sort_values("utc", kind="stable")
    rows = fails.groupby("src_ip").indices  # each source's failures, as positions in time order
    utc = fails.utc.to_numpy()
    times = {ip: utc[pos] for ip, pos in rows.items()}
    sudo = ev[ev.event.isin(("sudo", "sudo_failed"))]
    last_ok: dict[str, pd.Timestamp] = {}
    out = []
    for a in ev[ev.event == "accepted"].sort_values("utc", kind="stable").itertuples():
        since = max(a.utc - lookback, last_ok.get(a.src_ip, pd.Timestamp.min))
        last_ok[a.src_ip] = a.utc
        if a.src_ip not in times:
            continue
        # failures in (since, success]: a binary search per login instead of a scan of every failure
        lo, hi = np.searchsorted(times[a.src_ip], [since.to_datetime64(), a.utc.to_datetime64()], side="right")
        if hi - lo < cfg.success_min_failures:
            continue
        prior = fails.iloc[rows[a.src_ip][lo:hi]]
        after = sudo[(sudo.user == a.user) & (sudo.utc >= a.utc) & (sudo.utc <= a.utc + lookback)].head(MAX_SUDO)
        then = f" {a.user} then ran sudo {len(after)} time(s), shown in the evidence." if len(after) else ""
        out.append(Finding(
            "success_after_failures", "critical",
            f"Login for {a.user} from {a.src_ip} after {len(prior)} failures",
            f"{a.method} login for {a.user} succeeded at {a.timestamp:%Y-%m-%d %H:%M:%S} after {len(prior)} "
            f"failed attempts from the same source within {cfg.lookback_minutes} minutes "
            f"(usernames tried: {_users(prior)}).{then}",
            "Treat as a possible account compromise: contact the user, review what the session ran "
            "(sudo entries, shell history), rotate the credential and consider isolating the host.",
            a.src_ip, a.user, prior.timestamp.min(), a.timestamp, len(prior) + 1,
            prior.line_no.tolist() + [a.line_no] + after.line_no.tolist()))
    return out


def off_hours_logins(ev: pd.DataFrame, cfg: Config) -> list[Finding]:
    """Accepted logins outside business hours or at the weekend."""
    acc = ev[ev.event == "accepted"]
    start, end = cfg.business_hours
    hour = acc.timestamp.dt.hour
    off = acc[(hour < start) | (hour >= end) | (acc.timestamp.dt.weekday >= 5)]
    out = []
    for (user, ip), g in off.groupby(["user", "src_ip"]):
        times = ", ".join(t.strftime("%a %H:%M") for t in g.timestamp.iloc[:5])
        out.append(Finding(
            "off_hours_login", "high" if user == "root" else "low",
            f"{len(g)} off-hours login(s) for {user} from {ip}",
            f"Successful logins outside {start:02d}:00-{end:02d}:00 on weekdays. Times: {times}.",
            "Confirm the activity with the user or a change ticket. Root logins at night deserve a "
            "direct check of what was run.",
            ip, user, g.timestamp.min(), g.timestamp.max(), len(g), g.line_no.tolist()))
    return out


def _trusted(ip: str, nets: list) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in nets)


def untrusted_source_logins(ev: pd.DataFrame, cfg: Config) -> list[Finding]:
    """Accepted logins from outside the trusted networks."""
    nets = cfg.networks
    acc = ev[ev.event == "accepted"]
    outside = acc[~acc.src_ip.map(lambda ip: _trusted(ip, nets)).astype(bool)]
    out = []
    for (user, ip), g in outside.groupby(["user", "src_ip"]):
        out.append(Finding(
            "untrusted_source", "high" if user == "root" else "medium",
            f"{len(g)} login(s) for {user} from untrusted {ip}",
            f"Source is outside the trusted networks ({', '.join(cfg.trusted_networks)}).",
            "Verify the source belongs to the user (VPN, home, travel). Unknown external sources with "
            "a successful login warrant credential rotation.",
            ip, user, g.timestamp.min(), g.timestamp.max(), len(g), g.line_no.tolist()))
    return out


RULES: tuple[Callable[[pd.DataFrame, Config], list[Finding]], ...] = (
    failed_logins, success_after_failures, off_hours_logins, untrusted_source_logins,
)


def run_all(ev: pd.DataFrame, cfg: Config | None = None) -> list[Finding]:
    """Run every rule; findings are sorted by severity then time and numbered LS-001, LS-002, ..."""
    cfg = cfg or Config()
    findings = [f for rule in RULES for f in rule(ev, cfg)]
    findings.sort(key=lambda f: (SEVERITIES.index(f.severity), f.first_seen, f.rule, f.src_ip or ""))
    for i, f in enumerate(findings, 1):
        f.id = f"LS-{i:03d}"
    return findings


def to_frame(findings: list[Finding]) -> pd.DataFrame:
    cols = ["id", "severity", "rule", "title", "src_ip", "user", "first_seen", "last_seen", "count"]
    return pd.DataFrame([{c: getattr(f, c) for c in cols} for f in findings], columns=cols)
