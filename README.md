# LogSentinel

[![CI](https://github.com/Leonard-Opasanjo/logsentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/Leonard-Opasanjo/logsentinel/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

LogSentinel is a small, offline SIEM-style analyser for Linux authentication logs. You give it an `auth.log` or
`secure` file. It finds brute-force attacks, password spraying, logins that succeed after a run of failures,
logins at odd hours and logins from places you do not trust. It then produces an incident report that names the
evidence line by line, carries your own investigation notes, and records the thresholds that were used, so the
result can be handed to a colleague, a manager or an auditor.

It runs as a command-line tool for scripts and cron, and as a Streamlit dashboard for interactive investigation.
It needs no agents, no accounts, no cloud service and no network access.

![LogSentinel dashboard showing the timeline, findings table and investigation panel](docs/dashboard.png)

## Contents

- [Purpose](#purpose)
- [Objectives](#objectives)
- [Who it is for](#who-it-is-for)
- [What an authentication log contains](#what-an-authentication-log-contains)
- [What it detects](#what-it-detects)
- [Severity model](#severity-model)
- [Anatomy of a finding](#anatomy-of-a-finding)
- [Walkthrough: investigating the sample log](#walkthrough-investigating-the-sample-log)
- [Architecture](#architecture)
- [Install](#install)
- [Usage](#usage)
- [Reports](#reports)
- [The sample data](#the-sample-data)
- [Tests and continuous integration](#tests-and-continuous-integration)
- [Security assumptions](#security-assumptions)
- [Limitations](#limitations)
- [Roadmap](#roadmap)
- [About this project](#about-this-project)
- [Licence](#licence)

## Purpose

Every Linux host that accepts SSH logins writes a record of each attempt to its authentication log. On a server
that is reachable from the internet, that file fills with thousands of failed attempts a day from automated
scanners, and somewhere among them may be the handful of lines that matter: the attempt that got in, the login
at 02:00 on a Saturday, the staff account used from a country the company does not operate in.

Large organisations feed these logs into a SIEM (Security Information and Event Management platform) that
correlates them and raises alerts. Small teams, freelancers, NGOs and the people who look after a few VPS hosts
for a business usually have nothing of the kind. The log exists, nobody reads it, and the first sign of a
compromise is a ransom note, a spam complaint or a cloud bill.

LogSentinel exists to close that gap for the small case. It applies the detection logic a security analyst would
apply by hand, in seconds, to a file you already have, and it writes down what it found in a form that can be
acted on. It is deliberately narrow: one log family, a handful of well-understood attack patterns, and a report.
It is not a replacement for a SIEM, and it does not try to be.

## Objectives

The project set out to meet six concrete objectives. Each one is checked by the test suite or the CI pipeline.

1. **Parse real authentication logs reliably.** Accept both syslog timestamp styles that Linux distributions
   use, the `sshd` and `sshd-session` process names, gzip-rotated files, and malformed or hostile input, without
   crashing and without executing anything found in the log.
2. **Detect the attack patterns that matter most on an SSH host.** Repeated failures, brute force, password
   spraying, a success that follows failures, off-hours access and access from untrusted networks. Each pattern
   is a separate, documented rule with a configurable threshold.
3. **Rank findings so a person knows where to start.** Four severity levels with stated meanings, findings
   ordered by severity then time, and stable identifiers so notes can refer to them.
4. **Show the evidence, not just the verdict.** Every finding carries the exact log lines and their line numbers
   that caused it, so the analyst can verify the tool's reasoning and quote it in a report.
5. **Produce a report that can leave the building.** Markdown for people and JSON for other tools, both
   including the evidence, the recommendations, the analyst's notes and the thresholds that produced the result.
6. **Be safe to run on untrusted data.** The log is attacker-influenced input. Size and line-length caps,
   replacement decoding, sanitised report output, no network calls, a non-root container.

## Who it is for

- **System administrators and DevOps engineers** who look after a few internet-facing hosts and want a
  five-minute answer to "has anyone been hammering this box, and did they get in?"
- **Incident responders and blue-team analysts** who receive an `auth.log` from a client or a colleague and need
  a first triage with evidence they can cite.
- **Security students and people preparing for SOC roles** who want to see how detection rules are written,
  tuned and tested, with a synthetic dataset they can experiment on.
- **Developers building security tooling** who need a compact, tested reference for parsing syslog-format
  authentication events into a DataFrame.

## What an authentication log contains

On Debian and Ubuntu the file is `/var/log/auth.log`; on Red Hat, Rocky, Alma and Fedora it is
`/var/log/secure`. Rotated copies sit next to it as `auth.log.1`, `auth.log.2.gz` and so on. Every line has a
timestamp, the host name, the process that wrote it and a message. Two timestamp styles are in use:

```
Oct 15 03:12:04 bastion-01 sshd[1431]: Failed password for root from 203.0.113.45 port 51152 ssh2
2026-10-15T03:12:04.312884+03:00 bastion-01 sshd[1431]: Failed password for root from 203.0.113.45 port 51152 ssh2
```

The first is the traditional format. It has no year, which is why LogSentinel takes a `--year` option. The second
is RFC 3339 with microseconds and a UTC offset, the default on current Debian. LogSentinel reads both.

The messages that matter for authentication come from two processes:

| Process | Message | Meaning |
|---|---|---|
| `sshd` | `Failed password for alice from 10.0.1.20 port 51000 ssh2` | wrong password for an existing account |
| `sshd` | `Failed password for invalid user admin from 203.0.113.45 port 50122 ssh2` | attempt against an account that does not exist |
| `sshd` | `Accepted publickey for alice from 10.0.1.20 port 51000 ssh2: ED25519 SHA256:...` | successful login with a key |
| `sshd` | `Accepted password for bob from 10.0.1.77 port 27564 ssh2` | successful login with a password |
| `sudo` | `    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update` | a command run as root |
| `sudo` | `    carol : 3 incorrect password attempts ; TTY=pts/1 ; ... ; COMMAND=/bin/bash` | sudo refused |

Everything else in the file (PAM session lines, cron, `systemd-logind`, "Connection closed" notices) is noise
for this purpose. LogSentinel counts those lines as "other" and drops them, and counts lines it cannot read at all
as "unparsed", so you can tell at a glance whether the file was the kind you expected.

Attackers leave characteristic shapes in this file. A brute-force tool produces hundreds of failures against one
or two usernames in minutes. A password spray tries a short list of common passwords against many usernames,
slowly, to stay under lockout thresholds. A compromise shows up as a success from the same source that was
failing a moment earlier, often at a time nobody at the organisation is working, from an address nobody
recognises, followed by `sudo` commands that read credential files or package up home directories. The rules
below look for exactly these shapes.

## What it detects

| Rule | Triggers when (defaults) | Severity |
|---|---|---|
| `password_spray` | one source IP fails against 5 or more different usernames | high |
| `brute_force` | one source IP has 20 or more failures inside any 10-minute window | high |
| `repeated_failures` | one source IP has 5 or more failures inside any 10-minute window | medium |
| `success_after_failures` | a login succeeds within 30 minutes of 3 or more failures from the same IP | critical |
| `off_hours_login` | a login succeeds outside 07:00 to 19:00 on a weekday, or at any time at the weekend | low, high for root |
| `untrusted_source` | a login succeeds from outside the trusted networks (RFC 1918 ranges by default) | medium, high for root |

The three failure rules are evaluated together, once per source IP, and only the most serious one that applies
is reported. A scanner that hits 140 times in seven minutes is one `brute_force` finding, not a `brute_force`
and a `repeated_failures` finding for the same address.

### password_spray

**What it looks for.** One source address producing failed logins against many different usernames. The count
of distinct usernames is what matters, not the rate.

**Why it matters.** Spraying is how attackers avoid lockouts: one or two guesses per account, across every
account they can think of. It is slow and easy to miss if you only count failures per minute. The usernames in
the finding also tell you what list the attacker is working from (`admin`, `oracle`, `postgres`, `ubuntu`,
`pi` and so on mean a generic wordlist; your real staff names mean they did their homework).

**Tuning.** `--spray-users N`, default 5. A NAT gateway or a VPN concentrator that puts many legitimate users
behind one address will trip this rule; raise the threshold for that address or exclude it upstream.

### brute_force

**What it looks for.** At least `--brute-threshold` failures (default 20) from one address inside any window of
`--window` minutes (default 10). The window slides: the rule checks every run of 20 consecutive failures, not
fixed clock intervals.

**Why it matters.** Brute force is the loudest thing in the log and usually the least dangerous on a host with
key-only authentication, but it is still worth a finding. It tells you the host is being actively targeted, it
consumes CPU and log space, and the same address is the first place to look for a later success.

**Tuning.** The default is comfortably above what a fat-fingered administrator produces and below what any
automated tool produces. Lower it on a host that should see almost no password attempts at all.

### repeated_failures

**What it looks for.** At least `--fail-threshold` failures (default 5) from one address inside the window,
when the address did not reach the brute-force or spray thresholds.

**Why it matters.** This is the low-and-slow version of brute force and also what an internal user looks like
when they have forgotten a password or have an old credential in a script. It is medium severity because the
answer is usually "ask the person", but a repeated-failures finding against an external address with no
success afterwards is still reconnaissance.

**Tuning.** `--fail-threshold`, `--window`. Five in ten minutes is the common fail2ban default.

### success_after_failures

**What it looks for.** An accepted login from an address that produced at least three failures in the
preceding `--lookback` minutes (default 30). The count of three is the `success_min_failures` setting; it is
fixed in this version. Failures are only counted once: after a success, the next success from the same address
starts counting from zero.

**Why it matters.** This is the single most important pattern in an authentication log. Failures followed by
success is what a guessed password looks like, what a credential-stuffing hit looks like, and what a bruteforcer
that finally succeeded looks like. It is always critical, because the cost of ignoring a real one is a
compromised host and the cost of checking a false one is a phone call.

**Interpreting it.** The description tells you which usernames were tried before the success. If they are all
the same user and the source is internal, it is most likely a person mistyping. If the usernames vary, or the
source is external, or the success is at night, treat it as a compromise until shown otherwise. The sample log
contains one of each.

### off_hours_login

**What it looks for.** Accepted logins outside the business-hours window on weekdays, or at any hour on a
Saturday or Sunday, grouped by user and source address. Root is rated high; everyone else low.

**Why it matters.** Most compromises are discovered because something happened when nobody should have been
working. On its own an off-hours login is low severity, since on-call staff and automation exist, but it is the
multiplier that turns a medium finding into an incident when it coincides with one.

**Tuning.** `--business-hours START-END` in 24-hour local time, default `7-19`. Weekends are always off-hours;
there is no flag to change that in this version. Times are the host's wall-clock time, see
[Limitations](#limitations).

### untrusted_source

**What it looks for.** Accepted logins from an address that is not inside any of the trusted networks. The
defaults are the three RFC 1918 private ranges, so out of the box this means "any login from the public
internet". Root is rated high; everyone else medium. A source that is not a valid IP address at all is treated
as untrusted.

**Why it matters.** If your staff reach the host through an office network or a VPN, a login from anywhere
else is either a remote worker you did not know about or an attacker with a working credential. Either way you
want to know.

**Tuning.** `--trusted-network CIDR`, repeatable. Replacing the defaults with your office and VPN ranges makes
this rule precise. Adding `0.0.0.0/0` switches it off.

## Severity model

| Severity | Meaning | What to do |
|---|---|---|
| critical | strong evidence of a successful unauthorised login | act now: contact the user, review the session, rotate credentials, consider isolating the host |
| high | an active attack, or a sensitive account used in a suspicious way | block the source, verify no success followed, check root activity |
| medium | suspicious but commonly benign; needs a human decision | confirm with the account owner or the change record |
| low | worth recording, rarely worth acting on alone | note it; it raises the weight of any other finding for the same user or address |

Findings are sorted by severity, then by first-seen time, then by rule and source address, and numbered
`LS-001`, `LS-002` and so on. The numbering is deterministic for a given input and configuration, which is what
lets a notes file written against one run still apply to the next.

## Anatomy of a finding

Every finding, in the dashboard, the Markdown report and the JSON file, carries the same fields:

| Field | Content |
|---|---|
| `id` | `LS-001` style identifier, assigned after sorting |
| `rule` | one of the six rule names |
| `severity` | critical, high, medium or low |
| `title` | one line a person can read in a table: `Login for dave from 203.0.113.9 after 4 failures` |
| `description` | why the rule fired, with the numbers: counts, window, usernames involved, times |
| `recommendation` | the first steps an analyst should take for this kind of finding |
| `src_ip`, `user` | the address and account concerned (user may be a list for spray findings) |
| `first_seen`, `last_seen`, `count` | the time span and number of events behind the finding |
| `evidence` | the line numbers in the source log; the reports expand them to the full lines |
| `notes` | the analyst's own text, if any was supplied |

## Walkthrough: investigating the sample log

The bundled log covers three days (Thursday 15 to Saturday 17 October 2026) on a host called `bastion-01` with
six staff accounts. Running the analyser with defaults gives:

```
$ logsentinel analyze src/logsentinel/data/sample_auth.log --report docs/sample-report.md
sample_auth.log: 467 lines, 280 auth events, 10 findings (2 critical, 3 high, 3 medium, 2 low)
  LS-001  critical success_after_failures  Login for bob from 10.0.1.77 after 6 failures
  LS-002  critical success_after_failures  Login for dave from 203.0.113.9 after 4 failures
  LS-003  high     brute_force             140 failed logins from 203.0.113.45
  LS-004  high     password_spray          36 failed logins from 198.51.100.23
  LS-005  high     off_hours_login         1 off-hours login(s) for root from 192.168.10.5
  LS-006  medium   untrusted_source        1 login(s) for erin from untrusted 198.51.100.77
  LS-007  medium   repeated_failures       7 failed logins from 10.0.1.77
  LS-008  medium   untrusted_source        1 login(s) for dave from untrusted 203.0.113.9
  LS-009  low      off_hours_login         1 off-hours login(s) for dave from 203.0.113.9
  LS-010  low      off_hours_login         1 off-hours login(s) for alice from 10.0.1.20
report written to docs/sample-report.md
```

Here is how an analyst would read that list.

**LS-002, LS-008 and LS-009 are one incident.** `dave` logged in with a password at 02:17 on Saturday from
`203.0.113.9`, a public address, after four failures in the preceding six minutes. Three rules fired on the same
event. Opening the evidence shows what the session did next: `sudo cat /etc/shadow` two minutes later, then
`sudo tar czf /tmp/.cache.tgz /home /etc`. That is an attacker reading password hashes and packaging the host's
data. This is the finding that justifies the whole exercise. Action: disable the account, rotate every credential
on the host, preserve the log, and find out how the password was obtained.

**LS-001 and LS-007 are probably not an incident.** `bob` failed six times from `10.0.1.77` on Friday
afternoon and then got in with a password at 14:10. The source is the office network, the account is his own,
the usernames tried were all `bob`, and the hour is ordinary. Most likely a forgotten or mistyped password.
Action: a phone call to confirm, and a note on the finding. The second screenshot shows exactly that note being
written.

**LS-003 is background noise with a lesson in it.** 140 password failures for `root` and `admin` from
`203.0.113.45` between 03:12 and 03:19 on Thursday. An automated tool. Nothing from that address succeeded.
Action: block it, and check that password authentication for root is disabled in `sshd_config`, because the
tool was clearly hoping it was not.

**LS-004 shows the attacker's wordlist.** 36 failures from `198.51.100.23` spread over two and a half hours
against `admin`, `deploy`, `ftp`, `git`, `guest`, `oracle`, `pi`, `postgres`, `test`, `ubuntu`, `user` and
`www-data`. None of those accounts exist on the host. A generic spray; block and move on.

**LS-005 needs a question asked.** A root login with a key at 04:40 on Saturday from `192.168.10.5`, inside
the VPN range. Keys are not guessed, so this is someone who holds the root key. Whether it is an administrator
doing emergency maintenance or an attacker who took a key from a laptop is not something the log can tell you.
Action: ask whoever holds that key.

**LS-006 and LS-010 are the kind of finding that becomes a policy decision.** `erin` logged in from
`198.51.100.77` during Thursday business hours; `alice` logged in from the office at 10:30 on Saturday. Both
are almost certainly legitimate. The useful output is the question they raise: should remote staff be on the
VPN, and should weekend work be logged somewhere? Record the answer in the notes and tune the thresholds so the
next run does not ask again.

In the dashboard, choose a finding to see its evidence, write up what you checked, and download the report with
the notes included:

![Investigation panel with evidence lines, analyst notes and export buttons](docs/dashboard-investigate.png)

The complete report for this run is in [docs/sample-report.md](docs/sample-report.md) and the JSON in
[docs/sample-report.json](docs/sample-report.json).

## Architecture

```
src/logsentinel/
├── parser.py   log lines  ->  pandas DataFrame of sshd and sudo events
├── detect.py   DataFrame + Config  ->  list[Finding]   (one function per rule, registered in RULES)
├── report.py   findings + notes  ->  Markdown and JSON incident reports, hourly timeline
├── cli.py      `logsentinel analyze` and `logsentinel dashboard`
├── app.py      Streamlit dashboard: the same pipeline with interactive thresholds, notes and export
└── data/sample_auth.log   synthetic three-day log with the scenarios described above
scripts/make_sample_log.py   the seeded generator for that log
tests/                       parser, every rule, reports, CLI, dashboard
```

The pipeline is three pure functions in a row. `parse_file` turns text into a DataFrame with one row per
authentication event and the columns `line_no`, `timestamp`, `host`, `process`, `pid`, `event`, `user`,
`src_ip`, `method`, `invalid` and `raw`. `run_all` applies each rule in `RULES` to that frame with a `Config` and
returns sorted, numbered findings. `to_markdown` and `to_json` turn the findings plus the analyst's notes into
documents. The CLI and the dashboard are thin layers over those three calls, which is why they always agree.

Design decisions worth knowing about:

- **pandas, not a stream.** A 50 MB `auth.log` is a few hundred thousand lines and parses in seconds. Having the
  whole file in a frame makes the rules short and testable: the brute-force window check, for instance, is a
  sort and a `diff` over the timestamps of one address. Streaming would suit multi-gigabyte archives but would
  make every rule stateful.
- **Rules are plain functions with one signature.** A new rule is a function, an entry in a tuple, a threshold on
  `Config`, a test and a line in this README. See [CONTRIBUTING.md](CONTRIBUTING.md).
- **Thresholds are validated in one place.** `Config` rejects zero thresholds, inverted business hours and bad
  CIDRs when it is constructed, so the CLI and the dashboard cannot disagree about what is allowed.
- **Findings carry line numbers, not copies of lines.** The report looks the lines up when it is written. That
  keeps findings small and keeps the evidence tied to the original file.
- **Wall-clock time.** Timestamps are read as the host's local time and their UTC offset is dropped rather than
  converted. The business-hours rule is about when people at that host work, and that is what the host's clock
  records.
- **No network.** Enrichment (GeoIP, reputation feeds) is on the roadmap as a local-database feature only. A
  triage tool that phones home with the addresses in your logs is itself a data leak.

## Install

Python 3.11 or newer.

```bash
git clone https://github.com/Leonard-Opasanjo/logsentinel.git
cd logsentinel
python -m venv .venv && . .venv/bin/activate     # or: uv venv && . .venv/bin/activate
pip install -e ".[dev]"                           # or: uv pip install -e ".[dev]"
```

The `[dev]` extra adds pytest, ruff, bandit and pip-audit. Leave it off for a runtime-only install.

Docker:

```bash
docker build -t logsentinel .
docker run --rm -p 8501:8501 logsentinel                                   # dashboard on http://localhost:8501
docker run --rm -v "$PWD/logs:/logs:ro" logsentinel logsentinel analyze /logs/auth.log
```

The image is based on `python:3.12-slim`, installs the package, and runs as an unprivileged user with a health
check on the Streamlit endpoint.

## Usage

### Command line

```
logsentinel analyze LOGFILE [options]
logsentinel dashboard [--host HOST] [--port PORT]
logsentinel --version
```

`analyze` prints a one-line summary and one line per finding, then writes whatever exports were requested.

| Option | Default | Effect |
|---|---|---|
| `LOGFILE` | | `auth.log`, `secure`, or a `.gz` rotation of either |
| `--year YYYY` | current year | year to apply to legacy `Oct 15 08:12:33` timestamps |
| `--report FILE.md` | | write the Markdown incident report |
| `--json FILE.json` | | write findings, evidence and settings as JSON |
| `--notes FILE.json` | | merge analyst notes, a JSON object keyed by finding id |
| `--fail-threshold N` | 5 | failures from one address inside the window for `repeated_failures` |
| `--brute-threshold N` | 20 | failures inside the window for `brute_force` |
| `--spray-users N` | 5 | distinct usernames from one address for `password_spray` |
| `--window MIN` | 10 | the sliding window for the three failure rules |
| `--lookback MIN` | 30 | how far before a success to count failures |
| `--business-hours START-END` | `7-19` | weekday hours that are not off-hours |
| `--trusted-network CIDR` | RFC 1918 | repeatable; replaces the default list |
| `-v` | | debug logging to stderr |

Exit codes: `0` on success, `2` when the file cannot be read, is too large, or an option is invalid. The
findings themselves do not affect the exit code in this version.

Examples:

```bash
# First look at a host
logsentinel analyze /var/log/auth.log

# A rotated file from last year, with the office and VPN ranges as the only trusted sources
logsentinel analyze auth.log.4.gz --year 2025 --trusted-network 10.20.0.0/16 --trusted-network 192.168.100.0/24

# Full report with notes for the incident file
echo '{"LS-001": "Spoke to bob at 14:30. Mistyped password, confirmed by help-desk ticket 4471."}' > notes.json
logsentinel analyze auth.log --report incident.md --json incident.json --notes notes.json

# A quiet host where any password attempt is unusual
logsentinel analyze auth.log --fail-threshold 2 --brute-threshold 5 --window 60 --business-hours 8-18
```

### Dashboard

```bash
logsentinel dashboard              # http://localhost:8501
logsentinel dashboard --port 9000
```

The sidebar selects the bundled sample or an uploaded file (up to 50 MB, `.log`, `.txt` or `.gz`), the year for
legacy timestamps, and every threshold as a slider or text box. The main area shows the headline counts, a
timeline of failed, accepted, sudo and sudo-failed events at 15-minute, hourly, 6-hourly or daily resolution, the
findings table, and an investigation panel for the selected finding with its evidence and a notes box. The two
download buttons produce the same Markdown and JSON as the CLI, with the notes typed in the session included. An
expander at the bottom lists every parsed event for ad-hoc filtering.

The dashboard binds to `localhost` by default and has no login of its own. See
[Security assumptions](#security-assumptions) before putting it anywhere else.

## Reports

### Markdown

The report is meant to be pasted into a ticket or an incident record as it is. Its sections, in order:

1. Header: source file, generation time (UTC), line counts (read, auth events, unparsed, other) and the period
   the events cover in the host's clock.
2. Summary: a table of findings per severity.
3. Findings: one section per finding with its id, severity and title as the heading, then rule, source, user,
   time span and event count, the description, the recommendation, the analyst notes (or `_none_`), and the
   first ten evidence lines in a code block with their line numbers.
4. Timeline: an hourly table of event counts by type.
5. Detection settings: every threshold that produced the result, so the report is reproducible.

Values that come from the log (usernames, addresses, the source file name) are sanitised before they are placed
in the Markdown, and evidence lines have backticks replaced, so a crafted username cannot break out of a code
block or insert a heading.

### JSON

```json
{
  "tool": "logsentinel",
  "generated": "2026-10-19T12:25:33+00:00",
  "source": "sample_auth.log",
  "stats": {"lines": 467, "events": 280, "unparsed": 0, "ignored": 187},
  "config": {"fail_threshold": 5, "brute_threshold": 20, "...": "..."},
  "severity_counts": {"critical": 2, "high": 3, "medium": 3, "low": 2},
  "findings": [
    {
      "id": "LS-001",
      "rule": "success_after_failures",
      "severity": "critical",
      "title": "Login for bob from 10.0.1.77 after 6 failures",
      "description": "...",
      "recommendation": "...",
      "src_ip": "10.0.1.77",
      "user": "bob",
      "first_seen": "2026-10-16T14:02:10.367452",
      "last_seen": "2026-10-16T14:10:12.467159",
      "count": 7,
      "evidence": [{"line": 380, "raw": "2026-10-16T14:02:10.367452+03:00 bastion-01 sshd[2869]: Failed password for bob ..."}],
      "notes": ""
    }
  ]
}
```

The JSON carries every evidence line, not just the first ten, which makes it the right input for a ticketing
system, a spreadsheet or a second tool.

## The sample data

`src/logsentinel/data/sample_auth.log` is generated by `scripts/make_sample_log.py` from a fixed random seed, so
it is identical on every run and CI checks that the committed file matches the generator. It contains:

- Three days of background activity: hourly cron sessions, six staff accounts logging in from office
  (`10.0.1.0/24`) and VPN (`192.168.10.0/24`) addresses during working hours, with occasional `sudo` commands
  and the odd mistyped password.
- The six planted scenarios walked through above, plus a `sudo` password failure for one user.
- Realistic noise that the parser must ignore: PAM session lines, `systemd-logind` session notices and
  `Connection closed by authenticating user` messages.

External addresses come from the RFC 5737 documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`,
`203.0.113.0/24`), which are reserved and never routed. Usernames are generic. No real host, person or address
appears anywhere in the repository.

To create a variant, edit the scenarios in the generator and run it:

```bash
python scripts/make_sample_log.py                 # rewrites the bundled file
python scripts/make_sample_log.py /tmp/my.log     # writes elsewhere
```

## Tests and continuous integration

```bash
ruff check .                              # lint and import order
pytest                                    # 40 tests
bandit -q -c pyproject.toml -r src        # static security scan of the package
pip-audit                                 # known vulnerabilities in the installed dependencies
python scripts/make_sample_log.py /tmp/s.log && cmp /tmp/s.log src/logsentinel/data/sample_auth.log
```

The test suite covers:

- **Parser:** both timestamp formats, `sshd-session`, the invalid-user flag, empty usernames, sudo success and
  failure, noise and garbage lines, impossible dates, line truncation, the size cap, gzip input, non-UTF-8
  bytes, and the schema of an empty result.
- **Each rule:** fires at the threshold and not one below it, slow failures that never form a burst, spray
  taking precedence over count, one finding per address, the look-back and once-only counting for success after
  failures, business-hour boundaries and weekends, root severity, trusted-network overrides, IPv6 and non-IP
  sources, ordering and numbering, empty input, and `Config` validation.
- **Reports:** the Markdown structure, closed evidence fences under a hostile username, notes placement, the JSON
  schema, and the timeline.
- **CLI:** the full sample run with notes merged into both exports, threshold flags changing the result, and
  the exit code for a missing file, a malformed option and a malformed notes file.
- **Dashboard:** rendered through Streamlit's `AppTest` with the sample, checking the headline metrics, the
  finding selector and that a typed note survives a rerun, plus the error shown for an invalid CIDR.

GitHub Actions runs the same five commands on Python 3.11, 3.12 and 3.13, then builds the Docker image and runs
the CLI inside it. The dependency audit is meant to turn the build red when a dependency gets a published
advisory; the install step upgrades `pip` and `setuptools` first because the runner images sometimes ship an
old `setuptools` that the audit would otherwise flag.

## Security assumptions

- **Log files are hostile input.** Anyone who can attempt an SSH login can put a chosen string into the
  username field of `auth.log`. Lines are capped at 4 KiB, files at 50 MB (also after gzip decompression),
  undecodable bytes are replaced, and nothing from a log is evaluated, templated or passed to a shell.
- **Report output is sanitised.** Log-derived strings are cleaned before they go into the Markdown, evidence
  blocks strip backticks, and the dashboard renders log values through Streamlit components, which escape HTML.
- **No network access.** No reputation lookups, no GeoIP web services, no telemetry (`gatherUsageStats` is off
  in the bundled Streamlit configuration).
- **The dashboard has no authentication.** It binds to `localhost`. To share it with a team, put it behind a
  reverse proxy that handles login, and remember that uploaded logs sit in the server process's memory for the
  session. The Docker image binds to all interfaces inside the container because it must; publish the port only
  where you intend.
- **Least privilege in the container.** The image runs as an unprivileged user and installs nothing beyond the
  package and its dependencies.
- **Reporting a vulnerability:** see [SECURITY.md](SECURITY.md).

## Limitations

- Only `sshd` and `sudo` events are parsed. PAM-only lines, `su`, `login`, console logins and journald's binary
  journal are not. Export the journal with `journalctl -o short-iso` and the sshd lines will parse.
- Legacy syslog timestamps have no year; one year is applied to the whole file. A file that spans New Year is
  misdated on one side of it.
- Timestamps are the host's wall-clock time. Offsets are dropped, not converted, so the business-hours rule
  reflects where the host is, not where you are, and logs from hosts in different zones should be analysed
  separately.
- Weekends are always treated as off-hours. There is no flag for organisations that work Saturdays.
- Detection is threshold-based. The defaults suit a typical internet-facing host and were tuned on the synthetic
  sample. A busy jump host, or a NAT gateway that puts many users behind one address, will need the thresholds
  raised or the address excluded.
- "Untrusted" means outside the configured CIDRs. There is no baseline of where each user normally logs in from,
  so a user's first login from a new country inside a trusted range is not a finding.
- The whole file is loaded into memory. Fifty megabytes takes seconds; this is not a streaming tool for
  multi-gigabyte archives.
- The tool reports; it does not block, notify or remediate. Pair it with fail2ban or a firewall for response.

## Roadmap

- Per-user baseline of known source addresses across runs, so a new address for an existing user is a finding.
- `su`, `login`, PAM and journald inputs.
- GeoIP and ASN enrichment from a local MaxMind database, still with no outbound calls.
- A configurable weekend and a holiday list for the off-hours rule.
- fail2ban-style block-list export.
- A `--fail-on SEVERITY` option that sets the exit code for cron and CI use.
- Windows Security event logs (4625 and 4624) as a second log family.

## About this project

LogSentinel is the first in a series of open-source security tools I am building to show practical detection
engineering, incident-response thinking and software craft in one place: working code, tests that prove it,
documentation that explains the reasoning, and a synthetic dataset anyone can experiment on. It was written for
the kind of environment I work in, where the organisation has real exposure and no SIEM budget.

If you use it, find a log line it mishandles, or have a rule you think belongs in it, open an issue or a pull
request. [CONTRIBUTING.md](CONTRIBUTING.md) explains how the pieces fit.

## Licence

MIT. See [LICENSE](LICENSE).
